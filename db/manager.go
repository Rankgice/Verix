package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
)

type tableLister interface {
	ListTables(ctx context.Context) ([]string, error)
}

func NewManager() *Manager {
	return NewManagerFromEnv(DefaultConnectionsEnvVar, os.Getenv)
}

func NewManagerFromEnv(envVar string, getenv func(string) string) *Manager {
	if strings.TrimSpace(envVar) == "" {
		envVar = DefaultConnectionsEnvVar
	}
	if getenv == nil {
		getenv = os.Getenv
	}

	return &Manager{
		conns:  make(map[string]*Connection),
		envVar: envVar,
		getenv: getenv,
		openDB: sql.Open,
	}
}

func (m *Manager) GetConnection(name string) (*Connection, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return nil, fmt.Errorf("connection is required")
	}
	if err := m.ensureConfigsLoaded(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, ok := m.conns[trimmedName]; ok {
		return conn, nil
	}

	cfg, ok := m.configs[trimmedName]
	if !ok {
		return nil, missingConnectionConfigError(m.envVar, trimmedName, len(m.configs) > 0)
	}

	dbConn, err := m.openDB(cfg.Driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open connection %q: %w", trimmedName, err)
	}
	if cfg.MaxOpenConns > 0 {
		dbConn.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		dbConn.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetimeMS > 0 {
		dbConn.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMS) * time.Millisecond)
	}

	conn := &Connection{
		Name:   trimmedName,
		DB:     dbConn,
		Driver: cfg.Driver,
	}
	switch cfg.Driver {
	case DriverMySQL:
		conn.executor = newMySQLExecutor(dbConn)
	default:
		_ = dbConn.Close()
		return nil, fmt.Errorf("connection %q uses unsupported driver %q", trimmedName, cfg.Driver)
	}

	m.conns[trimmedName] = conn
	return conn, nil
}

func (m *Manager) GetExecutor(name string) (DBExecutor, error) {
	conn, err := m.GetConnection(name)
	if err != nil {
		return nil, err
	}
	return conn.executor, nil
}

func (m *Manager) ExecuteSQL(ctx context.Context, req ExecuteSQLRequest) (*ExecuteSQLResult, error) {
	connection := strings.TrimSpace(req.Connection)
	if connection == "" {
		return nil, fmt.Errorf("connection is required")
	}
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		return nil, fmt.Errorf("sql is required")
	}

	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return nil, err
	}
	if err := ValidateExecution(analysis, normalizeReadOnly(req.ReadOnly)); err != nil {
		return nil, err
	}

	requestedLimit := NormalizeLimit(req.Limit)
	rewriteLimit := requestedLimit
	if analysis.Operation == "SELECT" && !analysis.HasLimit {
		rewriteLimit++
	}

	rewrittenSQL, limitApplied, err := RewriteSelectLimit(sqlText, rewriteLimit)
	if err != nil {
		return nil, err
	}
	boundSQL, args, err := BindNamedParams(rewrittenSQL, req.Params)
	if err != nil {
		return nil, err
	}

	executor, err := m.GetExecutor(connection)
	if err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(NormalizeTimeoutMS(req.TimeoutMS))*time.Millisecond)
	defer cancel()

	started := time.Now()
	out := &ExecuteSQLResult{
		Success: true,
		Data: ExecuteSQLData{
			Operation: analysis.Operation,
		},
		Meta: ExecuteSQLMeta{},
	}

	if usesQueryExecution(analysis.Operation) {
		queryResult, err := executor.Query(execCtx, boundSQL, args...)
		if err != nil {
			return nil, fmt.Errorf("execute query: %w", err)
		}
		out.Data.Columns = queryResult.Columns
		out.Data.Rows = queryResult.Rows
		out.Data.RowCount = queryResult.RowCount
		if limitApplied && len(queryResult.Rows) > requestedLimit {
			out.Data.Rows = queryResult.Rows[:requestedLimit]
			out.Data.RowCount = requestedLimit
			out.Meta.Truncated = true
		}
	} else {
		execResult, err := executor.Exec(execCtx, boundSQL, args...)
		if err != nil {
			return nil, fmt.Errorf("execute statement: %w", err)
		}
		out.Data.RowsAffected = execResult.RowsAffected
		out.Data.LastInsertID = execResult.LastInsertID
	}

	out.Meta.LatencyMS = time.Since(started).Milliseconds()
	return out, nil
}

func (m *Manager) ListTables(ctx context.Context, connection string) (*ListTablesResult, error) {
	executor, err := m.GetExecutor(connection)
	if err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(DefaultTimeoutMS)*time.Millisecond)
	defer cancel()

	if lister, ok := executor.(tableLister); ok {
		tables, err := lister.ListTables(timeoutCtx)
		if err != nil {
			return nil, err
		}
		return &ListTablesResult{Data: TableListData{Tables: tables}}, nil
	}

	schema, err := executor.GetSchema(timeoutCtx)
	if err != nil {
		return nil, err
	}
	tables := make([]string, 0, len(schema.Tables))
	for _, table := range schema.Tables {
		tables = append(tables, table.Name)
	}
	return &ListTablesResult{Data: TableListData{Tables: tables}}, nil
}

func (m *Manager) GetSchemaResult(ctx context.Context, connection string) (*GetSchemaResult, error) {
	executor, err := m.GetExecutor(connection)
	if err != nil {
		return nil, err
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(DefaultTimeoutMS)*time.Millisecond)
	defer cancel()

	schema, err := executor.GetSchema(timeoutCtx)
	if err != nil {
		return nil, err
	}
	return &GetSchemaResult{Data: *schema}, nil
}

func (m *Manager) DescribeTableResult(ctx context.Context, connection string, table string) (*DescribeTableResult, error) {
	trimmedTable := strings.TrimSpace(table)
	if trimmedTable == "" {
		return nil, fmt.Errorf("table is required")
	}

	executor, err := m.GetExecutor(connection)
	if err != nil {
		return nil, err
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(DefaultTimeoutMS)*time.Millisecond)
	defer cancel()

	tableSchema, err := executor.DescribeTable(timeoutCtx, trimmedTable)
	if err != nil {
		return nil, err
	}
	return &DescribeTableResult{Data: *tableSchema}, nil
}

func (m *Manager) ensureConfigsLoaded() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return m.configErr
	}

	m.configs, m.configErr = parseConnectionConfigs(m.envVar, m.getenv(m.envVar))
	m.loaded = true
	return m.configErr
}
