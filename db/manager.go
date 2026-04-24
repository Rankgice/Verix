package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	runtimeConnectionName           = "runtime"
	initializeDBSourceDatabaseURL   = "database_url"
	initializeDBSourcePersistedFile = "persisted_state"
)

type runtimeStateFile struct {
	DatabaseURL string `json:"database_url"`
}

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
		conns:            make(map[string]*Connection),
		envVar:           envVar,
		getenv:           getenv,
		openDB:           sql.Open,
		now:              time.Now,
		runtimeStatePath: DefaultRuntimeStatePath,
	}
}

func (m *Manager) GetConnection(ctx context.Context, name string) (*Connection, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return m.getRuntimeConnection(normalizeContext(ctx))
	}
	return m.getNamedConnection(normalizeContext(ctx), trimmedName)
}

func (m *Manager) getNamedConnection(ctx context.Context, name string) (*Connection, error) {
	if err := m.ensureConfigsLoaded(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	if conn, ok := m.conns[name]; ok {
		m.mu.Unlock()
		return conn, nil
	}

	cfg, ok := m.configs[name]
	hasConfiguredConnections := len(m.configs) > 0
	m.mu.Unlock()
	if !ok {
		return nil, missingConnectionConfigError(m.envVar, name, hasConfiguredConnections)
	}

	conn, err := m.openConnection(ctx, name, cfg, false)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if existing, ok := m.conns[name]; ok {
		m.mu.Unlock()
		m.closeConnection(conn)
		return existing, nil
	}
	if m.conns == nil {
		m.conns = make(map[string]*Connection)
	}
	m.conns[name] = conn
	m.mu.Unlock()
	return conn, nil
}

func (m *Manager) getRuntimeConnection(ctx context.Context) (*Connection, error) {
	now := m.currentTime()
	if conn, ok := m.getActiveRuntimeConnection(now); ok {
		return conn, nil
	}

	m.runtimeInitMu.Lock()
	defer m.runtimeInitMu.Unlock()

	now = m.currentTime()
	if conn, ok := m.getActiveRuntimeConnection(now); ok {
		return conn, nil
	}

	return m.loadRuntimeConnectionFromFile(ctx)
}

func (m *Manager) getActiveRuntimeConnection(now time.Time) (*Connection, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.runtime == nil || !now.Before(m.runtime.expiresAt) {
		return nil, false
	}

	m.runtime.expiresAt = now.Add(DefaultRuntimeLeaseDuration)
	return m.runtime.connection, true
}

func (m *Manager) GetExecutor(ctx context.Context, name string) (DBExecutor, error) {
	conn, err := m.GetConnection(ctx, name)
	if err != nil {
		return nil, err
	}
	return conn.executor, nil
}

func (m *Manager) InitializeRuntimeConnection(ctx context.Context, databaseURL string) (*InitializeDBResult, error) {
	ctx = normalizeContext(ctx)
	trimmedDatabaseURL := strings.TrimSpace(databaseURL)
	if trimmedDatabaseURL == "" {
		if _, err := m.getRuntimeConnection(ctx); err != nil {
			return nil, err
		}
		return &InitializeDBResult{
			Success: true,
			Data: InitializeDBData{
				Source:    initializeDBSourcePersistedFile,
				StatePath: m.runtimeFilePath(),
			},
		}, nil
	}

	m.runtimeInitMu.Lock()
	defer m.runtimeInitMu.Unlock()

	cfg, err := runtimeConnectionConfig(trimmedDatabaseURL)
	if err != nil {
		return nil, err
	}

	conn, err := m.openConnection(ctx, runtimeConnectionName, cfg, true)
	if err != nil {
		return nil, err
	}
	if err := m.persistRuntimeState(cfg.DSN); err != nil {
		m.closeConnection(conn)
		return nil, err
	}

	m.installRuntimeConnection(conn, cfg.DSN)
	return &InitializeDBResult{
		Success: true,
		Data: InitializeDBData{
			Source:    initializeDBSourceDatabaseURL,
			StatePath: m.runtimeFilePath(),
		},
	}, nil
}

func (m *Manager) ExecuteSQL(ctx context.Context, req ExecuteSQLRequest) (*ExecuteSQLResult, error) {
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

	executor, err := m.GetExecutor(ctx, req.Connection)
	if err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(NormalizeTimeoutMS(req.TimeoutMS))*time.Millisecond)
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
	executor, err := m.GetExecutor(ctx, connection)
	if err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(DefaultTimeoutMS)*time.Millisecond)
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
	executor, err := m.GetExecutor(ctx, connection)
	if err != nil {
		return nil, err
	}
	timeoutCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(DefaultTimeoutMS)*time.Millisecond)
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

	executor, err := m.GetExecutor(ctx, connection)
	if err != nil {
		return nil, err
	}
	timeoutCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(DefaultTimeoutMS)*time.Millisecond)
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

func (m *Manager) openConnection(ctx context.Context, name string, cfg ConnectionConfig, ping bool) (*Connection, error) {
	dbConn, err := m.openDB(cfg.Driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open connection %q: %w", name, err)
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
	if ping {
		pingCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(DefaultTimeoutMS)*time.Millisecond)
		defer cancel()
		if err := dbConn.PingContext(pingCtx); err != nil {
			_ = dbConn.Close()
			return nil, fmt.Errorf("ping connection %q: %w", name, err)
		}
	}

	conn := &Connection{
		Name:   name,
		DB:     dbConn,
		Driver: cfg.Driver,
	}
	switch cfg.Driver {
	case DriverMySQL:
		conn.executor = newMySQLExecutor(dbConn)
	default:
		_ = dbConn.Close()
		return nil, fmt.Errorf("connection %q uses unsupported driver %q", name, cfg.Driver)
	}

	return conn, nil
}

func (m *Manager) loadRuntimeConnectionFromFile(ctx context.Context) (*Connection, error) {
	databaseURL, err := m.readPersistedRuntimeDatabaseURL()
	if err != nil {
		return nil, err
	}

	cfg, err := runtimeConnectionConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("initialize runtime database from %s: %w", m.runtimeFilePath(), err)
	}

	conn, err := m.openConnection(ctx, runtimeConnectionName, cfg, true)
	if err != nil {
		return nil, err
	}
	m.installRuntimeConnection(conn, cfg.DSN)
	return conn, nil
}

func (m *Manager) readPersistedRuntimeDatabaseURL() (string, error) {
	path := m.runtimeFilePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("runtime database is not initialized; call initialize_db with database_url or ensure %s exists", path)
		}
		return "", fmt.Errorf("read runtime database state %q: %w", path, err)
	}

	var state runtimeStateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return "", fmt.Errorf("parse runtime database state %q: %w", path, err)
	}

	databaseURL := strings.TrimSpace(state.DatabaseURL)
	if databaseURL == "" {
		return "", fmt.Errorf("runtime database state %q is missing database_url", path)
	}
	return databaseURL, nil
}

func (m *Manager) persistRuntimeState(databaseURL string) error {
	path := m.runtimeFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime database state directory %q: %w", dir, err)
	}

	raw, err := json.MarshalIndent(runtimeStateFile{DatabaseURL: databaseURL}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime database state: %w", err)
	}
	raw = append(raw, byte(10))

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write runtime database state %q: %w", path, err)
	}
	return nil
}

func (m *Manager) installRuntimeConnection(conn *Connection, databaseURL string) {
	m.mu.Lock()
	oldConn := m.clearRuntimeConnectionLocked()
	m.runtime = &runtimeConnectionState{
		connection:  conn,
		databaseURL: databaseURL,
		expiresAt:   m.currentTime().Add(DefaultRuntimeLeaseDuration),
	}
	m.mu.Unlock()

	m.closeConnection(oldConn)
}

func (m *Manager) clearRuntimeConnectionLocked() *Connection {
	if m.runtime == nil {
		return nil
	}

	oldConn := m.runtime.connection
	m.runtime = nil
	return oldConn
}

func (m *Manager) runtimeFilePath() string {
	if strings.TrimSpace(m.runtimeStatePath) == "" {
		return DefaultRuntimeStatePath
	}
	return m.runtimeStatePath
}

func (m *Manager) currentTime() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

func (m *Manager) closeConnection(conn *Connection) {
	if conn == nil || conn.DB == nil {
		return
	}
	_ = conn.DB.Close()
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
