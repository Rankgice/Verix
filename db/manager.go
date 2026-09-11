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

// 运行时连接使用固定内部名称，并在初始化结果中标记配置来源。
const (
	runtimeConnectionName           = "runtime"
	initializeDBSourceDatabaseURL   = "database_url"
	initializeDBSourcePersistedFile = "persisted_state"
)

// runtimeStateFile 是写入 .mcp/db.json 的最小运行时数据库状态。
type runtimeStateFile struct {
	// DatabaseURL 是用户提供并持久化的原始数据库 DSN。
	DatabaseURL string `json:"database_url"`
	// DBType 标识 mysql 或 sqlite。
	DBType string `json:"db_type"`
	// IsReadOnly 表示恢复连接时是否应用驱动级只读参数。
	IsReadOnly bool `json:"is_readonly"`
}

// tableLister 是支持高效列举表名的可选执行器能力。
type tableLister interface {
	// ListTables 返回当前数据库的业务表名。
	ListTables(ctx context.Context) ([]string, error)
}

// NewManager 使用默认环境变量和系统环境读取函数创建数据库管理器。
func NewManager() *Manager {
	return NewManagerFromEnv(DefaultConnectionsEnvVar, os.Getenv)
}

// NewManagerFromEnv 使用可注入的环境读取函数创建管理器，主要用于测试或自定义配置源。
func NewManagerFromEnv(envVar string, getenv func(string) string) *Manager {
	if strings.TrimSpace(envVar) == "" {
		envVar = DefaultConnectionsEnvVar
	}
	if getenv == nil {
		getenv = os.Getenv
	}

	// 默认仅创建空缓存，实际环境配置和数据库连接都在首次使用时加载。
	return &Manager{
		conns:            make(map[string]*Connection),
		envVar:           envVar,
		getenv:           getenv,
		openDB:           sql.Open,
		now:              time.Now,
		runtimeStatePath: DefaultRuntimeStatePath,
	}
}

// GetConnection 返回命名连接；连接名为空时返回 initialize_db 管理的运行时连接。
func (m *Manager) GetConnection(ctx context.Context, name string) (*Connection, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return m.getRuntimeConnection(normalizeContext(ctx))
	}
	return m.getNamedConnection(normalizeContext(ctx), trimmedName)
}

// getNamedConnection 延迟加载环境配置并并发安全地缓存指定命名连接。
func (m *Manager) getNamedConnection(ctx context.Context, name string) (*Connection, error) {
	if err := m.ensureConfigsLoaded(); err != nil {
		return nil, err
	}

	// 第一阶段在锁内读取缓存和配置，打开连接的慢操作放到锁外执行。
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

	// 并发调用可能已安装同名连接，此时复用先完成的连接并关闭当前新建连接。
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

// getRuntimeConnection 返回有效运行时连接，租约失效时从状态文件重新建立连接。
func (m *Manager) getRuntimeConnection(ctx context.Context) (*Connection, error) {
	now := m.currentTime()
	if conn, ok := m.getActiveRuntimeConnection(now); ok {
		return conn, nil
	}

	// 冷启动和过期重载必须串行，避免并发创建多个运行时连接。
	m.runtimeInitMu.Lock()
	defer m.runtimeInitMu.Unlock()

	now = m.currentTime()
	if conn, ok := m.getActiveRuntimeConnection(now); ok {
		return conn, nil
	}

	return m.loadRuntimeConnectionFromFile(ctx)
}

// getActiveRuntimeConnection 获取未过期连接并将其租约向后续期。
func (m *Manager) getActiveRuntimeConnection(now time.Time) (*Connection, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.runtime == nil || !now.Before(m.runtime.expiresAt) {
		return nil, false
	}

	// 每次成功访问都会滑动续租，活跃连接不会因固定创建时间而过期。
	m.runtime.expiresAt = now.Add(DefaultRuntimeLeaseDuration)
	return m.runtime.connection, true
}

// GetExecutor 获取连接对应的 MySQL 或 SQLite 协议执行器。
func (m *Manager) GetExecutor(ctx context.Context, name string) (DBExecutor, error) {
	conn, err := m.GetConnection(ctx, name)
	if err != nil {
		return nil, err
	}
	return conn.executor, nil
}

// InitializeRuntimeConnection 初始化并持久化运行时连接；DSN 为空时复用已有状态文件。
func (m *Manager) InitializeRuntimeConnection(ctx context.Context, databaseURL string, dbType string, isReadOnly bool) (*InitializeDBResult, error) {
	ctx = normalizeContext(ctx)
	// 空 DSN 表示调用方要求从状态文件恢复，而不是创建一个空连接。
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

	// 先生成驱动专属的有效 DSN，再打开并 Ping 数据库。
	cfg, state, err := runtimeConnectionConfig(runtimeStateFile{
		DatabaseURL: trimmedDatabaseURL,
		DBType:      dbType,
		IsReadOnly:  isReadOnly,
	})
	if err != nil {
		return nil, err
	}

	conn, err := m.openConnection(ctx, runtimeConnectionName, cfg, true)
	if err != nil {
		return nil, err
	}
	// 只有连通性验证成功后才落盘，避免持久化不可用配置。
	if err := m.persistRuntimeState(state); err != nil {
		m.closeConnection(conn)
		return nil, err
	}

	m.installRuntimeConnection(conn, state)
	return &InitializeDBResult{
		Success: true,
		Data: InitializeDBData{
			Source:    initializeDBSourceDatabaseURL,
			StatePath: m.runtimeFilePath(),
		},
	}, nil
}

// ExecuteSQL 分析、校验、绑定并执行单条 SQL，统一处理超时、行数限制和结果格式。
func (m *Manager) ExecuteSQL(ctx context.Context, req ExecuteSQLRequest) (*ExecuteSQLResult, error) {
	sqlText := strings.TrimSpace(req.SQL)
	if sqlText == "" {
		return nil, fmt.Errorf("sql is required")
	}

	// 所有语句先经过静态分析和安全校验，危险 SQL 不会到达驱动。
	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return nil, err
	}
	if err := ValidateExecution(analysis, normalizeReadOnly(req.ReadOnly)); err != nil {
		return nil, err
	}

	// 对无 LIMIT 的 SELECT 多取一行，以准确判断结果是否真的被截断。
	requestedLimit := NormalizeLimit(req.Limit)
	rewriteLimit := requestedLimit
	if analysis.Operation == "SELECT" && !analysis.HasLimit {
		rewriteLimit++
	}

	// LIMIT 重写在命名参数绑定前执行，随后统一转换 :name 占位符。
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

	// 每次 SQL 使用独立超时上下文，防止慢查询长期占用 Tool 调用。
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

	// 查询类语句读取行集，其余语句只返回影响行数和最后插入 ID。
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

// ListTables 返回指定连接中的业务表名，连接为空时使用运行时数据库。
func (m *Manager) ListTables(ctx context.Context, connection string) (*ListTablesResult, error) {
	executor, err := m.GetExecutor(ctx, connection)
	if err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(normalizeContext(ctx), time.Duration(DefaultTimeoutMS)*time.Millisecond)
	defer cancel()

	// 优先使用驱动专属的高效列表能力，其他执行器可回退到完整 Schema。
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

// GetSchemaResult 返回指定连接中表名和列名组成的轻量 Schema。
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

// DescribeTableResult 返回指定表的列、索引和外键等详细元数据。
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

// ensureConfigsLoaded 只解析一次环境变量，并缓存成功配置或解析错误。
func (m *Manager) ensureConfigsLoaded() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return m.configErr
	}

	// 成功结果和错误都会缓存，避免每次调用重复解析同一环境变量。
	m.configs, m.configErr = parseConnectionConfigs(m.envVar, m.getenv(m.envVar))
	m.loaded = true
	return m.configErr
}

// openConnection 打开并配置连接池，按驱动选择执行器，并可选地验证连通性。
func (m *Manager) openConnection(ctx context.Context, name string, cfg ConnectionConfig, ping bool) (*Connection, error) {
	// MySQL 和 modernc SQLite 的注册名与公开 Driver 常量一致，可直接传给 sql.Open。
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
	// SQLite 的 :memory: 数据库与单个物理连接绑定，将连接池限制为 1 可避免不同连接看到不同数据库。
	if cfg.Driver == DriverSQLite && isSQLiteMemoryDSN(cfg.DSN) {
		dbConn.SetMaxOpenConns(1)
		dbConn.SetMaxIdleConns(1)
	}
	// initialize_db 需要立即 Ping 并反馈错误；命名连接维持 database/sql 的延迟连接语义。
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
	// 执行器负责适配各数据库不同的 Schema 元数据 SQL。
	switch cfg.Driver {
	case DriverMySQL:
		conn.executor = newMySQLExecutor(dbConn)
	case DriverSQLite:
		conn.executor = newSQLiteExecutor(dbConn)
	default:
		_ = dbConn.Close()
		return nil, fmt.Errorf("connection %q uses unsupported driver %q", name, cfg.Driver)
	}

	return conn, nil
}

// loadRuntimeConnectionFromFile 从持久化状态恢复、验证并安装运行时连接。
func (m *Manager) loadRuntimeConnectionFromFile(ctx context.Context) (*Connection, error) {
	state, err := m.readPersistedRuntimeState()
	if err != nil {
		return nil, err
	}

	cfg, state, err := runtimeConnectionConfig(state)
	if err != nil {
		return nil, fmt.Errorf("initialize runtime database from %s: %w", m.runtimeFilePath(), err)
	}

	conn, err := m.openConnection(ctx, runtimeConnectionName, cfg, true)
	if err != nil {
		return nil, err
	}
	m.installRuntimeConnection(conn, state)
	return conn, nil
}

// readPersistedRuntimeState 读取并校验 .mcp/db.json 中的运行时数据库状态。
func (m *Manager) readPersistedRuntimeState() (runtimeStateFile, error) {
	path := m.runtimeFilePath()
	// 缺少状态文件时给出 initialize_db 的明确使用提示。
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return runtimeStateFile{}, fmt.Errorf("runtime database is not initialized; call initialize_db with database_url or ensure %s exists", path)
		}
		return runtimeStateFile{}, fmt.Errorf("read runtime database state %q: %w", path, err)
	}

	var state runtimeStateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return runtimeStateFile{}, fmt.Errorf("parse runtime database state %q: %w", path, err)
	}

	normalizedState, err := normalizeRuntimeStateFile(state)
	if err != nil {
		return runtimeStateFile{}, fmt.Errorf("invalid runtime database state %q: %w", path, err)
	}
	return normalizedState, nil
}

// persistRuntimeState 以仅当前用户可读写的权限保存运行时数据库状态。
func (m *Manager) persistRuntimeState(state runtimeStateFile) error {
	path := m.runtimeFilePath()
	dir := filepath.Dir(path)
	// 状态中可能包含数据库凭据，目录和文件均使用仅当前用户可访问的权限。
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime database state directory %q: %w", dir, err)
	}

	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime database state: %w", err)
	}
	raw = append(raw, byte(10))

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write runtime database state %q: %w", path, err)
	}
	return nil
}

// installRuntimeConnection 原子替换运行时连接、设置新租约并关闭旧连接。
func (m *Manager) installRuntimeConnection(conn *Connection, state runtimeStateFile) {
	// 锁内只交换状态，耗时的 Close 放到锁外执行。
	m.mu.Lock()
	oldConn := m.clearRuntimeConnectionLocked()
	m.runtime = &runtimeConnectionState{
		connection:  conn,
		databaseURL: state.DatabaseURL,
		dbType:      state.DBType,
		isReadOnly:  state.IsReadOnly,
		expiresAt:   m.currentTime().Add(DefaultRuntimeLeaseDuration),
	}
	m.mu.Unlock()

	m.closeConnection(oldConn)
}

// clearRuntimeConnectionLocked 在持有 m.mu 时移除运行时连接并返回旧连接。
func (m *Manager) clearRuntimeConnectionLocked() *Connection {
	if m.runtime == nil {
		return nil
	}

	oldConn := m.runtime.connection
	m.runtime = nil
	return oldConn
}

// runtimeFilePath 返回自定义状态路径，空值时回退到默认路径。
func (m *Manager) runtimeFilePath() string {
	if strings.TrimSpace(m.runtimeStatePath) == "" {
		return DefaultRuntimeStatePath
	}
	return m.runtimeStatePath
}

// currentTime 返回可测试注入的当前时间。
func (m *Manager) currentTime() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

// closeConnection 安全关闭非空数据库连接。
func (m *Manager) closeConnection(conn *Connection) {
	if conn == nil || conn.DB == nil {
		return
	}
	_ = conn.DB.Close()
}

// normalizeContext 将 nil 上下文替换为 Background，避免 database/sql 调用崩溃。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
