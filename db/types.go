package db

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// 数据库驱动名称、Tool 默认值和运行时连接默认配置。
const (
	// DriverMySQL 是配置和 database/sql 使用的 MySQL 驱动名称。
	DriverMySQL = "mysql"
	// DriverSQLite 是配置和 database/sql 使用的 SQLite 驱动名称。
	DriverSQLite = "sqlite"

	// DefaultConnectionsEnvVar 是命名数据库连接的默认环境变量。
	DefaultConnectionsEnvVar = "VERIX_DB_CONNECTIONS"
	// DefaultLimit 是 SELECT 未指定 limit 时的默认最大返回行数。
	DefaultLimit = 100
	// DefaultTimeoutMS 是数据库查询和 Schema 操作的默认超时毫秒数。
	DefaultTimeoutMS = 2000

	// DefaultRuntimeStatePath 是 initialize_db 持久化运行时连接状态的默认路径。
	DefaultRuntimeStatePath = ".mcp/db.json"
	// DefaultRuntimeLeaseDuration 是运行时连接每次被访问后续租的时长。
	DefaultRuntimeLeaseDuration = 30 * time.Minute
	// DefaultRuntimeMaxOpenConns 是运行时数据库连接池的默认最大打开连接数。
	DefaultRuntimeMaxOpenConns = 10
	// DefaultRuntimeMaxIdleConns 是运行时数据库连接池的默认最大空闲连接数。
	DefaultRuntimeMaxIdleConns = 10
)

// DBExecutor 统一 MySQL 与 SQLite 的 SQL 执行和 Schema 查询能力。
type DBExecutor interface {
	// Query 执行会返回结果集的 SQL。
	Query(ctx context.Context, sql string, args ...any) (*QueryResult, error)
	// Exec 执行不会返回结果集的 SQL。
	Exec(ctx context.Context, sql string, args ...any) (*ExecResult, error)

	// GetSchema 返回当前数据库的轻量表结构。
	GetSchema(ctx context.Context) (*Schema, error)
	// DescribeTable 返回指定表的详细列、索引和外键信息。
	DescribeTable(ctx context.Context, table string) (*TableSchema, error)
}

// Connection 保存一个已打开数据库连接及其协议执行器。
type Connection struct {
	// Name 是运行时连接名或 VERIX_DB_CONNECTIONS 中的命名连接名。
	Name string `json:"name"`
	// DB 是底层 database/sql 连接池，不参与 JSON 序列化。
	DB *sql.DB `json:"-"`
	// Driver 标识 mysql 或 sqlite。
	Driver string `json:"driver"`

	// executor 封装驱动专属的 Schema 查询实现。
	executor DBExecutor
}

// runtimeConnectionState 保存 initialize_db 创建的临时运行时连接及租约信息。
type runtimeConnectionState struct {
	// connection 是当前生效的运行时连接。
	connection *Connection
	// databaseURL 是持久化时使用的原始 DSN，不包含运行时追加的只读参数。
	databaseURL string
	// dbType 标识运行时数据库类型。
	dbType string
	// isReadOnly 记录初始化时声明的只读模式。
	isReadOnly bool
	// expiresAt 是当前连接租约到期时间。
	expiresAt time.Time
}

// Manager 延迟加载并管理命名连接、运行时连接以及安全 SQL 执行流程。
type Manager struct {
	// conns 缓存已打开的命名连接。
	conns map[string]*Connection

	// envVar 和 getenv 用于延迟读取连接配置，并允许测试注入环境。
	envVar string
	getenv func(string) string
	// openDB 允许测试替换 sql.Open。
	openDB func(driverName, dsn string) (*sql.DB, error)
	// now 允许测试控制运行时租约时间。
	now func() time.Time

	// runtimeStatePath 是运行时连接状态文件路径。
	runtimeStatePath string

	// configs 和 configErr 缓存一次性的环境配置解析结果。
	configs   map[string]ConnectionConfig
	configErr error
	loaded    bool
	// runtime 保存当前运行时连接。
	runtime *runtimeConnectionState
	// runtimeInitMu 串行化运行时连接的创建和冷启动加载。
	runtimeInitMu sync.Mutex
	// mu 保护配置缓存、连接缓存和运行时连接状态。
	mu sync.Mutex
}

// ConnectionConfig 描述一个 MySQL 或 SQLite 命名连接及其连接池参数。
type ConnectionConfig struct {
	// Driver 支持 mysql 和 sqlite，空值默认使用 mysql。
	Driver string `json:"driver,omitempty"`
	// DSN 是驱动原生连接串；SQLite 可使用文件路径、:memory: 或 file: URI。
	DSN string `json:"dsn"`
	// MaxOpenConns 限制连接池最大打开连接数，零值沿用 database/sql 默认值。
	MaxOpenConns int `json:"max_open_conns,omitempty"`
	// MaxIdleConns 限制连接池最大空闲连接数，零值沿用 database/sql 默认值。
	MaxIdleConns int `json:"max_idle_conns,omitempty"`
	// ConnMaxLifetimeMS 设置连接最大复用时间，零值表示不限制。
	ConnMaxLifetimeMS int `json:"conn_max_lifetime_ms,omitempty"`
}

// QueryResult 是可 JSON 序列化的查询结果。
type QueryResult struct {
	// Columns 按结果集顺序描述列名和数据库类型。
	Columns []ResultColumn `json:"columns"`
	// Rows 保存二维行列数据。
	Rows [][]any `json:"rows"`
	// RowCount 是 Rows 中的实际行数。
	RowCount int `json:"row_count"`
}

// ExecResult 是 INSERT、UPDATE 等非查询语句的执行结果。
type ExecResult struct {
	// RowsAffected 是受语句影响的行数。
	RowsAffected int64 `json:"rows_affected"`
	// LastInsertID 是驱动支持时返回的最后插入主键。
	LastInsertID *int64 `json:"last_insert_id,omitempty"`
}

// ResultColumn 描述查询结果中的一列。
type ResultColumn struct {
	// Name 是结果列名或别名。
	Name string `json:"name"`
	// Type 是驱动返回的数据库类型名称。
	Type string `json:"type,omitempty"`
}

// Schema 保存数据库中的轻量表结构列表。
type Schema struct {
	// Tables 按稳定顺序保存业务表。
	Tables []SchemaTable `json:"tables"`
}

// SchemaTable 描述一个表及其列名列表。
type SchemaTable struct {
	// Name 是表名。
	Name string `json:"name"`
	// Columns 按声明顺序保存列名。
	Columns []string `json:"columns"`
}

// TableSchema 描述一张表的详细列与索引信息。
type TableSchema struct {
	// Table 是被描述的表名。
	Table string `json:"table"`
	// Columns 按声明顺序保存列定义。
	Columns []TableColumn `json:"columns"`
	// Indexes 保存主键、唯一索引和普通索引。
	Indexes []Index `json:"indexes,omitempty"`
}

// TableColumn 描述数据库列及其约束信息。
type TableColumn struct {
	// Name 是列名。
	Name string `json:"name"`
	// Type 是数据库声明的数据类型。
	Type string `json:"type"`
	// Nullable 表示列是否允许 NULL。
	Nullable bool `json:"nullable,omitempty"`
	// IsPrimaryKey 表示列是否属于主键。
	IsPrimaryKey bool `json:"is_primary_key,omitempty"`
	// IsForeignKey 表示列是否拥有外键引用。
	IsForeignKey bool `json:"is_foreign_key,omitempty"`
	// References 保存外键目标表和目标列。
	References *ForeignKeyReference `json:"references,omitempty"`
	// DefaultValue 保存数据库定义的默认值表达式。
	DefaultValue *string `json:"default_value,omitempty"`
	// Extra 保存自增、生成列等附加属性。
	Extra string `json:"extra,omitempty"`
}

// ForeignKeyReference 描述外键引用目标。
type ForeignKeyReference struct {
	// Table 是被引用的表名。
	Table string `json:"table"`
	// Column 是被引用的列名。
	Column string `json:"column"`
}

// Index 描述一个数据库索引。
type Index struct {
	// Name 是索引名；SQLite 主键统一表示为 PRIMARY。
	Name string `json:"name"`
	// Columns 按索引顺序保存列名。
	Columns []string `json:"columns"`
	// Unique 表示索引是否具有唯一性约束。
	Unique bool `json:"unique"`
}

// ExecuteSQLRequest 描述 execute_sql 的数据库选择、安全开关和执行参数。
type ExecuteSQLRequest struct {
	// Connection 是可选命名连接；空值使用 initialize_db 创建的运行时连接。
	Connection string `json:"connection,omitempty"`
	// SQL 是待分析和执行的单条 SQL。
	SQL string `json:"sql"`
	// Params 保存 :name 形式的命名参数。
	Params map[string]any `json:"params,omitempty"`
	// Limit 是缺少 LIMIT 的 SELECT 最大返回行数。
	Limit int `json:"limit,omitempty"`
	// TimeoutMS 是本次执行超时毫秒数。
	TimeoutMS int `json:"timeout_ms,omitempty"`
	// ReadOnly 为空时默认 true，限制为仅执行 SELECT。
	ReadOnly *bool `json:"readonly,omitempty"`
}

// ExecuteSQLResult 是 execute_sql 的统一输出。
type ExecuteSQLResult struct {
	// Success 表示 SQL 已成功完成。
	Success bool `json:"success"`
	// Data 保存查询行或语句影响信息。
	Data ExecuteSQLData `json:"data"`
	// Meta 保存耗时和截断标记。
	Meta ExecuteSQLMeta `json:"meta"`
}

// ExecuteSQLData 保存查询语句和非查询语句的统一结果字段。
type ExecuteSQLData struct {
	// Operation 是识别出的顶层 SQL 操作。
	Operation string `json:"operation"`
	// Columns 是查询结果列定义。
	Columns []ResultColumn `json:"columns"`
	// Rows 是查询结果行。
	Rows [][]any `json:"rows"`
	// RowCount 是实际返回行数。
	RowCount int `json:"row_count"`
	// RowsAffected 是非查询语句影响行数。
	RowsAffected int64 `json:"rows_affected,omitempty"`
	// LastInsertID 是驱动支持时返回的最后插入主键。
	LastInsertID *int64 `json:"last_insert_id,omitempty"`
}

// ExecuteSQLMeta 保存 SQL 执行元信息。
type ExecuteSQLMeta struct {
	// LatencyMS 是数据库调用耗时毫秒数。
	LatencyMS int64 `json:"latency_ms"`
	// Truncated 表示查询结果因自动上限被裁剪。
	Truncated bool `json:"truncated"`
}

// ListTablesResult 是 list_tables 的输出包装。
type ListTablesResult struct {
	// Data 保存表名列表。
	Data TableListData `json:"data"`
}

// TableListData 保存数据库表名。
type TableListData struct {
	// Tables 是按名称稳定排序的业务表列表。
	Tables []string `json:"tables"`
}

// GetSchemaResult 是 get_schema 的输出包装。
type GetSchemaResult struct {
	// Data 保存轻量数据库结构。
	Data Schema `json:"data"`
}

// DescribeTableResult 是 describe_table 的输出包装。
type DescribeTableResult struct {
	// Data 保存详细表结构。
	Data TableSchema `json:"data"`
}

// InitializeDBResult 是 initialize_db 的输出。
type InitializeDBResult struct {
	// Success 表示运行时数据库初始化成功。
	Success bool `json:"success"`
	// Data 描述连接来源和持久化路径。
	Data InitializeDBData `json:"data"`
}

// InitializeDBData 描述运行时数据库状态来源。
type InitializeDBData struct {
	// Source 是 database_url 或 persisted_state。
	Source string `json:"source"`
	// StatePath 是运行时状态文件路径。
	StatePath string `json:"state_path"`
}

// AnalyzeQueryResult 是 analyze_query 的输出包装。
type AnalyzeQueryResult struct {
	// Data 保存静态 SQL 分析结果。
	Data SQLAnalysis `json:"data"`
}

// SQLAnalysis 保存 SQL 操作、涉及表、风险等级和安全检查标记。
type SQLAnalysis struct {
	// Operation 是顶层 SQL 操作，例如 SELECT 或 UPDATE。
	Operation string `json:"operation"`
	// Tables 是静态分析识别出的表名。
	Tables []string `json:"tables,omitempty"`
	// RiskLevel 是 low、medium 或 high。
	RiskLevel string `json:"risk_level"`
	// Warnings 是面向调用方的安全提示。
	Warnings []string `json:"warnings,omitempty"`

	// HasWhere 标记顶层语句是否包含 WHERE。
	HasWhere bool `json:"-"`
	// HasLimit 标记顶层语句是否包含 LIMIT。
	HasLimit bool `json:"-"`
	// HasMultipleStatements 标记输入是否包含多条 SQL。
	HasMultipleStatements bool `json:"-"`
}
