package db

import (
	"context"
	"database/sql"
	"sync"
)

const (
	DriverMySQL              = "mysql"
	DefaultConnectionsEnvVar = "VERIX_DB_CONNECTIONS"
	DefaultLimit             = 100
	DefaultTimeoutMS         = 2000
)

type DBExecutor interface {
	Query(ctx context.Context, sql string, args ...any) (*QueryResult, error)
	Exec(ctx context.Context, sql string, args ...any) (*ExecResult, error)

	GetSchema(ctx context.Context) (*Schema, error)
	DescribeTable(ctx context.Context, table string) (*TableSchema, error)
}

type Connection struct {
	Name   string  `json:"name"`
	DB     *sql.DB `json:"-"`
	Driver string  `json:"driver"`

	executor DBExecutor
}

type Manager struct {
	conns map[string]*Connection

	envVar string
	getenv func(string) string
	openDB func(driverName, dsn string) (*sql.DB, error)

	configs   map[string]ConnectionConfig
	configErr error
	loaded    bool
	mu        sync.Mutex
}

type ConnectionConfig struct {
	Driver            string `json:"driver,omitempty"`
	DSN               string `json:"dsn"`
	MaxOpenConns      int    `json:"max_open_conns,omitempty"`
	MaxIdleConns      int    `json:"max_idle_conns,omitempty"`
	ConnMaxLifetimeMS int    `json:"conn_max_lifetime_ms,omitempty"`
}

type QueryResult struct {
	Columns  []ResultColumn `json:"columns"`
	Rows     [][]any        `json:"rows"`
	RowCount int            `json:"row_count"`
}

type ExecResult struct {
	RowsAffected int64  `json:"rows_affected"`
	LastInsertID *int64 `json:"last_insert_id,omitempty"`
}

type ResultColumn struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type Schema struct {
	Tables []SchemaTable `json:"tables"`
}

type SchemaTable struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

type TableSchema struct {
	Table   string        `json:"table"`
	Columns []TableColumn `json:"columns"`
	Indexes []Index       `json:"indexes,omitempty"`
}

type TableColumn struct {
	Name         string               `json:"name"`
	Type         string               `json:"type"`
	Nullable     bool                 `json:"nullable,omitempty"`
	IsPrimaryKey bool                 `json:"is_primary_key,omitempty"`
	IsForeignKey bool                 `json:"is_foreign_key,omitempty"`
	References   *ForeignKeyReference `json:"references,omitempty"`
	DefaultValue *string              `json:"default_value,omitempty"`
	Extra        string               `json:"extra,omitempty"`
}

type ForeignKeyReference struct {
	Table  string `json:"table"`
	Column string `json:"column"`
}

type Index struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
}

type ExecuteSQLRequest struct {
	Connection string         `json:"connection"`
	SQL        string         `json:"sql"`
	Params     map[string]any `json:"params,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	TimeoutMS  int            `json:"timeout_ms,omitempty"`
	ReadOnly   *bool          `json:"readonly,omitempty"`
}

type ExecuteSQLResult struct {
	Success bool           `json:"success"`
	Data    ExecuteSQLData `json:"data"`
	Meta    ExecuteSQLMeta `json:"meta"`
}

type ExecuteSQLData struct {
	Operation    string         `json:"operation"`
	Columns      []ResultColumn `json:"columns"`
	Rows         [][]any        `json:"rows"`
	RowCount     int            `json:"row_count"`
	RowsAffected int64          `json:"rows_affected,omitempty"`
	LastInsertID *int64         `json:"last_insert_id,omitempty"`
}

type ExecuteSQLMeta struct {
	LatencyMS int64 `json:"latency_ms"`
	Truncated bool  `json:"truncated"`
}

type ListTablesResult struct {
	Data TableListData `json:"data"`
}

type TableListData struct {
	Tables []string `json:"tables"`
}

type GetSchemaResult struct {
	Data Schema `json:"data"`
}

type DescribeTableResult struct {
	Data TableSchema `json:"data"`
}

type AnalyzeQueryResult struct {
	Data SQLAnalysis `json:"data"`
}

type SQLAnalysis struct {
	Operation string   `json:"operation"`
	Tables    []string `json:"tables,omitempty"`
	RiskLevel string   `json:"risk_level"`
	Warnings  []string `json:"warnings,omitempty"`

	HasWhere              bool `json:"-"`
	HasLimit              bool `json:"-"`
	HasMultipleStatements bool `json:"-"`
}
