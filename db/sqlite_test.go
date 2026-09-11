package db

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestSQLiteManagerSupportsDBOperations 验证命名 SQLite 连接支持执行 SQL、列出表和读取完整表结构。
func TestSQLiteManagerSupportsDBOperations(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "verix.db")
	rawConfig, err := json.Marshal(map[string]ConnectionConfig{
		"local": {Driver: DriverSQLite, DSN: databasePath},
	})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	// 通过真实 Manager 打开命名连接，覆盖环境配置解析和 SQLite 执行器选择逻辑。
	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return string(rawConfig) })
	t.Cleanup(func() { closeManagerConnections(manager) })
	conn, err := manager.GetConnection(context.Background(), "local")
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}

	// 建立包含默认值、外键、唯一约束和普通索引的表，验证各类 Schema 元数据。
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            manager_id INTEGER REFERENCES users(id),
            status TEXT DEFAULT 'active',
            display_name TEXT GENERATED ALWAYS AS (email || ':' || status) VIRTUAL
        )`,
		`CREATE INDEX idx_users_status ON users(status)`,
		`INSERT INTO users(email) VALUES ('alice@example.com')`,
	}
	for _, statement := range statements {
		if _, err := conn.DB.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("ExecContext(%q) returned error: %v", statement, err)
		}
	}

	listResult, err := manager.ListTables(context.Background(), "local")
	if err != nil {
		t.Fatalf("ListTables returned error: %v", err)
	}
	if !reflect.DeepEqual(listResult.Data.Tables, []string{"users"}) {
		t.Fatalf("unexpected tables: %#v", listResult.Data.Tables)
	}

	schemaResult, err := manager.GetSchemaResult(context.Background(), "local")
	if err != nil {
		t.Fatalf("GetSchemaResult returned error: %v", err)
	}
	wantColumns := []string{"id", "email", "manager_id", "status", "display_name"}
	if len(schemaResult.Data.Tables) != 1 || !reflect.DeepEqual(schemaResult.Data.Tables[0].Columns, wantColumns) {
		t.Fatalf("unexpected schema: %#v", schemaResult.Data)
	}

	describeResult, err := manager.DescribeTableResult(context.Background(), "local", "users")
	if err != nil {
		t.Fatalf("DescribeTableResult returned error: %v", err)
	}
	assertSQLiteTableDescription(t, describeResult.Data)

	// 显式关闭 readonly 后，execute_sql 应能通过命名参数写入 SQLite。
	writeResult, err := manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{
		Connection: "local",
		SQL:        "INSERT INTO users(email, status) VALUES (:email, :status)",
		Params: map[string]any{
			"email":  "bob@example.com",
			"status": "pending",
		},
		ReadOnly: boolPointer(false),
	})
	if err != nil {
		t.Fatalf("write ExecuteSQL returned error: %v", err)
	}
	if writeResult.Data.RowsAffected != 1 || writeResult.Data.LastInsertID == nil {
		t.Fatalf("unexpected write result: %#v", writeResult.Data)
	}

	// 查询路径的命名参数和自动 LIMIT 逻辑应与 MySQL 保持一致。
	queryResult, err := manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{
		Connection: "local",
		SQL:        "SELECT id, email FROM users WHERE email = :email",
		Params:     map[string]any{"email": "alice@example.com"},
	})
	if err != nil {
		t.Fatalf("ExecuteSQL returned error: %v", err)
	}
	if queryResult.Data.RowCount != 1 || queryResult.Data.Rows[0][1] != "alice@example.com" {
		t.Fatalf("unexpected query result: %#v", queryResult.Data)
	}
}

// TestSQLiteMemoryConnectionUsesSinglePhysicalConnection 验证 :memory: 连接池被限制为单连接。
func TestSQLiteMemoryConnectionUsesSinglePhysicalConnection(t *testing.T) {
	rawConfig, err := json.Marshal(map[string]ConnectionConfig{
		"memory": {Driver: DriverSQLite, DSN: ":memory:", MaxOpenConns: 8, MaxIdleConns: 8},
	})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	// 即使用户为内存数据库配置更大的连接池，Manager 也必须覆盖为 1。
	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return string(rawConfig) })
	t.Cleanup(func() { closeManagerConnections(manager) })
	conn, err := manager.GetConnection(context.Background(), "memory")
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}
	if got := conn.DB.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("unexpected max open connections: %d", got)
	}
}

// TestSQLiteRuntimeReadOnlyConnection 验证 initialize_db 创建的 SQLite 只读连接允许查询并拒绝写入。
func TestSQLiteRuntimeReadOnlyConnection(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "readonly.db")
	seedManager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string {
		raw, _ := json.Marshal(map[string]ConnectionConfig{
			"seed": {Driver: DriverSQLite, DSN: databasePath},
		})
		return string(raw)
	})
	seedConnection, err := seedManager.GetConnection(context.Background(), "seed")
	if err != nil {
		t.Fatalf("seed GetConnection returned error: %v", err)
	}
	if _, err := seedConnection.DB.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create seed table: %v", err)
	}
	if _, err := seedConnection.DB.Exec(`INSERT INTO items(name) VALUES ('demo')`); err != nil {
		t.Fatalf("insert seed row: %v", err)
	}
	closeManagerConnections(seedManager)

	// 初始化运行时连接时使用原始文件路径，Manager 会在实际连接 DSN 上追加 mode=ro。
	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return "" })
	manager.runtimeStatePath = filepath.Join(t.TempDir(), ".mcp", "db.json")
	t.Cleanup(func() { closeManagerConnections(manager) })
	if _, err := manager.InitializeRuntimeConnection(context.Background(), databasePath, DriverSQLite, true); err != nil {
		t.Fatalf("InitializeRuntimeConnection returned error: %v", err)
	}
	if manager.runtime == nil || manager.runtime.dbType != DriverSQLite || !manager.runtime.isReadOnly {
		t.Fatalf("unexpected runtime state: %#v", manager.runtime)
	}

	queryResult, err := manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{SQL: "SELECT name FROM items"})
	if err != nil {
		t.Fatalf("readonly SELECT returned error: %v", err)
	}
	if queryResult.Data.RowCount != 1 {
		t.Fatalf("unexpected readonly query result: %#v", queryResult.Data)
	}

	_, err = manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{
		SQL:      "INSERT INTO items(name) VALUES ('blocked')",
		ReadOnly: boolPointer(false),
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "readonly") {
		t.Fatalf("expected SQLite readonly error, got: %v", err)
	}
}

// assertSQLiteTableDescription 校验 SQLite 表描述中的主键、外键、默认值、生成列和索引信息。
func assertSQLiteTableDescription(t *testing.T, schema TableSchema) {
	t.Helper()
	columns := make(map[string]TableColumn, len(schema.Columns))
	for _, column := range schema.Columns {
		columns[column.Name] = column
	}
	if !columns["id"].IsPrimaryKey || columns["id"].Nullable {
		t.Fatalf("unexpected primary key column: %#v", columns["id"])
	}
	if !columns["manager_id"].IsForeignKey || columns["manager_id"].References == nil || columns["manager_id"].References.Table != "users" || columns["manager_id"].References.Column != "id" {
		t.Fatalf("unexpected foreign key column: %#v", columns["manager_id"])
	}
	if columns["status"].DefaultValue == nil || *columns["status"].DefaultValue != "'active'" {
		t.Fatalf("unexpected default value: %#v", columns["status"])
	}
	if columns["display_name"].Extra != "generated virtual" {
		t.Fatalf("unexpected generated column metadata: %#v", columns["display_name"])
	}

	indexNames := make(map[string]bool, len(schema.Indexes))
	for _, index := range schema.Indexes {
		indexNames[index.Name] = index.Unique
	}
	if !indexNames["PRIMARY"] {
		t.Fatalf("PRIMARY index missing: %#v", schema.Indexes)
	}
	if _, ok := indexNames["idx_users_status"]; !ok {
		t.Fatalf("custom index missing: %#v", schema.Indexes)
	}
}

// boolPointer 创建布尔值指针，便于测试可选的 readonly 输入。
func boolPointer(value bool) *bool {
	return &value
}
