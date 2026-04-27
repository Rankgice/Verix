package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestInitializeRuntimeConnectionPersistsFileAndInstallsRuntimeState(t *testing.T) {
	const wantDSN = "user:pass@tcp(localhost:3306)/app?parseTime=true"

	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return "" })
	manager.runtimeStatePath = filepath.Join(t.TempDir(), ".mcp", "db.json")

	now := time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	var pingCount int32
	manager.openDB = func(driverName, dsn string) (*sql.DB, error) {
		if driverName != DriverMySQL {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		assertMySQLReadOnlyDSN(t, dsn, wantDSN)
		return newPingOnlyDB(nil, &pingCount, nil), nil
	}
	t.Cleanup(func() { closeManagerConnections(manager) })

	out, err := manager.InitializeRuntimeConnection(context.Background(), wantDSN, DriverMySQL, true)
	if err != nil {
		t.Fatalf("InitializeRuntimeConnection returned error: %v", err)
	}
	if !out.Success {
		t.Fatal("expected initialize result to be successful")
	}
	if out.Data.Source != initializeDBSourceDatabaseURL {
		t.Fatalf("unexpected source: %s", out.Data.Source)
	}
	if out.Data.StatePath != manager.runtimeStatePath {
		t.Fatalf("unexpected state path: %s", out.Data.StatePath)
	}

	raw, err := os.ReadFile(manager.runtimeStatePath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	var persisted runtimeStateFile
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if persisted.DatabaseURL != wantDSN {
		t.Fatalf("unexpected persisted database_url: %s", persisted.DatabaseURL)
	}
	if persisted.DBType != DriverMySQL {
		t.Fatalf("unexpected persisted db_type: %s", persisted.DBType)
	}
	if !persisted.IsReadOnly {
		t.Fatal("expected persisted is_readonly to be true")
	}

	if manager.runtime == nil {
		t.Fatal("expected runtime state to be installed")
	}
	if manager.runtime.databaseURL != wantDSN {
		t.Fatalf("unexpected runtime database_url: %s", manager.runtime.databaseURL)
	}
	if manager.runtime.dbType != DriverMySQL {
		t.Fatalf("unexpected runtime db_type: %s", manager.runtime.dbType)
	}
	if !manager.runtime.isReadOnly {
		t.Fatal("expected runtime isReadOnly to be true")
	}
	if !manager.runtime.expiresAt.Equal(now.Add(DefaultRuntimeLeaseDuration)) {
		t.Fatalf("unexpected lease expiry: %s", manager.runtime.expiresAt)
	}
	if manager.runtime.connection == nil || manager.runtime.connection.DB == nil {
		t.Fatal("expected runtime sql.DB to be installed")
	}
	if got := manager.runtime.connection.DB.Stats().MaxOpenConnections; got != DefaultRuntimeMaxOpenConns {
		t.Fatalf("unexpected max open connections: %d", got)
	}
	if got := atomic.LoadInt32(&pingCount); got != 1 {
		t.Fatalf("unexpected ping count: %d", got)
	}
}

func TestInitializeRuntimeConnectionLoadsPersistedStateWhenDatabaseURLEmpty(t *testing.T) {
	const wantDSN = "user:pass@tcp(localhost:3306)/persisted?parseTime=true"

	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return "" })
	manager.runtimeStatePath = filepath.Join(t.TempDir(), ".mcp", "db.json")

	if err := os.MkdirAll(filepath.Dir(manager.runtimeStatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(manager.runtimeStatePath, []byte("{\n  \"database_url\": \""+wantDSN+"\"\n}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var pingCount int32
	manager.openDB = func(driverName, dsn string) (*sql.DB, error) {
		if driverName != DriverMySQL {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		if dsn != wantDSN {
			t.Fatalf("unexpected dsn: %s", dsn)
		}
		return newPingOnlyDB(nil, &pingCount, nil), nil
	}
	t.Cleanup(func() { closeManagerConnections(manager) })

	out, err := manager.InitializeRuntimeConnection(context.Background(), "", "", false)
	if err != nil {
		t.Fatalf("InitializeRuntimeConnection returned error: %v", err)
	}
	if out.Data.Source != initializeDBSourcePersistedFile {
		t.Fatalf("unexpected source: %s", out.Data.Source)
	}
	if manager.runtime == nil {
		t.Fatal("expected runtime state to be installed")
	}
	if manager.runtime.databaseURL != wantDSN {
		t.Fatalf("unexpected runtime database_url: %s", manager.runtime.databaseURL)
	}
	if manager.runtime.dbType != DriverMySQL {
		t.Fatalf("unexpected runtime db_type: %s", manager.runtime.dbType)
	}
	if manager.runtime.isReadOnly {
		t.Fatal("expected runtime isReadOnly to default to false")
	}
	if got := atomic.LoadInt32(&pingCount); got != 1 {
		t.Fatalf("unexpected ping count: %d", got)
	}
}

func TestExecuteSQLUsesRuntimeConnectionWhenConnectionEmpty(t *testing.T) {
	now := time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC)
	var used bool

	manager := &Manager{
		conns: make(map[string]*Connection),
		now:   func() time.Time { return now },
		runtime: &runtimeConnectionState{
			connection: &Connection{
				Name:   runtimeConnectionName,
				Driver: DriverMySQL,
				executor: fakeExecutor{query: func(ctx context.Context, sql string, args ...any) (*QueryResult, error) {
					used = true
					return &QueryResult{
						Columns:  []ResultColumn{{Name: "value", Type: "bigint"}},
						Rows:     [][]any{{1}},
						RowCount: 1,
					}, nil
				}},
			},
			databaseURL: "runtime-dsn",
			expiresAt:   now.Add(time.Minute),
		},
	}

	out, err := manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{SQL: "SELECT 1"})
	if err != nil {
		t.Fatalf("ExecuteSQL returned error: %v", err)
	}
	if !used {
		t.Fatal("expected runtime executor to be used")
	}
	if out.Data.RowCount != 1 {
		t.Fatalf("unexpected row count: %d", out.Data.RowCount)
	}
}

func TestGetConnectionRefreshesRuntimeLease(t *testing.T) {
	now := time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC)

	manager := &Manager{
		conns: make(map[string]*Connection),
		now:   func() time.Time { return now },
		runtime: &runtimeConnectionState{
			connection:  &Connection{Name: runtimeConnectionName, Driver: DriverMySQL, executor: fakeExecutor{}},
			databaseURL: "runtime-dsn",
			expiresAt:   now.Add(5 * time.Minute),
		},
	}

	conn, err := manager.GetConnection(context.Background(), "")
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}
	if conn != manager.runtime.connection {
		t.Fatal("expected runtime connection to be returned")
	}
	if !manager.runtime.expiresAt.Equal(now.Add(DefaultRuntimeLeaseDuration)) {
		t.Fatalf("unexpected lease expiry: %s", manager.runtime.expiresAt)
	}
}

func TestGetConnectionReloadsExpiredRuntimeStateFromFile(t *testing.T) {
	const persistedDSN = "user:pass@tcp(localhost:3306)/rehydrated?parseTime=true"

	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return "" })
	manager.runtimeStatePath = filepath.Join(t.TempDir(), ".mcp", "db.json")

	raw, err := json.Marshal(runtimeStateFile{DatabaseURL: persistedDSN, DBType: DriverMySQL, IsReadOnly: true})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(manager.runtimeStatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(manager.runtimeStatePath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	now := time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	var oldCloseCount int32
	oldDB := newPingOnlyDB(nil, nil, &oldCloseCount)
	if err := oldDB.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}

	manager.runtime = &runtimeConnectionState{
		connection:  &Connection{Name: runtimeConnectionName, Driver: DriverMySQL, DB: oldDB, executor: fakeExecutor{}},
		databaseURL: "old-runtime-dsn",
		expiresAt:   now.Add(-time.Second),
	}

	var pingCount int32
	manager.openDB = func(driverName, dsn string) (*sql.DB, error) {
		if driverName != DriverMySQL {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		assertMySQLReadOnlyDSN(t, dsn, persistedDSN)
		return newPingOnlyDB(nil, &pingCount, nil), nil
	}
	t.Cleanup(func() { closeManagerConnections(manager) })

	conn, err := manager.GetConnection(context.Background(), "")
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}
	if conn == nil || conn.DB == nil {
		t.Fatal("expected rehydrated runtime sql.DB")
	}
	if manager.runtime == nil {
		t.Fatal("expected runtime state to be installed")
	}
	if manager.runtime.databaseURL != persistedDSN {
		t.Fatalf("unexpected runtime database_url: %s", manager.runtime.databaseURL)
	}
	if manager.runtime.dbType != DriverMySQL {
		t.Fatalf("unexpected runtime db_type: %s", manager.runtime.dbType)
	}
	if !manager.runtime.isReadOnly {
		t.Fatal("expected runtime isReadOnly to be true")
	}
	if !manager.runtime.expiresAt.Equal(now.Add(DefaultRuntimeLeaseDuration)) {
		t.Fatalf("unexpected lease expiry: %s", manager.runtime.expiresAt)
	}
	if got := atomic.LoadInt32(&oldCloseCount); got != 1 {
		t.Fatalf("unexpected closed connection count: %d", got)
	}
	if got := atomic.LoadInt32(&pingCount); got != 1 {
		t.Fatalf("unexpected ping count: %d", got)
	}
}

func TestGetConnectionColdStartSerializesRuntimeLoad(t *testing.T) {
	const persistedDSN = "user:pass@tcp(localhost:3306)/coldstart?parseTime=true"

	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string { return "" })
	manager.runtimeStatePath = filepath.Join(t.TempDir(), ".mcp", "db.json")

	raw, err := json.Marshal(runtimeStateFile{DatabaseURL: persistedDSN, DBType: DriverMySQL, IsReadOnly: false})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(manager.runtimeStatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(manager.runtimeStatePath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var openCalls int32
	openStarted := make(chan struct{})
	releaseOpen := make(chan struct{})
	var releaseOpenClosed int32
	closeReleaseOpen := func() {
		if atomic.CompareAndSwapInt32(&releaseOpenClosed, 0, 1) {
			close(releaseOpen)
		}
	}
	manager.openDB = func(driverName, dsn string) (*sql.DB, error) {
		if driverName != DriverMySQL {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		if dsn != persistedDSN {
			t.Fatalf("unexpected dsn: %s", dsn)
		}
		if atomic.AddInt32(&openCalls, 1) == 1 {
			close(openStarted)
			<-releaseOpen
		}
		return newPingOnlyDB(nil, nil, nil), nil
	}
	t.Cleanup(func() {
		closeReleaseOpen()
		closeManagerConnections(manager)
	})

	manager.runtimeInitMu.Lock()

	type result struct {
		conn *Connection
		err  error
	}

	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			conn, err := manager.GetConnection(context.Background(), "")
			results <- result{conn: conn, err: err}
		}()
	}

	close(start)
	manager.runtimeInitMu.Unlock()

	<-openStarted
	closeReleaseOpen()

	first := <-results
	second := <-results
	if first.err != nil {
		t.Fatalf("first GetConnection returned error: %v", first.err)
	}
	if second.err != nil {
		t.Fatalf("second GetConnection returned error: %v", second.err)
	}
	if got := atomic.LoadInt32(&openCalls); got != 1 {
		t.Fatalf("unexpected open call count: %d", got)
	}
	if first.conn == nil || second.conn == nil {
		t.Fatal("expected both goroutines to receive a runtime connection")
	}
	if first.conn != second.conn {
		t.Fatal("expected both goroutines to receive the same installed runtime connection")
	}
	if manager.runtime == nil || manager.runtime.connection == nil {
		t.Fatal("expected manager runtime connection to be installed")
	}
	if first.conn != manager.runtime.connection {
		t.Fatal("expected returned connection to match installed runtime connection")
	}
}

func TestGetConnectionUsesNamedEnvConnectionWhenProvided(t *testing.T) {
	manager := NewManagerFromEnv(DefaultConnectionsEnvVar, func(string) string {
		return `{"analytics":{"dsn":"user:pass@tcp(localhost:3306)/analytics?parseTime=true"}}`
	})

	var opened bool
	manager.openDB = func(driverName, dsn string) (*sql.DB, error) {
		if driverName != DriverMySQL {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		if dsn != "user:pass@tcp(localhost:3306)/analytics?parseTime=true" {
			t.Fatalf("unexpected dsn: %s", dsn)
		}
		opened = true
		return newPingOnlyDB(nil, nil, nil), nil
	}
	t.Cleanup(func() { closeManagerConnections(manager) })

	conn, err := manager.GetConnection(context.Background(), "analytics")
	if err != nil {
		t.Fatalf("GetConnection returned error: %v", err)
	}
	if !opened {
		t.Fatal("expected env-backed connection to be opened")
	}
	if conn.Name != "analytics" {
		t.Fatalf("unexpected connection name: %s", conn.Name)
	}
	if conn.Driver != DriverMySQL {
		t.Fatalf("unexpected connection driver: %s", conn.Driver)
	}
}

func assertMySQLReadOnlyDSN(t *testing.T, gotDSN string, wantBaseDSN string) {
	t.Helper()

	parsed, err := mysqldriver.ParseDSN(gotDSN)
	if err != nil {
		t.Fatalf("ParseDSN returned error: %v", err)
	}
	baseParsed, err := mysqldriver.ParseDSN(wantBaseDSN)
	if err != nil {
		t.Fatalf("ParseDSN base returned error: %v", err)
	}
	if parsed.FormatDSN() == baseParsed.FormatDSN() {
		t.Fatalf("expected readonly dsn to differ from base dsn: %s", gotDSN)
	}
	if parsed.Params["transaction_read_only"] != "1" {
		t.Fatalf("expected transaction_read_only=1, got %q", parsed.Params["transaction_read_only"])
	}
	if baseParsed.Params["parseTime"] == "true" && parsed.Params["parseTime"] != "true" {
		t.Fatalf("expected parseTime=true to be preserved, got %q", parsed.Params["parseTime"])
	}
}

func closeManagerConnections(manager *Manager) {
	if manager == nil {
		return
	}
	if manager.runtime != nil && manager.runtime.connection != nil && manager.runtime.connection.DB != nil {
		_ = manager.runtime.connection.DB.Close()
	}
	for _, conn := range manager.conns {
		if conn != nil && conn.DB != nil {
			_ = conn.DB.Close()
		}
	}
}

func newPingOnlyDB(pingErr error, pingCount *int32, closeCount *int32) *sql.DB {
	return sql.OpenDB(pingOnlyConnector{
		pingErr:    pingErr,
		pingCount:  pingCount,
		closeCount: closeCount,
	})
}

type pingOnlyConnector struct {
	pingErr    error
	pingCount  *int32
	closeCount *int32
}

func (c pingOnlyConnector) Connect(context.Context) (driver.Conn, error) {
	return &pingOnlyConn{
		pingErr:    c.pingErr,
		pingCount:  c.pingCount,
		closeCount: c.closeCount,
	}, nil
}

func (c pingOnlyConnector) Driver() driver.Driver {
	return pingOnlyDriver{}
}

type pingOnlyDriver struct{}

func (pingOnlyDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("not implemented")
}

type pingOnlyConn struct {
	pingErr    error
	pingCount  *int32
	closeCount *int32
}

func (c *pingOnlyConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *pingOnlyConn) Close() error {
	if c.closeCount != nil {
		atomic.AddInt32(c.closeCount, 1)
	}
	return nil
}

func (c *pingOnlyConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (c *pingOnlyConn) Ping(context.Context) error {
	if c.pingCount != nil {
		atomic.AddInt32(c.pingCount, 1)
	}
	return c.pingErr
}
