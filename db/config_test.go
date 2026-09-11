package db

import (
	"strings"
	"testing"
)

// TestParseConnectionConfigsDefaultsDriverToMySQL 验证未声明驱动时保持兼容并默认使用 MySQL。
func TestParseConnectionConfigsDefaultsDriverToMySQL(t *testing.T) {
	// 输入只提供 DSN，用于覆盖默认驱动分支。
	configs, err := parseConnectionConfigs("VERIX_DB_CONNECTIONS", `{"analytics":{"dsn":"user:pass@tcp(localhost:3306)/app?parseTime=true"}}`)
	if err != nil {
		t.Fatalf("parseConnectionConfigs returned error: %v", err)
	}

	cfg, ok := configs["analytics"]
	if !ok {
		t.Fatal("expected analytics config to be present")
	}
	if cfg.Driver != DriverMySQL {
		t.Fatalf("unexpected driver: %s", cfg.Driver)
	}
	if cfg.DSN == "" {
		t.Fatal("expected DSN to be populated")
	}
}

// TestParseConnectionConfigsRejectsInvalidEntries 验证非法驱动、缺少 DSN 和无效 JSON 都会被拒绝。
func TestParseConnectionConfigsRejectsInvalidEntries(t *testing.T) {
	// 表驱动用例确保每类配置错误都返回可定位的消息。
	tests := []struct {
		name      string
		raw       string
		wantError string
	}{
		{name: "unsupported driver", raw: `{"analytics":{"driver":"postgres","dsn":"postgres://localhost/app"}}`, wantError: "unsupported driver"},
		{name: "missing dsn", raw: `{"analytics":{"driver":"mysql"}}`, wantError: "missing dsn"},
		{name: "invalid json", raw: `{`, wantError: "parse VERIX_DB_CONNECTIONS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConnectionConfigs("VERIX_DB_CONNECTIONS", tt.raw)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("unexpected error %q, want substring %q", err.Error(), tt.wantError)
			}
		})
	}
}

// TestParseConnectionConfigsAcceptsSQLite 验证命名连接能够显式配置 SQLite 驱动和文件 DSN。
func TestParseConnectionConfigsAcceptsSQLite(t *testing.T) {
	configs, err := parseConnectionConfigs("VERIX_DB_CONNECTIONS", `{"local":{"driver":"sqlite","dsn":"file:local.db"}}`)
	if err != nil {
		t.Fatalf("parseConnectionConfigs returned error: %v", err)
	}

	cfg := configs["local"]
	if cfg.Driver != DriverSQLite {
		t.Fatalf("unexpected driver: %s", cfg.Driver)
	}
	if cfg.DSN != "file:local.db" {
		t.Fatalf("unexpected dsn: %s", cfg.DSN)
	}
}

// TestRuntimeReadOnlyDSNSQLite 验证 SQLite 只读模式会保留原参数并覆盖 mode=ro。
func TestRuntimeReadOnlyDSNSQLite(t *testing.T) {
	dsn, err := runtimeReadOnlyDSN("file:local.db?cache=shared&mode=rw", DriverSQLite)
	if err != nil {
		t.Fatalf("runtimeReadOnlyDSN returned error: %v", err)
	}
	if dsn != "file:local.db?cache=shared&mode=ro" {
		t.Fatalf("unexpected readonly dsn: %s", dsn)
	}
}

// TestRuntimeReadOnlyDSNRejectsSQLiteMemory 验证内存 SQLite 不会被错误地初始化为只读连接。
func TestRuntimeReadOnlyDSNRejectsSQLiteMemory(t *testing.T) {
	_, err := runtimeReadOnlyDSN(":memory:", DriverSQLite)
	if err == nil || !strings.Contains(err.Error(), "in-memory sqlite") {
		t.Fatalf("unexpected error: %v", err)
	}
}
