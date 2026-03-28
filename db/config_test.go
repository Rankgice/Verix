package db

import (
	"strings"
	"testing"
)

func TestParseConnectionConfigsDefaultsDriverToMySQL(t *testing.T) {
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

func TestParseConnectionConfigsRejectsInvalidEntries(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantError string
	}{
		{name: "unsupported driver", raw: `{"analytics":{"driver":"sqlite","dsn":"file:test.db"}}`, wantError: "unsupported driver"},
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
