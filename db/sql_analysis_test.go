package db

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

type fakeExecutor struct {
	query func(ctx context.Context, sql string, args ...any) (*QueryResult, error)
	exec  func(ctx context.Context, sql string, args ...any) (*ExecResult, error)
}

func (f fakeExecutor) Query(ctx context.Context, sql string, args ...any) (*QueryResult, error) {
	if f.query == nil {
		return nil, nil
	}
	return f.query(ctx, sql, args...)
}

func (f fakeExecutor) Exec(ctx context.Context, sql string, args ...any) (*ExecResult, error) {
	if f.exec == nil {
		return nil, nil
	}
	return f.exec(ctx, sql, args...)
}

func (fakeExecutor) GetSchema(ctx context.Context) (*Schema, error) {
	return &Schema{}, nil
}

func (fakeExecutor) DescribeTable(ctx context.Context, table string) (*TableSchema, error) {
	return &TableSchema{Table: table}, nil
}

func TestAnalyzeSQLSelectMissingLimit(t *testing.T) {
	analysis, err := AnalyzeSQL("SELECT u.id, o.id FROM users u JOIN orders o ON o.user_id = u.id")
	if err != nil {
		t.Fatalf("AnalyzeSQL returned error: %v", err)
	}

	if analysis.Operation != "SELECT" {
		t.Fatalf("unexpected operation: %s", analysis.Operation)
	}
	if analysis.RiskLevel != "low" {
		t.Fatalf("unexpected risk level: %s", analysis.RiskLevel)
	}
	if analysis.HasLimit {
		t.Fatal("expected LIMIT to be absent")
	}
	if !reflect.DeepEqual(analysis.Tables, []string{"users", "orders"}) {
		t.Fatalf("unexpected tables: %#v", analysis.Tables)
	}
	if len(analysis.Warnings) != 1 || analysis.Warnings[0] != "No LIMIT clause" {
		t.Fatalf("unexpected warnings: %#v", analysis.Warnings)
	}
}

func TestAnalyzeSQLWithCTEFindsMainOperation(t *testing.T) {
	analysis, err := AnalyzeSQL(`WITH recent AS (SELECT * FROM orders LIMIT 5) SELECT * FROM recent`)
	if err != nil {
		t.Fatalf("AnalyzeSQL returned error: %v", err)
	}

	if analysis.Operation != "SELECT" {
		t.Fatalf("unexpected operation: %s", analysis.Operation)
	}
	if analysis.HasLimit {
		t.Fatal("expected top-level LIMIT to be absent")
	}
	if len(analysis.Warnings) == 0 || analysis.Warnings[0] != "No LIMIT clause" {
		t.Fatalf("unexpected warnings: %#v", analysis.Warnings)
	}
}

func TestValidateExecutionRejectsDangerousStatements(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		readOnly  bool
		wantError string
	}{
		{name: "drop", sql: "DROP TABLE users", readOnly: false, wantError: "DROP"},
		{name: "truncate", sql: "TRUNCATE TABLE users", readOnly: false, wantError: "TRUNCATE"},
		{name: "delete without where", sql: "DELETE FROM users", readOnly: false, wantError: "DELETE without WHERE"},
		{name: "update without where", sql: "UPDATE users SET name = 'x'", readOnly: false, wantError: "UPDATE without WHERE"},
		{name: "multiple statements", sql: "SELECT * FROM users; DELETE FROM users WHERE id = 1", readOnly: false, wantError: "multiple SQL statements"},
		{name: "readonly insert", sql: "INSERT INTO users(name) VALUES ('alice')", readOnly: true, wantError: "readonly mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeSQL(tt.sql)
			if err != nil {
				t.Fatalf("AnalyzeSQL returned error: %v", err)
			}
			err = ValidateExecution(analysis, tt.readOnly)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("unexpected error %q, want substring %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestAnalyzeSQLFlagsMultipleStatements(t *testing.T) {
	analysis, err := AnalyzeSQL("SELECT * FROM users; DELETE FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("AnalyzeSQL returned error: %v", err)
	}
	if !analysis.HasMultipleStatements {
		t.Fatal("expected multiple statements to be detected")
	}
	if analysis.RiskLevel != "high" {
		t.Fatalf("unexpected risk level: %s", analysis.RiskLevel)
	}
	if !reflect.DeepEqual(analysis.Tables, []string{"users"}) {
		t.Fatalf("unexpected tables: %#v", analysis.Tables)
	}
	if !containsString(analysis.Warnings, "Multiple SQL statements are not allowed") {
		t.Fatalf("unexpected warnings: %#v", analysis.Warnings)
	}
}

func TestRewriteSelectLimitAppendsBeforeSemicolon(t *testing.T) {
	rewritten, truncated, err := RewriteSelectLimit("SELECT * FROM users;   ", 25)
	if err != nil {
		t.Fatalf("RewriteSelectLimit returned error: %v", err)
	}
	if !truncated {
		t.Fatal("expected query to be rewritten")
	}
	if rewritten != "SELECT * FROM users LIMIT 25;   " {
		t.Fatalf("unexpected rewritten SQL: %q", rewritten)
	}
}

func TestRewriteSelectLimitLeavesExistingLimit(t *testing.T) {
	original := "SELECT * FROM users LIMIT 10"
	rewritten, truncated, err := RewriteSelectLimit(original, 25)
	if err != nil {
		t.Fatalf("RewriteSelectLimit returned error: %v", err)
	}
	if truncated {
		t.Fatal("did not expect rewrite when LIMIT already exists")
	}
	if rewritten != original {
		t.Fatalf("unexpected rewritten SQL: %q", rewritten)
	}
}

func TestBindNamedParamsReplacesPlaceholdersOutsideStringsAndComments(t *testing.T) {
	sqlText := "SELECT * FROM users WHERE id = :id AND note = ':ignored' -- :comment\nAND status IN (:statuses)"
	rewritten, args, err := BindNamedParams(sqlText, map[string]any{
		"id":       7,
		"statuses": []string{"active", "pending"},
	})
	if err != nil {
		t.Fatalf("BindNamedParams returned error: %v", err)
	}

	wantSQL := "SELECT * FROM users WHERE id = ? AND note = ':ignored' -- :comment\nAND status IN (?, ?)"
	if rewritten != wantSQL {
		t.Fatalf("unexpected SQL rewrite: %q", rewritten)
	}
	if !reflect.DeepEqual(args, []any{7, "active", "pending"}) {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestBindNamedParamsReturnsErrorForMissingValue(t *testing.T) {
	_, _, err := BindNamedParams("SELECT * FROM users WHERE id = :id", map[string]any{})
	if err == nil {
		t.Fatal("expected missing parameter error")
	}
	if !strings.Contains(err.Error(), `"id"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBindNamedParamsRejectsEmptySlices(t *testing.T) {
	_, _, err := BindNamedParams("SELECT * FROM users WHERE id IN (:ids)", map[string]any{"ids": []int{}})
	if err == nil {
		t.Fatal("expected empty slice error")
	}
	if !strings.Contains(err.Error(), "empty slice") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteSQLMarksTruncatedOnlyWhenRowsWereActuallyClipped(t *testing.T) {
	var capturedSQL string
	manager := &Manager{
		conns: map[string]*Connection{
			"primary": {
				Name:   "primary",
				Driver: DriverMySQL,
				executor: fakeExecutor{query: func(ctx context.Context, sql string, args ...any) (*QueryResult, error) {
					capturedSQL = sql
					return &QueryResult{
						Columns:  []ResultColumn{{Name: "id", Type: "bigint"}},
						Rows:     [][]any{{1}, {2}, {3}},
						RowCount: 3,
					}, nil
				}},
			},
		},
		loaded: true,
	}

	out, err := manager.ExecuteSQL(context.Background(), ExecuteSQLRequest{
		Connection: "primary",
		SQL:        "SELECT id FROM users",
		Limit:      2,
	})
	if err != nil {
		t.Fatalf("ExecuteSQL returned error: %v", err)
	}
	if capturedSQL != "SELECT id FROM users LIMIT 3" {
		t.Fatalf("unexpected executed SQL: %q", capturedSQL)
	}
	if !out.Meta.Truncated {
		t.Fatal("expected truncated to be true when result rows exceed requested limit")
	}
	if out.Data.RowCount != 2 {
		t.Fatalf("unexpected row count: %d", out.Data.RowCount)
	}
	if !reflect.DeepEqual(out.Data.Rows, [][]any{{1}, {2}}) {
		t.Fatalf("unexpected rows: %#v", out.Data.Rows)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
