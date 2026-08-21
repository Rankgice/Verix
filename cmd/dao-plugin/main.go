package main

import (
	"context"
	"fmt"
	"strings"

	"verix/sdk/plugin"
	"verix/sdk/protocol"
)

// GenerateInput 是 generate 方法的输入参数。
type GenerateInput struct {
	DSN         string   `json:"dsn"`          // MySQL 连接串，含用户名密码，如 root:pass@tcp(127.0.0.1:3306)/db?parseTime=true
	Tables      []string `json:"tables"`       // 要生成 model 的表名列表
	PackageName string   `json:"package_name"` // 可选，生成的包名，默认 model
}

// ListTablesInput 是 list_tables 方法的输入参数。
type ListTablesInput struct {
	DSN string `json:"dsn"` // MySQL 连接串
}

// GenerateFile 是 generate 返回的单个文件。
type GenerateFile struct {
	Table   string `json:"table"`
	Entity  string `json:"entity"`
	Package string `json:"package"`
	Code    string `json:"code"`
}

func main() {
	_ = plugin.Run(context.Background(), plugin.Options{
		ID:          "com.verix.dao",
		Name:        "dao",
		Version:     "1.0.0",
		Description: "根据数据库表结构生成符合 Go GORM Model Standards 的 DAO 层代码",
		Manifest: []protocol.Method{
			{Name: "generate", Description: "根据 DSN 和表名生成 GORM model 代码", Flags: protocol.MethodFlags{ReadOnly: true, Idempotent: true, SupportsCancellation: true}},
			{Name: "list_tables", Description: "列出当前数据库的所有表", Flags: protocol.MethodFlags{ReadOnly: true, Idempotent: true}},
		},
		Methods: map[string]plugin.Handler{
			"generate":    generateHandler,
			"list_tables": listTablesHandler,
		},
	})
}

// generateHandler 处理 generate 方法：连库、读表结构、渲染 model 代码。
func generateHandler(ctx context.Context, call *plugin.Call) (any, error) {
	var in GenerateInput
	if err := call.DecodeInput(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.DSN) == "" {
		return nil, fmt.Errorf("dsn is required")
	}
	if len(in.Tables) == 0 {
		return nil, fmt.Errorf("tables is required")
	}
	packageName := in.PackageName
	if packageName == "" {
		packageName = "model"
	}

	db, err := connect(ctx, in.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()

	files := make([]GenerateFile, 0, len(in.Tables))
	for _, table := range in.Tables {
		columns, err := readTableColumns(ctx, db, table)
		if err != nil {
			return nil, fmt.Errorf("read table %q: %w", table, err)
		}
		m := buildTableModel(packageName, table, columns)
		code, err := renderModel(m)
		if err != nil {
			return nil, fmt.Errorf("render table %q: %w", table, err)
		}
		files = append(files, GenerateFile{
			Table:   table,
			Entity:  m.EntityName,
			Package: packageName,
			Code:    code,
		})
	}

	return map[string]any{"files": files}, nil
}

// listTablesHandler 处理 list_tables 方法：连库并列出所有表。
func listTablesHandler(ctx context.Context, call *plugin.Call) (any, error) {
	var in ListTablesInput
	if err := call.DecodeInput(&in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.DSN) == "" {
		return nil, fmt.Errorf("dsn is required")
	}

	db, err := connect(ctx, in.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()

	tables, err := listTables(ctx, db)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tables": tables}, nil
}
