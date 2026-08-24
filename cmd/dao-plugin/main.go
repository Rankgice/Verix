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
	DSN         string   `json:"dsn"`
	Tables      []string `json:"tables"`
	PackageName string   `json:"package_name"`
	Mode        string   `json:"mode"`
	OutputDir   string   `json:"output_dir"`
}

// ListTablesInput 是 list_tables 方法的输入参数。
type ListTablesInput struct {
	DSN string `json:"dsn"`
}

// GenerateFile 是 code 模式返回的单个源码文件。
type GenerateFile struct {
	Table   string `json:"table"`
	Entity  string `json:"entity"`
	Package string `json:"package"`
	Code    string `json:"code"`
}

// GeneratedFileInfo 是 file 模式返回的文件信息，不包含源码。
type GeneratedFileInfo struct {
	Table       string `json:"table"`
	Entity      string `json:"entity"`
	Package     string `json:"package"`
	Path        string `json:"path"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Created     bool   `json:"created"`
	Overwritten bool   `json:"overwritten"`
}

func main() {
	_ = plugin.Run(context.Background(), plugin.Options{
		ID: "com.verix.dao", Name: "dao", Version: "1.1.0", Description: "根据数据库表结构生成符合 Go GORM Model Standards 的 DAO 层代码",
		Manifest: []protocol.Method{
			{Name: "generate", Description: "根据 DSN 和表名生成 GORM model 代码，支持返回 code 或直接写入 output_dir", Flags: protocol.MethodFlags{ReadOnly: false, Idempotent: true, SupportsCancellation: true}},
			{Name: "list_tables", Description: "列出当前数据库的所有表", Flags: protocol.MethodFlags{ReadOnly: true, Idempotent: true}},
		},
		Methods: map[string]plugin.Handler{"generate": generateHandler, "list_tables": listTablesHandler},
	})
}

// generateHandler 先完成全部渲染，再按 mode 返回源码或写入 output_dir。
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
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = "code"
	}
	if mode != "code" && mode != "file" {
		return nil, fmt.Errorf("unsupported mode %q: want code or file", in.Mode)
	}
	packageName := in.PackageName
	if packageName == "" {
		packageName = "model"
	}
	var outputDir string
	if mode == "file" {
		var err error
		outputDir, err = resolveOutputDir(in.OutputDir)
		if err != nil {
			return nil, err
		}
	}

	db, err := connect(ctx, in.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()
	type rendered struct{ table, entity, packageName, code string }
	renderedFiles := make([]rendered, 0, len(in.Tables))
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
		renderedFiles = append(renderedFiles, rendered{table: table, entity: m.EntityName, packageName: packageName, code: code})
	}

	if mode == "code" {
		files := make([]GenerateFile, 0, len(renderedFiles))
		for _, f := range renderedFiles {
			files = append(files, GenerateFile{Table: f.table, Entity: f.entity, Package: f.packageName, Code: f.code})
		}
		return map[string]any{"files": files}, nil
	}
	files := make([]GeneratedFileInfo, 0, len(renderedFiles))
	for _, f := range renderedFiles {
		info, err := writeGeneratedFile(outputDir, f.table, f.entity, f.packageName, f.code)
		if err != nil {
			return map[string]any{"files": files}, fmt.Errorf("write table %q: %w", f.table, err)
		}
		files = append(files, info)
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
