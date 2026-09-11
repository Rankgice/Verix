package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Rankgice/Verix/sdk/plugin"
	"github.com/Rankgice/Verix/sdk/protocol"
)

// GenerateInput 描述代码生成使用的数据库、表、包名和输出方式。
type GenerateInput struct {
	// DBType 支持 mysql 和 sqlite，空值默认使用 mysql。
	DBType string `json:"db_type"`
	// DSN 是对应数据库驱动的连接串或 SQLite 文件路径。
	DSN string `json:"dsn"`
	// Tables 是需要生成代码的表名列表。
	Tables []string `json:"tables"`
	// PackageName 是生成代码的 Go 包名，空值默认 model。
	PackageName string `json:"package_name"`
	// Mode 支持 code 和 file，空值默认 code。
	Mode string `json:"mode"`
	// OutputDir 是 file 模式的代码输出目录。
	OutputDir string `json:"output_dir"`
}

// ListTablesInput 描述列举代码生成候选表时使用的数据库连接。
type ListTablesInput struct {
	// DBType 支持 mysql 和 sqlite，空值默认使用 mysql。
	DBType string `json:"db_type"`
	// DSN 是对应数据库驱动的连接串或 SQLite 文件路径。
	DSN string `json:"dsn"`
}

// GenerateFile 是 code 模式返回的单表源码。
type GenerateFile struct {
	// Table 是来源表名。
	Table string `json:"table"`
	// Entity 是生成的 Go 实体名。
	Entity string `json:"entity"`
	// Package 是生成代码的包名。
	Package string `json:"package"`
	// Code 是格式化后的 Go 源码。
	Code string `json:"code"`
}

// GeneratedFileInfo 是 file 模式返回的落盘文件信息。
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

var daoGenerateInputSchema = map[string]any{"type": "object", "properties": map[string]any{
	"db_type":      map[string]any{"type": "string", "enum": []string{databaseTypeMySQL, databaseTypeSQLite}, "description": "数据库类型：mysql 或 sqlite，默认 mysql"},
	"dsn":          map[string]any{"type": "string", "description": "数据库连接串；MySQL 使用原生 DSN，SQLite 使用文件路径、:memory: 或 file: URI"},
	"tables":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "要生成的表名列表"},
	"package_name": map[string]any{"type": "string", "description": "Go 包名，默认 model"},
	"mode":         map[string]any{"type": "string", "enum": []string{"code", "file"}, "description": "code 返回源码；file 写入 output_dir 并只返回文件信息，默认 code"},
	"output_dir":   map[string]any{"type": "string", "description": "file 模式必填，输出目录；每张表生成 <output_dir>/<table>.go，已有文件会覆盖"},
}, "required": []string{"dsn", "tables"}, "additionalProperties": false}
var daoGenerateOutputSchema = map[string]any{"type": "object", "properties": map[string]any{
	"files": map[string]any{"type": "array", "items": map[string]any{
		"type": "object", "properties": map[string]any{
			"table":       map[string]any{"type": "string"},
			"entity":      map[string]any{"type": "string"},
			"package":     map[string]any{"type": "string"},
			"code":        map[string]any{"type": "string"},
			"path":        map[string]any{"type": "string"},
			"bytes":       map[string]any{"type": "integer"},
			"sha256":      map[string]any{"type": "string"},
			"created":     map[string]any{"type": "boolean"},
			"overwritten": map[string]any{"type": "boolean"},
		}, "required": []string{"table", "entity", "package"}, "additionalProperties": false,
	}},
}, "required": []string{"files"}, "additionalProperties": false}
var daoListInputSchema = map[string]any{"type": "object", "properties": map[string]any{
	"db_type": map[string]any{"type": "string", "enum": []string{databaseTypeMySQL, databaseTypeSQLite}, "description": "数据库类型：mysql 或 sqlite，默认 mysql"},
	"dsn":     map[string]any{"type": "string", "description": "数据库连接串；MySQL 使用原生 DSN，SQLite 使用文件路径、:memory: 或 file: URI"},
}, "required": []string{"dsn"}, "additionalProperties": false}
var daoListOutputSchema = map[string]any{"type": "object", "properties": map[string]any{"tables": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"tables"}, "additionalProperties": false}

// main 启动 DAO 插件，并在运行时描述中提供完整输入输出 Schema。
func main() {
	_ = plugin.Run(context.Background(), plugin.Options{
		ID: "com.verix.dao", Name: "dao", Version: "1.2.0", Description: "根据 MySQL 或 SQLite 表结构生成符合 Go GORM Model Standards 的 DAO 层代码",
		Manifest: []protocol.Method{
			{Name: "generate", Description: "根据 MySQL 或 SQLite DSN 和表名生成 GORM model；code 模式返回源码，file 模式写入 output_dir", InputSchema: daoGenerateInputSchema, OutputSchema: daoGenerateOutputSchema, Flags: protocol.MethodFlags{ReadOnly: false, Idempotent: true, SupportsCancellation: true}},
			{Name: "list_tables", Description: "通过 GORM 连接 MySQL 或 SQLite 并列出当前数据库的所有表", InputSchema: daoListInputSchema, OutputSchema: daoListOutputSchema, Flags: protocol.MethodFlags{ReadOnly: true, Idempotent: true}},
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
	// 数据库差异封装在 GORM Dialector 和 Migrator 中，生成流程无需包含方言判断。
	database, err := connect(ctx, in.DBType, in.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	defer closeDatabase(database)
	type rendered struct{ table, entity, packageName, code string }
	renderedFiles := make([]rendered, 0, len(in.Tables))
	for _, table := range in.Tables {
		columns, err := readTableColumns(ctx, database, table)
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
	// list_tables 与 generate 共用连接和 GORM Migrator，确保支持的数据库类型一致。
	database, err := connect(ctx, in.DBType, in.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	defer closeDatabase(database)
	tables, err := listTables(ctx, database)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tables": tables}, nil
}
