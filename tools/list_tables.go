package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Rankgice/Verix/db"
)

// ConnectionInput 指定可选命名连接；留空时使用 initialize_db 初始化的运行时连接。
type ConnectionInput struct {
	// Connection 对应 VERIX_DB_CONNECTIONS 的键；留空时使用运行时连接。
	Connection string `json:"connection,omitempty" jsonschema:"Optional database connection name from VERIX_DB_CONNECTIONS. Omit to use the initialized runtime DB."`
}

// ListTablesOutput 复用数据库层定义的表列表结果。
type ListTablesOutput = db.ListTablesResult

// RegisterListTables 注册跨 MySQL 和 SQLite 的表列表 Tool。
func RegisterListTables(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tables",
		Description: "List tables for MySQL or SQLite. Omit connection to use the initialized runtime DB, or provide one to use VERIX_DB_CONNECTIONS.",
	}, listTablesHandler)
}

// listTablesHandler 解析连接选择并返回当前数据库中的业务表。
func listTablesHandler(ctx context.Context, req *mcp.CallToolRequest, in ConnectionInput) (*mcp.CallToolResult, ListTablesOutput, error) {
	_ = req

	// Manager 会依据连接配置自动选择 MySQL 或 SQLite 元数据实现。
	out, err := defaultDBManager.ListTables(ctx, in.Connection)
	if err != nil {
		return nil, ListTablesOutput{}, err
	}

	return nil, *out, nil
}
