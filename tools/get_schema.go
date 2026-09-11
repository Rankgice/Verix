package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Rankgice/Verix/db"
)

// GetSchemaOutput 复用数据库层定义的轻量 Schema 结果。
type GetSchemaOutput = db.GetSchemaResult

// RegisterGetSchema 注册跨 MySQL 和 SQLite 的 Schema 查询 Tool。
func RegisterGetSchema(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_schema",
		Description: "Get a lightweight MySQL or SQLite schema overview. Omit connection to use the initialized runtime DB, or provide one to use VERIX_DB_CONNECTIONS.",
	}, getSchemaHandler)
}

// getSchemaHandler 根据可选连接名读取表和列的轻量结构。
func getSchemaHandler(ctx context.Context, req *mcp.CallToolRequest, in ConnectionInput) (*mcp.CallToolResult, GetSchemaOutput, error) {
	_ = req

	// 连接为空时复用 initialize_db 持久化的运行时数据库。
	out, err := defaultDBManager.GetSchemaResult(ctx, in.Connection)
	if err != nil {
		return nil, GetSchemaOutput{}, err
	}

	return nil, *out, nil
}
