package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Rankgice/Verix/db"
)

// DescribeTableInput 指定数据库连接和需要描述的表。
type DescribeTableInput struct {
	// Connection 对应 VERIX_DB_CONNECTIONS 的键；留空时使用运行时连接。
	Connection string `json:"connection,omitempty" jsonschema:"Optional database connection name from VERIX_DB_CONNECTIONS. Omit to use the initialized runtime DB."`
	// Table 是当前数据库中需要读取详细元数据的表名。
	Table string `json:"table" jsonschema:"Table name to describe"`
}

// DescribeTableOutput 复用数据库层定义的详细表结构结果。
type DescribeTableOutput = db.DescribeTableResult

// RegisterDescribeTable 注册支持 MySQL 和 SQLite 元数据的表描述 Tool。
func RegisterDescribeTable(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "describe_table",
		Description: "Describe a table including columns, indexes, and foreign keys. Omit connection to use the initialized runtime DB, or provide one to use VERIX_DB_CONNECTIONS.",
	}, describeTableHandler)
}

// describeTableHandler 返回指定表的列、索引和外键结构。
func describeTableHandler(ctx context.Context, req *mcp.CallToolRequest, in DescribeTableInput) (*mcp.CallToolResult, DescribeTableOutput, error) {
	_ = req

	// 具体 Schema SQL 由连接对应的数据库执行器实现。
	out, err := defaultDBManager.DescribeTableResult(ctx, in.Connection, in.Table)
	if err != nil {
		return nil, DescribeTableOutput{}, err
	}

	return nil, *out, nil
}
