package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

// ExecuteSQLInput 描述安全 SQL 执行所需的连接、参数、限制和只读选项。
type ExecuteSQLInput struct {
	// Connection 对应 VERIX_DB_CONNECTIONS 的键；留空时使用运行时连接。
	Connection string `json:"connection,omitempty" jsonschema:"Optional database connection name from VERIX_DB_CONNECTIONS. Omit to use the initialized runtime DB."`
	// SQL 是单条待分析和执行的 SQL，不允许多语句输入。
	SQL string `json:"sql" jsonschema:"SQL statement to execute"`
	// Params 为 :name 占位符提供绑定值，切片值可用于 IN 条件。
	Params map[string]any `json:"params,omitempty" jsonschema:"Named SQL parameters keyed by placeholder name"`
	// Limit 控制缺少 LIMIT 的 SELECT 最大返回行数。
	Limit int `json:"limit,omitempty" jsonschema:"Maximum SELECT rows when LIMIT is missing; defaults to 100"`
	// TimeoutMS 控制本次数据库执行的超时时间。
	TimeoutMS int `json:"timeout_ms,omitempty" jsonschema:"Execution timeout in milliseconds; defaults to 2000"`
	// ReadOnly 留空时默认为 true，只有显式 false 才允许安全校验通过的写语句。
	ReadOnly *bool `json:"readonly,omitempty" jsonschema:"When true, only SELECT statements are allowed; defaults to true"`
}

// ExecuteSQLOutput 复用数据库层定义的统一 SQL 执行结果。
type ExecuteSQLOutput = db.ExecuteSQLResult

// RegisterExecuteSQL 注册支持 MySQL 和 SQLite 的安全 SQL 执行 Tool。
func RegisterExecuteSQL(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "execute_sql",
		Description: "Execute SQL safely against MySQL or SQLite. Omit connection to use the initialized runtime DB, or provide one to use VERIX_DB_CONNECTIONS.",
	}, executeSQLHandler)
}

// executeSQLHandler 将 MCP 输入转换为数据库层请求，并返回统一执行结果。
func executeSQLHandler(ctx context.Context, req *mcp.CallToolRequest, in ExecuteSQLInput) (*mcp.CallToolResult, ExecuteSQLOutput, error) {
	_ = req

	// Manager 统一完成 SQL 风险分析、命名参数绑定、超时和结果截断。
	out, err := defaultDBManager.ExecuteSQL(ctx, db.ExecuteSQLRequest{
		Connection: in.Connection,
		SQL:        in.SQL,
		Params:     in.Params,
		Limit:      in.Limit,
		TimeoutMS:  in.TimeoutMS,
		ReadOnly:   in.ReadOnly,
	})
	if err != nil {
		return nil, ExecuteSQLOutput{}, err
	}

	return nil, *out, nil
}
