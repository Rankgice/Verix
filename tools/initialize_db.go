package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Rankgice/Verix/db"
)

// InitializeDBInput 描述运行时数据库的 DSN、类型和只读模式。
type InitializeDBInput struct {
	// DatabaseURL 对 MySQL 使用原生 DSN，对 SQLite 使用文件路径、:memory: 或 file: URI；留空则恢复状态文件。
	DatabaseURL string `json:"database_url,omitempty" jsonschema:"Optional database DSN: use a MySQL DSN or a SQLite file path/file: URI. Leave empty to reuse the persisted .mcp/db.json runtime state."`
	// DBType 支持 mysql 和 sqlite，留空保持兼容并默认使用 mysql。
	DBType string `json:"db_type,omitempty" jsonschema:"Database type: mysql or sqlite. Defaults to mysql."`
	// IsReadOnly 为 true 时在驱动连接层启用只读模式。
	IsReadOnly bool `json:"is_readonly,omitempty" jsonschema:"Open the runtime database in driver-level read-only mode: MySQL transaction_read_only=1 or SQLite mode=ro."`
}

// InitializeDBOutput 复用数据库层定义的初始化结果。
type InitializeDBOutput = db.InitializeDBResult

// RegisterInitializeDB 注册支持 MySQL 和 SQLite 的运行时数据库初始化 Tool。
func RegisterInitializeDB(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "initialize_db",
		Description: "Initialize a runtime MySQL or SQLite connection using database_url, or reuse the persisted .mcp/db.json state.",
	}, initializeDBHandler)
}

// initializeDBHandler 将 MCP 输入转交给共享 Manager，并返回可持久化的初始化结果。
func initializeDBHandler(ctx context.Context, req *mcp.CallToolRequest, in InitializeDBInput) (*mcp.CallToolResult, InitializeDBOutput, error) {
	_ = req

	// database_url 为空时，Manager 会从 .mcp/db.json 恢复上一次运行时连接。
	out, err := defaultDBManager.InitializeRuntimeConnection(ctx, in.DatabaseURL, in.DBType, in.IsReadOnly)
	if err != nil {
		return nil, InitializeDBOutput{}, err
	}

	return nil, *out, nil
}
