package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type ExecuteSQLInput struct {
	Connection string         `json:"connection" jsonschema:"Database connection name from VERIX_DB_CONNECTIONS"`
	SQL        string         `json:"sql" jsonschema:"SQL statement to execute"`
	Params     map[string]any `json:"params,omitempty" jsonschema:"Named SQL parameters keyed by placeholder name"`
	Limit      int            `json:"limit,omitempty" jsonschema:"Maximum SELECT rows when LIMIT is missing; defaults to 100"`
	TimeoutMS  int            `json:"timeout_ms,omitempty" jsonschema:"Execution timeout in milliseconds; defaults to 2000"`
	ReadOnly   *bool          `json:"readonly,omitempty" jsonschema:"When true, only SELECT statements are allowed; defaults to true"`
}

type ExecuteSQLOutput = db.ExecuteSQLResult

func RegisterExecuteSQL(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "execute_sql",
		Description: "Execute SQL safely against a named MySQL connection.",
	}, executeSQLHandler)
}

func executeSQLHandler(ctx context.Context, req *mcp.CallToolRequest, in ExecuteSQLInput) (*mcp.CallToolResult, ExecuteSQLOutput, error) {
	_ = req

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
