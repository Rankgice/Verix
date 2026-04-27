package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type InitializeDBInput struct {
	DatabaseURL string `json:"database_url,omitempty" jsonschema:"Optional MySQL connection string (DSN). Leave empty to reuse the persisted .mcp/db.json runtime state."`
	DBType      string `json:"db_type,omitempty" jsonschema:"Database type for the runtime state. Defaults to mysql; currently only mysql is supported."`
	IsReadOnly  bool   `json:"is_readonly,omitempty" jsonschema:"When true, the runtime MySQL connection is opened in read-only mode by appending transaction_read_only=1 to the DSN during connection setup."`
}

type InitializeDBOutput = db.InitializeDBResult

func RegisterInitializeDB(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "initialize_db",
		Description: "Initialize the runtime MySQL connection using database_url or the persisted .mcp/db.json state.",
	}, initializeDBHandler)
}

func initializeDBHandler(ctx context.Context, req *mcp.CallToolRequest, in InitializeDBInput) (*mcp.CallToolResult, InitializeDBOutput, error) {
	_ = req

	out, err := defaultDBManager.InitializeRuntimeConnection(ctx, in.DatabaseURL, in.DBType, in.IsReadOnly)
	if err != nil {
		return nil, InitializeDBOutput{}, err
	}

	return nil, *out, nil
}
