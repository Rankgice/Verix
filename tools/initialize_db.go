package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type InitializeDBInput struct {
	DatabaseURL string `json:"database_url,omitempty" jsonschema:"Optional MySQL connection string (DSN). Leave empty to reuse the persisted .mcp/db.json runtime state."`
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

	out, err := defaultDBManager.InitializeRuntimeConnection(ctx, in.DatabaseURL)
	if err != nil {
		return nil, InitializeDBOutput{}, err
	}

	return nil, *out, nil
}
