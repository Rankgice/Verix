package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type ConnectionInput struct {
	Connection string `json:"connection,omitempty" jsonschema:"Optional database connection name from VERIX_DB_CONNECTIONS. Omit to use the initialized runtime DB."`
}

type ListTablesOutput = db.ListTablesResult

func RegisterListTables(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tables",
		Description: "List tables for MySQL. Omit connection to use the initialized runtime DB, or provide one to use VERIX_DB_CONNECTIONS.",
	}, listTablesHandler)
}

func listTablesHandler(ctx context.Context, req *mcp.CallToolRequest, in ConnectionInput) (*mcp.CallToolResult, ListTablesOutput, error) {
	_ = req

	out, err := defaultDBManager.ListTables(ctx, in.Connection)
	if err != nil {
		return nil, ListTablesOutput{}, err
	}

	return nil, *out, nil
}
