package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type ConnectionInput struct {
	Connection string `json:"connection" jsonschema:"Database connection name from VERIX_DB_CONNECTIONS"`
}

type ListTablesOutput = db.ListTablesResult

func RegisterListTables(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tables",
		Description: "List tables for a named MySQL connection.",
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
