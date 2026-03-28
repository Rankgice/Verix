package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type GetSchemaOutput = db.GetSchemaResult

func RegisterGetSchema(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_schema",
		Description: "Get a lightweight schema overview for a named MySQL connection.",
	}, getSchemaHandler)
}

func getSchemaHandler(ctx context.Context, req *mcp.CallToolRequest, in ConnectionInput) (*mcp.CallToolResult, GetSchemaOutput, error) {
	_ = req

	out, err := defaultDBManager.GetSchemaResult(ctx, in.Connection)
	if err != nil {
		return nil, GetSchemaOutput{}, err
	}

	return nil, *out, nil
}
