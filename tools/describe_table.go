package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type DescribeTableInput struct {
	Connection string `json:"connection" jsonschema:"Database connection name from VERIX_DB_CONNECTIONS"`
	Table      string `json:"table" jsonschema:"Table name to describe"`
}

type DescribeTableOutput = db.DescribeTableResult

func RegisterDescribeTable(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "describe_table",
		Description: "Describe a table including columns, indexes, and foreign keys.",
	}, describeTableHandler)
}

func describeTableHandler(ctx context.Context, req *mcp.CallToolRequest, in DescribeTableInput) (*mcp.CallToolResult, DescribeTableOutput, error) {
	_ = req

	out, err := defaultDBManager.DescribeTableResult(ctx, in.Connection, in.Table)
	if err != nil {
		return nil, DescribeTableOutput{}, err
	}

	return nil, *out, nil
}
