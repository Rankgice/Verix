package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

type AnalyzeQueryInput struct {
	SQL string `json:"sql" jsonschema:"SQL statement to analyze without executing"`
}

type AnalyzeQueryOutput = db.AnalyzeQueryResult

func RegisterAnalyzeQuery(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_query",
		Description: "Analyze SQL safety, operation type, and referenced tables without executing it.",
	}, analyzeQueryHandler)
}

func analyzeQueryHandler(ctx context.Context, req *mcp.CallToolRequest, in AnalyzeQueryInput) (*mcp.CallToolResult, AnalyzeQueryOutput, error) {
	_ = ctx
	_ = req

	out, err := db.AnalyzeQuery(in.SQL)
	if err != nil {
		return nil, AnalyzeQueryOutput{}, err
	}

	return nil, *out, nil
}
