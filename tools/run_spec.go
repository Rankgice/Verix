package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/engine"
)

type RunSpecOutput struct {
	Summary     engine.Summary         `json:"summary"`
	FailedCases []engine.FailedCase    `json:"failed_cases"`
	CaseResults []engine.CaseExecution `json:"case_results"`
}

func RegisterRunSpec(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_testspec",
		Description: "Run TestSpec v1 cases for HTTP/gRPC and return unified diff report.",
	}, runSpecHandler)
}

func runSpecHandler(ctx context.Context, req *mcp.CallToolRequest, in SpecInput) (*mcp.CallToolResult, RunSpecOutput, error) {
	_ = req
	spec, err := loadSpec(in)
	if err != nil {
		return nil, RunSpecOutput{}, err
	}

	report, err := engine.RunSpec(ctx, spec)
	if err != nil {
		return nil, RunSpecOutput{}, err
	}

	out := RunSpecOutput{
		Summary:     report.Summary,
		FailedCases: report.FailedCases,
		CaseResults: report.CaseResults,
	}

	text := fmt.Sprintf(
		"run finished: total=%d passed=%d failed=%d duration_ms=%d",
		report.Summary.Total, report.Summary.Passed, report.Summary.Failed, report.Summary.DurationMS,
	)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
	return result, out, nil
}
