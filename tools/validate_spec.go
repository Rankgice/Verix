package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/engine"
)

type ValidateSpecOutput struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

func RegisterValidateSpec(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "validate_testspec",
		Description: "Validate TestSpec v1 schema and required fields.",
	}, validateSpecHandler)
}

func validateSpecHandler(ctx context.Context, req *mcp.CallToolRequest, in SpecInput) (*mcp.CallToolResult, ValidateSpecOutput, error) {
	_ = ctx
	_ = req

	spec, err := loadSpec(in)
	if err != nil {
		return nil, ValidateSpecOutput{}, err
	}
	errs := engine.ValidateSpec(spec)
	out := ValidateSpecOutput{
		Valid:  len(errs) == 0,
		Errors: errs,
	}

	text := "spec is valid"
	if !out.Valid {
		text = fmt.Sprintf("spec invalid: %d error(s)", len(out.Errors))
	}
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
	return result, out, nil
}
