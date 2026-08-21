package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type InitializeTestSpecInput struct {
	Overwrite bool `json:"overwrite,omitempty" jsonschema:"When true, overwrite existing .mcp/global.json, .mcp/example.json, and .mcp/example-grpc.json files."`
}

type InitializeTestSpecOutput struct {
	Success bool                   `json:"success"`
	Data    InitializeTestSpecData `json:"data"`
}

type InitializeTestSpecData struct {
	Directory       string        `json:"directory"`
	GlobalFile      WorkspaceFile `json:"global_file"`
	ExampleFile     WorkspaceFile `json:"example_file"`
	GRPCExampleFile WorkspaceFile `json:"grpc_example_file"`
}

type WorkspaceFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

func RegisterInitializeTestSpec(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "initialize_testspec",
		Description: "Initialize .mcp/global.json plus HTTP/gRPC example TestSpec files for workspace bootstrapping.",
	}, initializeTestSpecHandler)
}

func initializeTestSpecHandler(ctx context.Context, req *mcp.CallToolRequest, in InitializeTestSpecInput) (*mcp.CallToolResult, InitializeTestSpecOutput, error) {
	_ = ctx
	_ = req

	out, err := initializeTestSpecWorkspace("", in.Overwrite)
	if err != nil {
		return nil, InitializeTestSpecOutput{}, err
	}

	return nil, InitializeTestSpecOutput{
		Success: true,
		Data:    *out,
	}, nil
}
