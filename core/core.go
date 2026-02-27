package core

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/tools"
)

func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "verix",
		Version: "v1.0.0",
	}, nil)

	tools.RegisterValidateSpec(server)
	tools.RegisterRunSpec(server)
	return server
}
