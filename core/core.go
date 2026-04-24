package core

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/resources"
	"verix/tools"
)

func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "verix",
		Version: "v1.0.0",
	}, nil)

	tools.RegisterValidateSpec(server)
	tools.RegisterRunSpec(server)
	tools.RegisterInitializeDB(server)
	tools.RegisterExecuteSQL(server)
	tools.RegisterListTables(server)
	tools.RegisterGetSchema(server)
	tools.RegisterDescribeTable(server)
	tools.RegisterAnalyzeQuery(server)
	resources.Register(server)
	return server
}
