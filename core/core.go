package core

import (
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/pluginhost"
	"verix/resources"
	"verix/tools"
)

// NewServer 创建并组装 Verix MCP Server，同时注册现有能力和插件管理能力。
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

	pluginManager := pluginhost.New(pluginhost.Options{
		RootDir: os.Getenv("VERIX_PLUGIN_DIR"),
		Logger:  func(level, message string, fields map[string]any) {},
	})
	_ = pluginManager.Discover()
	pluginManager.RegisterMCPTools(server)
	return server
}
