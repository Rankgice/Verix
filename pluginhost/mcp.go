package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type PluginListInput struct{}
type PluginDescribeInput struct {
	Plugin string `json:"plugin" jsonschema:"Plugin ID or name"`
}
type PluginCallInput struct {
	Plugin    string         `json:"plugin" jsonschema:"Plugin ID or name"`
	Method    string         `json:"method" jsonschema:"Plugin method name"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Method arguments as a JSON object"`
	TimeoutMS int            `json:"timeout_ms,omitempty" jsonschema:"Optional call timeout in milliseconds"`
}

type PluginListOutput struct {
	Plugins []PluginSummary `json:"plugins"`
}
type PluginDescribeOutput struct {
	Plugin *json.RawMessage `json:"plugin"`
}
type PluginCallOutput struct {
	Plugin string          `json:"plugin"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result,omitempty"`
	Meta   map[string]any  `json:"meta,omitempty"`
}

// RegisterMCPTools 将插件管理能力注册为 MCP Tools。
func (m *Manager) RegisterMCPTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_list", Description: "List installed Verix plugins and their current status."}, m.listHandler)
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_describe", Description: "Describe the methods and schemas exposed by a plugin."}, m.describeHandler)
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_call", Description: "Call a method exposed by a Verix plugin."}, m.callHandler)
}

// listHandler 处理 plugin_list MCP Tool 请求。
func (m *Manager) listHandler(ctx context.Context, _ *mcp.CallToolRequest, _ PluginListInput) (*mcp.CallToolResult, PluginListOutput, error) {
	return nil, PluginListOutput{Plugins: m.List(ctx)}, nil
}

// describeHandler 处理 plugin_describe MCP Tool 请求。
func (m *Manager) describeHandler(ctx context.Context, _ *mcp.CallToolRequest, in PluginDescribeInput) (*mcp.CallToolResult, PluginDescribeOutput, error) {
	if in.Plugin == "" {
		return nil, PluginDescribeOutput{}, fmt.Errorf("plugin is required")
	}
	out, err := m.Describe(ctx, in.Plugin)
	if err != nil {
		return nil, PluginDescribeOutput{}, err
	}
	raw, _ := json.Marshal(out)
	rawMessage := json.RawMessage(raw)
	return nil, PluginDescribeOutput{Plugin: &rawMessage}, nil
}

// callHandler 处理 plugin_call MCP Tool 请求并转发到目标插件。
func (m *Manager) callHandler(ctx context.Context, _ *mcp.CallToolRequest, in PluginCallInput) (*mcp.CallToolResult, PluginCallOutput, error) {
	if in.Plugin == "" || in.Method == "" {
		return nil, PluginCallOutput{}, fmt.Errorf("plugin and method are required")
	}
	timeout := time.Duration(in.TimeoutMS) * time.Millisecond
	result, err := m.Invoke(ctx, in.Plugin, in.Method, in.Arguments, timeout)
	if err != nil {
		return nil, PluginCallOutput{}, err
	}
	return nil, PluginCallOutput{Plugin: in.Plugin, Method: in.Method, Result: result, Meta: map[string]any{"duration_ms": 0}}, nil
}
