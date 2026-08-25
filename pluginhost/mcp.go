package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/sdk/protocol"
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
	Plugin *protocol.DescribeResult `json:"plugin"`
}
type PluginCallOutput struct {
	Plugin string         `json:"plugin"`
	Method string         `json:"method"`
	Result map[string]any `json:"result,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

// RegisterMCPTools 将插件管理能力注册为 MCP Tools。
func (m *Manager) RegisterMCPTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_list", Description: "List installed Verix plugins and their current status."}, m.listHandler)
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_describe", Description: "Describe plugin methods. Read each method's input_schema, output_schema, required fields, field descriptions, and flags before calling plugin_call."}, m.describeHandler)
	mcp.AddTool(server, &mcp.Tool{Name: "plugin_call", Description: "Call a plugin method using the exact arguments defined by plugin_describe. Call plugin_describe first when the method schema is not already known."}, m.callHandler)
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
	return nil, PluginDescribeOutput{Plugin: out}, nil
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
	var resultAny map[string]any
	if len(result) > 0 {
		_ = json.Unmarshal(result, &resultAny)
	}
	return nil, PluginCallOutput{Plugin: in.Plugin, Method: in.Method, Result: resultAny, Meta: map[string]any{"duration_ms": 0}}, nil
}
