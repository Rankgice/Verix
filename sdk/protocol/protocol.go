package protocol

import "encoding/json"

const (
	JSONRPCVersion  = "2.0"
	ProtocolVersion = "1.0"
)

// Request 表示一个 JSON-RPC 请求或通知消息。
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response 表示一个 JSON-RPC 响应消息。
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error 表示 JSON-RPC 或插件业务调用错误。
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603

	PluginNotFound       = -32001
	PluginNotReady       = -32002
	PluginStartFailed    = -32003
	PluginExited         = -32004
	PluginTimeout        = -32005
	PluginCancelled      = -32006
	PermissionDenied     = -32007
	ProtocolIncompatible = -32008
)

// InitializeParams 是主程序发送给插件的初始化参数。
type InitializeParams struct {
	ProtocolVersion string    `json:"protocol_version"`
	Host            HostInfo  `json:"host"`
	Plugin          PluginRef `json:"plugin"`
}

type HostInfo struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type PluginRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// InitializeResult 是插件返回的初始化结果。
type InitializeResult struct {
	ProtocolVersion string         `json:"protocol_version"`
	PluginID        string         `json:"plugin_id"`
	PluginVersion   string         `json:"plugin_version"`
	Capabilities    PluginFeatures `json:"capabilities,omitempty"`
}

type PluginFeatures struct {
	Cancellation    bool `json:"cancellation"`
	ConcurrentCalls bool `json:"concurrent_calls"`
}

// Manifest 是插件目录中的 plugin.json 对应的静态描述。
type Manifest struct {
	ManifestVersion string       `json:"manifest_version"`
	ProtocolVersion string       `json:"protocol_version"`
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	DisplayName     string       `json:"display_name,omitempty"`
	Version         string       `json:"version"`
	Description     string       `json:"description,omitempty"`
	Runtime         Runtime      `json:"runtime"`
	Permissions     []Permission `json:"permissions,omitempty"`
	Methods         []Method     `json:"methods,omitempty"`
	Config          *ConfigSpec  `json:"config,omitempty"`
}

// Runtime 描述插件进程的启动、超时、并发和重启参数。
type Runtime struct {
	Command            string   `json:"command"`
	Args               []string `json:"args,omitempty"`
	Activation         string   `json:"activation,omitempty"`
	StartupTimeoutMS   int      `json:"startup_timeout_ms,omitempty"`
	CallTimeoutMS      int      `json:"call_timeout_ms,omitempty"`
	ShutdownTimeoutMS  int      `json:"shutdown_timeout_ms,omitempty"`
	MaxConcurrentCalls int      `json:"max_concurrent_calls,omitempty"`
	RestartPolicy      string   `json:"restart_policy,omitempty"`
	MaxRestarts        int      `json:"max_restarts,omitempty"`
}

// Permission 描述插件申请使用的 Host API 权限。
type Permission struct {
	Name      string         `json:"name"`
	Reason    string         `json:"reason,omitempty"`
	Resources []string       `json:"resources,omitempty"`
	Config    map[string]any `json:"config,omitempty"`
}

// Method 描述插件提供的一个业务方法及其 Schema。
type Method struct {
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	InputSchema  map[string]any `json:"input_schema,omitempty"`
	OutputSchema map[string]any `json:"output_schema,omitempty"`
	Flags        MethodFlags    `json:"flags,omitempty"`
}

type MethodFlags struct {
	ReadOnly             bool `json:"read_only,omitempty"`
	Idempotent           bool `json:"idempotent,omitempty"`
	SupportsCancellation bool `json:"supports_cancellation,omitempty"`
}

type ConfigSpec struct {
	Schema map[string]any `json:"schema,omitempty"`
}

// DescribeResult 是插件运行时返回的完整能力描述。
type DescribeResult struct {
	PluginID    string   `json:"plugin_id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Methods     []Method `json:"methods"`
}

// InvokeParams 是主程序调用插件业务方法时发送的参数。
type InvokeParams struct {
	CallID    string          `json:"call_id"`
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Context   CallContext     `json:"context,omitempty"`
}

type CallContext struct {
	TraceID  string `json:"trace_id,omitempty"`
	Deadline string `json:"deadline,omitempty"`
}

// InvokeResult 是插件业务方法返回的结果包装。
type InvokeResult struct {
	CallID string          `json:"call_id"`
	Output json.RawMessage `json:"output,omitempty"`
	Meta   map[string]any  `json:"meta,omitempty"`
}

type CancelParams struct {
	CallID string `json:"call_id"`
}
type ShutdownParams struct {
	Reason string `json:"reason,omitempty"`
}
type PingResult struct {
	Status string `json:"status"`
}

// HostLogParams 是插件调用 host.log 时发送的日志参数。
type HostLogParams struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// ConfigGetParams 是插件读取主程序配置时的请求参数。
type ConfigGetParams struct {
	Key string `json:"key"`
}

// ConfigGetResult 是主程序返回的配置值。
type ConfigGetResult struct {
	Value json.RawMessage `json:"value,omitempty"`
}

// StorageParams 是插件读写专属 Storage 时的请求参数。
type StorageParams struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value,omitempty"`
}

// StorageResult 是主程序返回的 Storage 数据。
type StorageResult struct {
	Value json.RawMessage `json:"value,omitempty"`
}
