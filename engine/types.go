package engine

import "encoding/json"

// TestSpec 是 TestSpec v1 文档的顶层结构，包含元信息、变量以及待执行的测试用例。
type TestSpec struct {
	// Meta 保存测试名称、协议默认值和超时配置。
	Meta Meta `json:"meta"`
	// Vars 保存可在请求、断言和提取规则中引用的运行时变量。
	Vars map[string]any `json:"vars"`
	// Cases 按声明顺序保存所有待执行的测试用例。
	Cases []Case `json:"cases"`
}

// Meta 描述测试规格的基本信息和全局运行配置。
type Meta struct {
	// Name 是测试规格的可读名称。
	Name string `json:"name"`
	// ProtocolDefaults 保存 HTTP 和 gRPC 的协议级默认配置。
	ProtocolDefaults ProtocolDefaults `json:"protocol_defaults"`
	// TimeoutMS 是单个测试用例的超时时间，未设置时由引擎默认填充为 5000 毫秒。
	TimeoutMS int `json:"timeout_ms"`
}

// ProtocolDefaults 保存不同协议执行器共享的默认连接配置。
type ProtocolDefaults struct {
	// HTTP 是 HTTP 默认配置；为 nil 表示没有配置 HTTP 默认值。
	HTTP *HTTPDefaults `json:"http,omitempty"`
	// GRPC 是 gRPC 默认配置；为 nil 表示没有配置 gRPC 默认值。
	GRPC *GRPCDefaults `json:"grpc,omitempty"`
}

// HTTPDefaults 描述 HTTP 请求使用的基础 URL 和默认请求头。
type HTTPDefaults struct {
	// BaseURL 用于拼接请求中的相对路径。
	BaseURL string `json:"base_url"`
	// Headers 是会合并到每个 HTTP 请求中的默认请求头。
	Headers map[string]string `json:"headers"`
}

// GRPCDefaults 描述 grpcurl 连接目标、传输模式和默认元数据。
type GRPCDefaults struct {
	// Target 是 gRPC 服务地址，例如 127.0.0.1:50051。
	Target string `json:"target"`
	// Plaintext 表示是否使用明文 gRPC 连接。
	Plaintext bool `json:"plaintext"`
	// Metadata 是会合并到每个 gRPC 请求中的默认元数据。
	Metadata map[string]string `json:"metadata"`
}

// Case 描述一个独立的 HTTP 或 gRPC 测试用例。
type Case struct {
	// ID 是用例的稳定标识，必须在同一规格内唯一。
	ID string `json:"id"`
	// Name 是用例的可读名称。
	Name string `json:"name"`
	// Protocol 指定用例使用的协议类型。
	Protocol Protocol `json:"protocol"`
	// Request 保存协议相关的原始 JSON 请求内容。
	Request json.RawMessage `json:"request"`
	// Expect 保存对响应状态、头、代码和正文的断言规则。
	Expect Expect `json:"expect"`
	// Extract 定义从响应正文提取变量的路径映射。
	Extract map[string]string `json:"extract"`
}

// Protocol 标识测试用例的执行协议。
type Protocol struct {
	// Type 当前支持 http 和 grpc。
	Type string `json:"type"`
}

// HTTPRequest 描述一个 HTTP 请求的可配置部分。
type HTTPRequest struct {
	// Method 是 HTTP 方法，空值时执行器默认使用 GET。
	Method string `json:"method"`
	// Path 是请求路径，也可以是完整的绝对 URL。
	Path string `json:"path"`
	// Headers 是用例级请求头，会覆盖同名的默认请求头。
	Headers map[string]any `json:"headers"`
	// Query 是 URL 查询参数。
	Query map[string]any `json:"query"`
	// Body 是请求正文，发送前会进行变量替换并编码为 JSON。
	Body any `json:"body"`
}

// GRPCRequest 描述一个 gRPC 方法调用。
type GRPCRequest struct {
	// Service 是 protobuf 服务的完整名称。
	Service string `json:"service"`
	// Method 是要调用的方法名称。
	Method string `json:"method"`
	// Metadata 是用例级 gRPC 元数据，会覆盖同名默认元数据。
	Metadata map[string]any `json:"metadata"`
	// Message 是发送给 gRPC 方法的 JSON 消息。
	Message any `json:"message"`
}

// Expect 保存统一的响应断言规则。
type Expect struct {
	// Success 预留用于表达请求是否成功的断言条件；当前运行器未单独执行该字段。
	Success *bool `json:"success,omitempty"`
	// Status 是 HTTP 状态码断言。
	Status *int `json:"status,omitempty"`
	// GRPCCode 是 gRPC 状态码断言。
	GRPCCode string `json:"grpc_code,omitempty"`
	// Headers 是响应头或 gRPC 初始元数据断言。
	Headers map[string]any `json:"headers,omitempty"`
	// Body 按路径保存响应正文断言规则。
	Body map[string]BodyRule `json:"body,omitempty"`
}

// BodyRule 描述一个响应正文路径上的断言条件。
type BodyRule struct {
	// Type 断言实际值的 JSON 类型。
	Type string `json:"type,omitempty"`
	// Equals 断言实际值与期望值相等。
	Equals any `json:"equals,omitempty"`
	// NotEmpty 断言实际值不是空字符串、空数组或空对象。
	NotEmpty bool `json:"not_empty,omitempty"`
	// Exists 断言字段是否存在。
	Exists *bool `json:"exists,omitempty"`
	// Matches 使用正则表达式断言字符串值。
	Matches string `json:"matches,omitempty"`
	// MinItems 断言数组至少包含指定数量的元素。
	MinItems *int `json:"min_items,omitempty"`
}

// RunReport 是一次规格执行的汇总结果。
type RunReport struct {
	// Summary 保存总数、通过数、失败数和总耗时。
	Summary Summary `json:"summary"`
	// FailedCases 保存未通过断言或发生运行时错误的用例。
	FailedCases []FailedCase `json:"failed_cases"`
	// CaseResults 保存每个用例的完整执行结果。
	CaseResults []CaseExecution `json:"case_results"`
}

// Summary 保存一次运行的统计信息。
type Summary struct {
	// Total 是用例总数。
	Total int `json:"total"`
	// Passed 是通过的用例数。
	Passed int `json:"passed"`
	// Failed 是失败的用例数。
	Failed int `json:"failed"`
	// DurationMS 是整次运行耗时，单位为毫秒。
	DurationMS int64 `json:"duration_ms"`
}

// CaseExecution 保存单个用例的请求结果和断言结果。
type CaseExecution struct {
	// ID 是用例标识。
	ID string `json:"id"`
	// Protocol 是实际使用的协议类型。
	Protocol string `json:"protocol"`
	// Endpoint 是实际访问的 HTTP URL 或 gRPC 方法地址。
	Endpoint string `json:"endpoint"`
	// DurationMS 是用例耗时，单位为毫秒。
	DurationMS int64 `json:"duration_ms"`
	// Status 是 HTTP 响应状态码。
	Status *int `json:"status,omitempty"`
	// GRPCCode 是 gRPC 响应状态码。
	GRPCCode *string `json:"grpc_code,omitempty"`
	// ResponseHeaders 是扁平化后的响应头或 gRPC 初始元数据。
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	// ResponseBody 是解析后的响应正文。
	ResponseBody any `json:"response_body,omitempty"`
	// Error 是执行阶段产生的错误信息。
	Error string `json:"error,omitempty"`
	// Assertions 保存每条断言的通过状态和说明。
	Assertions []AssertionResult `json:"assertions"`
}

// AssertionResult 表示一条断言的执行结果。
type AssertionResult struct {
	// Path 是断言针对的响应路径。
	Path string `json:"path"`
	// Rule 是断言规则的简要描述。
	Rule string `json:"rule"`
	// Passed 表示断言是否通过。
	Passed bool `json:"passed"`
	// Message 是面向使用者的断言说明。
	Message string `json:"message"`
}

// FailedCase 保存失败用例的期望值、实际值、差异和诊断建议。
type FailedCase struct {
	// ID 是失败用例标识。
	ID string `json:"id"`
	// Protocol 是失败用例使用的协议。
	Protocol string `json:"protocol"`
	// Endpoint 是失败用例实际访问的端点。
	Endpoint string `json:"endpoint"`
	// Expected 是规范化后的期望结果。
	Expected map[string]any `json:"expected"`
	// Actual 是规范化后的实际结果。
	Actual map[string]any `json:"actual"`
	// Diff 是机器可读的差异列表。
	Diff []Diff `json:"diff"`
	// Diagnosis 是去重后的人工诊断提示。
	Diagnosis []string `json:"diagnosis"`
}

// Diff 描述一项期望结果与实际结果之间的差异。
type Diff struct {
	// Type 是稳定的差异类型，例如 status_mismatch 或 missing_field。
	Type string `json:"type"`
	// Path 是发生差异的响应路径。
	Path string `json:"path,omitempty"`
	// Expected 是期望值。
	Expected any `json:"expected,omitempty"`
	// Actual 是实际值。
	Actual any `json:"actual,omitempty"`
}
