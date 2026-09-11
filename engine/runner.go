package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// placeholderRe 匹配模板占位符；bracketIndexRe 规范化数组下标；grpcCodeRe 提取 grpcurl 错误码。
var (
	placeholderRe  = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)
	bracketIndexRe = regexp.MustCompile(`\[(\d+)\]`)
	grpcCodeRe     = regexp.MustCompile(`(?m)(?:code =|Code:\s*)([A-Za-z]+)`)
)

// execCommandContext 独立成变量，便于测试时注入模拟的 grpcurl 子进程。
var execCommandContext = exec.CommandContext

// ValidateSpec 校验测试规格的必填字段、协议类型和协议默认配置，并填充默认超时。
func ValidateSpec(spec *TestSpec) []string {
	if spec == nil {
		return []string{"spec is nil"}
	}
	// 收集所有校验错误，而不是遇到第一项错误就立即返回。
	var errs []string
	if strings.TrimSpace(spec.Meta.Name) == "" {
		errs = append(errs, "meta.name is required")
	}
	if spec.Meta.TimeoutMS <= 0 {
		spec.Meta.TimeoutMS = 5000
	}

	// 用集合检测用例 ID 是否重复。
	seenID := make(map[string]struct{}, len(spec.Cases))
	for i := range spec.Cases {
		c := spec.Cases[i]
		if strings.TrimSpace(c.ID) == "" {
			errs = append(errs, fmt.Sprintf("cases[%d].id is required", i))
		}
		if _, ok := seenID[c.ID]; ok {
			errs = append(errs, fmt.Sprintf("duplicate case id: %s", c.ID))
		}
		seenID[c.ID] = struct{}{}

		// 协议类型统一转为小写，保证配置大小写不影响校验。
		pt := strings.ToLower(strings.TrimSpace(c.Protocol.Type))
		if pt != "http" && pt != "grpc" {
			errs = append(errs, fmt.Sprintf("cases[%d].protocol.type must be http or grpc", i))
			continue
		}

		if len(c.Request) == 0 {
			errs = append(errs, fmt.Sprintf("cases[%d].request is required", i))
			continue
		}
		switch pt {
		case "http":
			var req HTTPRequest
			if err := json.Unmarshal(c.Request, &req); err != nil {
				errs = append(errs, fmt.Sprintf("cases[%d].request invalid http request: %v", i, err))
				continue
			}
			if strings.TrimSpace(req.Path) == "" {
				errs = append(errs, fmt.Sprintf("cases[%d].request.path is required", i))
			}
			if spec.Meta.ProtocolDefaults.HTTP == nil || strings.TrimSpace(spec.Meta.ProtocolDefaults.HTTP.BaseURL) == "" {
				if !(strings.HasPrefix(req.Path, "http://") || strings.HasPrefix(req.Path, "https://")) {
					errs = append(errs, fmt.Sprintf("cases[%d] missing meta.protocol_defaults.http.base_url", i))
				}
			}
		case "grpc":
			var req GRPCRequest
			if err := json.Unmarshal(c.Request, &req); err != nil {
				errs = append(errs, fmt.Sprintf("cases[%d].request invalid grpc request: %v", i, err))
				continue
			}
			if strings.TrimSpace(req.Service) == "" {
				errs = append(errs, fmt.Sprintf("cases[%d].request.service is required", i))
			}
			if strings.TrimSpace(req.Method) == "" {
				errs = append(errs, fmt.Sprintf("cases[%d].request.method is required", i))
			}
			if spec.Meta.ProtocolDefaults.GRPC == nil || strings.TrimSpace(spec.Meta.ProtocolDefaults.GRPC.Target) == "" {
				errs = append(errs, fmt.Sprintf("cases[%d] missing meta.protocol_defaults.grpc.target", i))
			}
		}
	}
	return errs
}

// RunSpec 按顺序执行规格中的所有用例，汇总执行结果、断言差异和诊断信息。
func RunSpec(ctx context.Context, spec *TestSpec) (*RunReport, error) {
	if spec == nil {
		return nil, errors.New("spec is nil")
	}

	// 先校验规格，避免执行阶段处理不完整的请求配置。
	validationErrors := ValidateSpec(spec)
	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("spec validation failed: %s", strings.Join(validationErrors, "; "))
	}

	if spec.Meta.TimeoutMS <= 0 {
		spec.Meta.TimeoutMS = 5000
	}
	if spec.Vars == nil {
		spec.Vars = map[string]any{}
	}

	// 初始化运行级计时器、结果容器和本次执行使用的变量副本。
	start := time.Now()
	results := make([]CaseExecution, 0, len(spec.Cases))
	failed := make([]FailedCase, 0)
	passedCount := 0
	vars := cloneMap(spec.Vars)

	// 用例按规格中的声明顺序串行执行，前一个用例提取的变量可供后续用例使用。
	for _, tc := range spec.Cases {
		caseStart := time.Now()
		protocol := strings.ToLower(tc.Protocol.Type)
		execResult := CaseExecution{
			ID:         tc.ID,
			Protocol:   protocol,
			Assertions: make([]AssertionResult, 0),
		}

		var (
			respStatus  *int
			respCode    *string
			respBody    any
			respHeaders map[string]string
			runErr      error
		)

		// 每个用例拥有独立的超时上下文，避免单个请求拖延整次运行。
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.Meta.TimeoutMS)*time.Millisecond)
		switch protocol {
		case "http":
			var req HTTPRequest
			if err := json.Unmarshal(tc.Request, &req); err != nil {
				runErr = fmt.Errorf("invalid http request: %w", err)
				break
			}
			// HTTP 执行器返回统一格式的状态、头、正文和端点信息。
			status, headers, body, endpoint, err := executeHTTP(timeoutCtx, spec, req, vars)
			execResult.Endpoint = endpoint
			if err != nil {
				runErr = err
			}
			respStatus = &status
			respBody = body
			respHeaders = headers
		case "grpc":
			var req GRPCRequest
			if err := json.Unmarshal(tc.Request, &req); err != nil {
				runErr = fmt.Errorf("invalid grpc request: %w", err)
				break
			}
			// gRPC 执行器将 grpcurl 的状态码和初始元数据转换为统一结果。
			code, headers, body, endpoint, err := executeGRPC(timeoutCtx, spec, req, vars)
			execResult.Endpoint = endpoint
			if err != nil {
				runErr = err
			}
			respCode = &code
			respHeaders = headers
			respBody = body
		default:
			runErr = fmt.Errorf("unsupported protocol %q", protocol)
		}
		cancel()

		execResult.Status = respStatus
		execResult.GRPCCode = respCode
		execResult.ResponseHeaders = respHeaders
		execResult.ResponseBody = respBody
		if runErr != nil {
			execResult.Error = runErr.Error()
		}

		// 无论请求是否成功，都执行断言以尽可能完整地报告差异。
		assertions, diffs := evaluateExpect(tc.Expect, protocol, respStatus, respCode, respHeaders, respBody)
		execResult.Assertions = append(execResult.Assertions, assertions...)
		execResult.DurationMS = time.Since(caseStart).Milliseconds()
		results = append(results, execResult)

		// 只有执行无错误且所有断言通过时，才应用变量提取并计为成功。
		if runErr == nil && len(diffs) == 0 {
			applyExtract(vars, tc.Extract, respBody)
			passedCount++
			continue
		}

		// 失败报告同时保留期望、实际、差异和面向使用者的诊断信息。
		failedCase := FailedCase{
			ID:       tc.ID,
			Protocol: protocol,
			Endpoint: execResult.Endpoint,
			Expected: expectedToMap(tc.Expect),
			Actual: map[string]any{
				"headers":   respHeaders,
				"status":    respStatus,
				"grpc_code": respCode,
				"body":      respBody,
				"error":     execResult.Error,
			},
			Diff:      diffs,
			Diagnosis: diagnose(runErr, diffs),
		}
		if runErr != nil {
			failedCase.Diff = append(failedCase.Diff, classifyRuntimeError(runErr)...)
		}
		failed = append(failed, failedCase)
	}

	return &RunReport{
		Summary: Summary{
			Total:      len(spec.Cases),
			Passed:     passedCount,
			Failed:     len(spec.Cases) - passedCount,
			DurationMS: time.Since(start).Milliseconds(),
		},
		FailedCases: failed,
		CaseResults: results,
	}, nil
}

// executeHTTP 构造并发送 HTTP 请求，返回状态码、响应头、响应正文和端点信息。
func executeHTTP(ctx context.Context, spec *TestSpec, in HTTPRequest, vars map[string]any) (int, map[string]string, any, string, error) {
	// 规范化方法名；未指定方法时使用 HTTP 默认的 GET。
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}

	// 先替换路径中的变量，再决定它是绝对 URL 还是相对路径。
	pathRaw := toString(substituteAny(in.Path, vars))
	pathRaw = strings.TrimSpace(pathRaw)
	baseURL := ""
	if spec.Meta.ProtocolDefaults.HTTP != nil {
		baseURL = toString(substituteAny(spec.Meta.ProtocolDefaults.HTTP.BaseURL, vars))
	}

	fullURL, err := joinURL(baseURL, pathRaw)
	if err != nil {
		return 0, nil, nil, method + " " + pathRaw, err
	}

	// 将查询参数合并到已解析的 URL 中，并统一转换为字符串。
	if len(in.Query) > 0 {
		parsed, err := url.Parse(fullURL)
		if err != nil {
			return 0, nil, nil, method + " " + pathRaw, err
		}
		query := parsed.Query()
		for k, v := range in.Query {
			query.Set(k, toString(substituteAny(v, vars)))
		}
		parsed.RawQuery = query.Encode()
		fullURL = parsed.String()
	}

	// 请求正文按 JSON 编码；nil 正文表示不发送 body。
	var bodyReader io.Reader
	hasBody := in.Body != nil
	if hasBody {
		body := substituteAny(in.Body, vars)
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, method + " " + pathRaw, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, nil, method + " " + pathRaw, err
	}

	// 先复制协议默认头，再用例级头覆盖同名值。
	headers := make(map[string]string)
	if spec.Meta.ProtocolDefaults.HTTP != nil {
		for k, v := range spec.Meta.ProtocolDefaults.HTTP.Headers {
			headers[k] = toString(substituteAny(v, vars))
		}
	}
	for k, v := range in.Headers {
		headers[k] = toString(substituteAny(v, vars))
	}
	if hasBody {
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 使用带超时上下文的请求发送 HTTP 调用。
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil, method + " " + pathRaw, err
	}
	defer resp.Body.Close()

	// 读取完整响应正文，随后尝试解析为 JSON。
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, nil, method + " " + pathRaw, err
	}
	respHeaders := flattenHeaders(resp.Header)
	return resp.StatusCode, respHeaders, parseMaybeJSON(respBytes), method + " " + pathRaw, nil
}

// executeGRPC 通过 grpcurl 调用 gRPC 方法，并解析详细输出中的元数据和响应正文。
func executeGRPC(ctx context.Context, spec *TestSpec, in GRPCRequest, vars map[string]any) (string, map[string]string, any, string, error) {
	// 从协议默认配置读取连接目标、明文开关和默认元数据。
	target := ""
	plaintext := true
	defaultMetadata := map[string]string{}
	if spec.Meta.ProtocolDefaults.GRPC != nil {
		target = toString(substituteAny(spec.Meta.ProtocolDefaults.GRPC.Target, vars))
		plaintext = spec.Meta.ProtocolDefaults.GRPC.Plaintext
		for k, v := range spec.Meta.ProtocolDefaults.GRPC.Metadata {
			defaultMetadata[k] = toString(substituteAny(v, vars))
		}
	}
	if strings.TrimSpace(target) == "" {
		return "UNKNOWN", nil, nil, "", errors.New("grpc target is empty")
	}

	// grpcurl 使用 Service/Method 形式定位 RPC 方法。
	endpoint := strings.TrimSpace(in.Service) + "/" + strings.TrimSpace(in.Method)
	args := make([]string, 0, 10)
	if plaintext {
		args = append(args, "-plaintext")
	}

	// 合并默认元数据与用例元数据，用例值优先。
	metadata := make(map[string]string)
	for k, v := range defaultMetadata {
		metadata[k] = v
	}
	for k, v := range in.Metadata {
		metadata[k] = toString(substituteAny(v, vars))
	}
	for k, v := range metadata {
		args = append(args, "-H", k+":"+v)
	}

	// grpcurl 的 JSON 请求消息默认为空对象。
	msg := map[string]any{}
	if in.Message != nil {
		msgAny := substituteAny(in.Message, vars)
		if cast, ok := msgAny.(map[string]any); ok {
			msg = cast
		}
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return "UNKNOWN", nil, nil, endpoint, fmt.Errorf("marshal grpc message: %w", err)
	}

	// -v 用于获取响应初始元数据，-d 用于传入 JSON 消息。
	args = append(args, "-v", "-d", string(msgBytes), target, endpoint)
	cmd := execCommandContext(ctx, "grpcurl", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// 执行外部 grpcurl 命令，并无论退出状态如何都解析其标准输出。
	err = cmd.Run()
	parsedHeaders, parsedBody := parseGRPCVerboseOutput(stdout.Bytes())
	if err == nil {
		return "OK", parsedHeaders, parsedBody, endpoint, nil
	}

	stderrText := strings.TrimSpace(stderr.String())
	if stderrText == "" {
		stderrText = err.Error()
	}

	// grpcurl 成功时可直接视为 OK；失败时从 stderr 中提取更精确的状态码。
	code := "UNKNOWN"
	match := grpcCodeRe.FindStringSubmatch(stderrText)
	if len(match) > 1 {
		code = match[1]
	}
	if bodyIsEmpty(parsedBody) {
		parsedBody = map[string]any{"error": stderrText}
	}

	return code, parsedHeaders, parsedBody, endpoint, fmt.Errorf("grpc call failed: %s", stderrText)
}

// evaluateExpect 根据 Expect DSL 评估响应，并同时生成断言结果和机器可读差异。
func evaluateExpect(expect Expect, protocol string, status *int, grpcCode *string, headers map[string]string, body any) ([]AssertionResult, []Diff) {
	// 分别维护断言明细和差异列表，供成功报告与失败报告使用。
	assertions := make([]AssertionResult, 0)
	diffs := make([]Diff, 0)

	// 先评估协议级状态断言。
	if expect.Status != nil {
		passed := status != nil && *status == *expect.Status
		assertions = append(assertions, AssertionResult{
			Path:    "status",
			Rule:    "equals",
			Passed:  passed,
			Message: fmt.Sprintf("expected=%d actual=%v", *expect.Status, status),
		})
		if !passed {
			diffs = append(diffs, Diff{
				Type:     "status_mismatch",
				Path:     "status",
				Expected: *expect.Status,
				Actual:   status,
			})
		}
	}

	if expect.GRPCCode != "" {
		actual := ""
		if grpcCode != nil {
			actual = *grpcCode
		}
		passed := strings.EqualFold(expect.GRPCCode, actual)
		assertions = append(assertions, AssertionResult{
			Path:    "grpc_code",
			Rule:    "equals",
			Passed:  passed,
			Message: fmt.Sprintf("expected=%s actual=%s", expect.GRPCCode, actual),
		})
		if !passed {
			diffs = append(diffs, Diff{
				Type:     "grpc_code_mismatch",
				Path:     "grpc_code",
				Expected: expect.GRPCCode,
				Actual:   actual,
			})
		}
	}

	// headers 规则同时适用于 HTTP 响应头和 gRPC 初始元数据。
	for key, expected := range expect.Headers {
		actual := headers[key]
		exp := toString(expected)
		passed := actual == exp
		assertions = append(assertions, AssertionResult{
			Path:    "headers." + key,
			Rule:    "equals",
			Passed:  passed,
			Message: fmt.Sprintf("expected=%s actual=%s", exp, actual),
		})
		if !passed {
			diffs = append(diffs, Diff{
				Type:     "value_mismatch",
				Path:     "headers." + key,
				Expected: exp,
				Actual:   actual,
			})
		}
	}

	// 将任意正文统一编码为 JSON，交给 gjson 按路径查询。
	bodyBytes, _ := json.Marshal(body)
	// 每条正文规则独立评估，并为失败项生成稳定的差异类型。
	for path, rule := range expect.Body {
		queryPath := normalizePath(path)
		res := gjson.GetBytes(bodyBytes, queryPath)
		value := res.Value()
		exists := res.Exists()

		if rule.Exists != nil {
			passed := exists == *rule.Exists
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "exists",
				Passed:  passed,
				Message: fmt.Sprintf("expected=%t actual=%t", *rule.Exists, exists),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "missing_field",
					Path:     path,
					Expected: *rule.Exists,
					Actual:   exists,
				})
			}
		}

		if !exists {
			if rule.Exists == nil || *rule.Exists {
				assertions = append(assertions, AssertionResult{
					Path:    path,
					Rule:    "exists",
					Passed:  false,
					Message: "field missing",
				})
				diffs = append(diffs, Diff{
					Type:     "missing_field",
					Path:     path,
					Expected: "field exists",
					Actual:   "missing",
				})
			}
			continue
		}

		if rule.Type != "" {
			actualType := jsonType(value)
			passed := strings.EqualFold(rule.Type, actualType)
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "type",
				Passed:  passed,
				Message: fmt.Sprintf("expected=%s actual=%s", rule.Type, actualType),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "type_mismatch",
					Path:     path,
					Expected: rule.Type,
					Actual:   actualType,
				})
			}
		}

		if rule.Equals != nil {
			passed := deepEqualLoose(rule.Equals, value)
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "equals",
				Passed:  passed,
				Message: fmt.Sprintf("expected=%v actual=%v", rule.Equals, value),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "value_mismatch",
					Path:     path,
					Expected: rule.Equals,
					Actual:   value,
				})
			}
		}

		if rule.NotEmpty {
			passed := isNotEmpty(value)
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "not_empty",
				Passed:  passed,
				Message: fmt.Sprintf("actual=%v", value),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "value_mismatch",
					Path:     path,
					Expected: "not empty",
					Actual:   value,
				})
			}
		}

		if rule.Matches != "" {
			s := toString(value)
			matched, err := regexp.MatchString(rule.Matches, s)
			passed := err == nil && matched
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "matches",
				Passed:  passed,
				Message: fmt.Sprintf("pattern=%s actual=%s", rule.Matches, s),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "regex_mismatch",
					Path:     path,
					Expected: rule.Matches,
					Actual:   s,
				})
			}
		}

		if rule.MinItems != nil {
			size, ok := arrayLen(value)
			passed := ok && size >= *rule.MinItems
			assertions = append(assertions, AssertionResult{
				Path:    path,
				Rule:    "min_items",
				Passed:  passed,
				Message: fmt.Sprintf("expected>=%d actual=%d", *rule.MinItems, size),
			})
			if !passed {
				diffs = append(diffs, Diff{
					Type:     "value_mismatch",
					Path:     path,
					Expected: *rule.MinItems,
					Actual:   size,
				})
			}
		}
	}

	_ = protocol
	return assertions, diffs
}

// applyExtract 按提取规则从响应正文读取值，并写回后续用例可使用的变量表。
func applyExtract(vars map[string]any, extract map[string]string, body any) {
	// 没有提取规则时无需序列化和遍历正文。
	if len(extract) == 0 {
		return
	}
	// 提取和断言使用相同的 gjson 路径语义。
	bodyBytes, _ := json.Marshal(body)
	for key, path := range extract {
		res := gjson.GetBytes(bodyBytes, normalizePath(path))
		if res.Exists() {
			vars[key] = res.Value()
		}
	}
}

// substituteAny 递归替换字符串、对象和数组中的变量占位符。
func substituteAny(v any, vars map[string]any) any {
	// 根据动态值的具体类型递归处理嵌套结构。
	switch t := v.(type) {
	case string:
		return substituteString(t, vars)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = substituteAny(vv, vars)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = substituteAny(t[i], vars)
		}
		return out
	default:
		return v
	}
}

// substituteString 替换字符串中的 {{vars.*}} 和 {{timestamp}} 占位符。
func substituteString(input string, vars map[string]any) string {
	// 未找到变量时保留原占位符，避免静默破坏请求内容。
	return placeholderRe.ReplaceAllStringFunc(input, func(match string) string {
		sub := placeholderRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		key := strings.TrimSpace(sub[1])
		if key == "timestamp" {
			return strconv.FormatInt(time.Now().Unix(), 10)
		}
		if strings.HasPrefix(key, "vars.") {
			key = strings.TrimPrefix(key, "vars.")
		}
		if val, ok := lookupVar(vars, key); ok {
			return toString(val)
		}
		return match
	})
}

// lookupVar 先查找顶层变量，再使用 gjson 支持嵌套路径查找变量。
func lookupVar(vars map[string]any, key string) (any, bool) {
	if v, ok := vars[key]; ok {
		return v, true
	}
	// 通过 JSON 序列化复用 gjson 的嵌套路径查询能力。
	b, _ := json.Marshal(vars)
	res := gjson.GetBytes(b, normalizePath(key))
	if !res.Exists() {
		return nil, false
	}
	return res.Value(), true
}

// parseMaybeJSON 将字节内容解析为 JSON；解析失败时保留为字符串。
func parseMaybeJSON(b []byte) any {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return map[string]any{}
	}
	var out any
	if json.Unmarshal(trimmed, &out) == nil {
		return out
	}
	return string(trimmed)
}

// parseGRPCVerboseOutput 解析 grpcurl -v 输出，提取响应初始元数据和正文。
func parseGRPCVerboseOutput(stdout []byte) (map[string]string, any) {
	// 先按 grpcurl 标题拆分输出，再分别解析 headers 和 contents。
	sections := parseGRPCVerboseSections(string(stdout))
	if len(sections) == 0 {
		return map[string]string{}, parseMaybeJSON(stdout)
	}

	headers := parseGRPCMetadataBlock(firstSection(sections["Response headers received"]))
	contentBlocks := sections["Response contents"]
	if len(contentBlocks) == 0 {
		return headers, map[string]any{}
	}
	if len(contentBlocks) == 1 {
		return headers, parseMaybeJSON([]byte(contentBlocks[0]))
	}

	body := make([]any, 0, len(contentBlocks))
	for _, block := range contentBlocks {
		body = append(body, parseMaybeJSON([]byte(block)))
	}
	return headers, body
}

// parseGRPCVerboseSections 将 grpcurl 文本输出按标题拆分为多个内容区段。
func parseGRPCVerboseSections(output string) map[string][]string {
	// 统一换行符，便于兼容不同平台的 grpcurl 输出。
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	sections := make(map[string][]string)
	currentHeading := ""
	var currentLines []string
	// flush 将当前标题下累积的文本保存为一个区段。
	flush := func() {
		if currentHeading == "" {
			return
		}
		sections[currentHeading] = append(sections[currentHeading], strings.Trim(strings.Join(currentLines, "\n"), "\n"))
		currentHeading = ""
		currentLines = nil
	}

	// 逐行识别区段标题、空行和 grpcurl 的统计尾部。
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "Request metadata to send:", "Response headers received:", "Response contents:", "Response trailers received:":
			flush()
			currentHeading = strings.TrimSuffix(trimmed, ":")
			currentLines = nil
		case "":
			if currentHeading != "" {
				currentLines = append(currentLines, line)
			}
		default:
			if strings.HasPrefix(trimmed, "Sent ") {
				flush()
				continue
			}
			if currentHeading != "" {
				currentLines = append(currentLines, line)
			}
		}
	}
	flush()
	return sections
}

// parseGRPCMetadataBlock 将 key:value 格式的元数据文本转换为字符串映射。
func parseGRPCMetadataBlock(block string) map[string]string {
	out := make(map[string]string)
	trimmed := strings.TrimSpace(block)
	if trimmed == "" || trimmed == "(empty)" {
		return out
	}

	// 每行按第一个冒号拆分，保留值中可能存在的其他冒号。
	for _, line := range strings.Split(trimmed, "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		key, value, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if existing, exists := out[key]; exists {
			out[key] = existing + "," + value
			continue
		}
		out[key] = value
	}
	return out
}

// firstSection 返回区段列表中的第一个元素，不存在时返回空字符串。
func firstSection(sections []string) string {
	if len(sections) == 0 {
		return ""
	}
	return sections[0]
}

// bodyIsEmpty 判断响应正文是否为空字符串、空数组、空对象或 nil。
func bodyIsEmpty(body any) bool {
	switch t := body.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// flattenHeaders 将 http.Header 的多值头合并为逗号分隔的字符串。
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ",")
	}
	return out
}

// joinURL 将相对路径与基础 URL 拼接；绝对 URL 会直接返回。
func joinURL(baseURL, path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	if baseURL == "" {
		return "", errors.New("base_url is empty")
	}
	// 去掉末尾斜杠后解析基础 URL，并用根相对路径覆盖其路径部分。
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid base_url: %w", err)
	}
	rel, err := url.Parse("/" + strings.TrimLeft(path, "/"))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}

// normalizePath 将数组下标路径转换为 gjson 使用的点号路径。
func normalizePath(path string) string {
	// gjson 使用 a.0.b 形式访问数组元素，而 DSL 允许 a[0].b。
	out := bracketIndexRe.ReplaceAllString(path, ".$1")
	return strings.TrimPrefix(out, ".")
}

// cloneMap 创建变量表的浅拷贝，避免执行过程直接改写原始变量映射。
func cloneMap(in map[string]any) map[string]any {
	// 仅复制顶层映射；嵌套值会在需要时由替换逻辑重新构造。
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// toString 将任意值转换为用于请求参数、头和占位符替换的字符串。
func toString(v any) string {
	// 字符串、数组和对象按容器语义判断空值，其他标量只要存在即视为非空。
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// jsonType 返回值对应的 JSON 类型名称。
func jsonType(v any) string {
	// JSON 类型名称与 DSL 中的 type 断言值保持一致。
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

// deepEqualLoose 比较两个值，并允许不同 Go 数值类型之间进行数值相等比较。
func deepEqualLoose(expected, actual any) bool {
	// JSON 数字通常被解码为 float64，因此先做跨数值类型比较。
	if asFloat(expected) != nil && asFloat(actual) != nil {
		return *asFloat(expected) == *asFloat(actual)
	}
	return reflect.DeepEqual(expected, actual)
}

// asFloat 将常见整数和浮点数转换为 float64 指针，非数字值返回 nil。
func asFloat(v any) *float64 {
	// 将各种整数类型归一化为 float64，供宽松相等比较使用。
	switch t := v.(type) {
	case float64:
		return &t
	case float32:
		f := float64(t)
		return &f
	case int:
		f := float64(t)
		return &f
	case int8:
		f := float64(t)
		return &f
	case int16:
		f := float64(t)
		return &f
	case int32:
		f := float64(t)
		return &f
	case int64:
		f := float64(t)
		return &f
	case uint:
		f := float64(t)
		return &f
	case uint8:
		f := float64(t)
		return &f
	case uint16:
		f := float64(t)
		return &f
	case uint32:
		f := float64(t)
		return &f
	case uint64:
		f := float64(t)
		return &f
	default:
		return nil
	}
}

// isNotEmpty 判断字符串、数组、对象或其他值是否具有非空语义。
func isNotEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// arrayLen 返回数组长度，并通过布尔值标识输入是否为数组。
func arrayLen(v any) (int, bool) {
	switch t := v.(type) {
	case []any:
		return len(t), true
	default:
		return 0, false
	}
}

// expectedToMap 将 Expect 结构转换为失败报告使用的通用键值结构。
func expectedToMap(expect Expect) map[string]any {
	// 只输出实际配置的断言字段，避免失败报告包含无意义的零值。
	out := map[string]any{}
	if expect.Status != nil {
		out["status"] = *expect.Status
	}
	if expect.GRPCCode != "" {
		out["grpc_code"] = expect.GRPCCode
	}
	if len(expect.Headers) > 0 {
		out["headers"] = expect.Headers
	}
	if len(expect.Body) > 0 {
		out["body"] = expect.Body
	}
	return out
}

// classifyRuntimeError 将运行时错误映射为稳定的差异类型。
func classifyRuntimeError(err error) []Diff {
	if err == nil {
		return nil
	}
	// 通过错误文本归类常见超时、连接失败和其他运行时错误。
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "deadline exceeded"):
		return []Diff{{Type: "timeout", Path: "request", Expected: "response within timeout", Actual: err.Error()}}
	case strings.Contains(msg, "connection") || strings.Contains(msg, "refused"):
		return []Diff{{Type: "connection_error", Path: "request", Expected: "reachable endpoint", Actual: err.Error()}}
	default:
		return []Diff{{Type: "connection_error", Path: "request", Expected: "successful call", Actual: err.Error()}}
	}
}

// diagnose 根据运行时错误和断言差异生成去重后的诊断提示。
func diagnose(runErr error, diffs []Diff) []string {
	// 诊断消息容量预留为常见的错误加若干断言提示。
	out := make([]string, 0, 3)
	if runErr != nil {
		out = append(out, runErr.Error())
	}
	for _, d := range diffs {
		switch d.Type {
		case "status_mismatch":
			out = append(out, "HTTP status mismatch, check auth, route, and business validation.")
		case "grpc_code_mismatch":
			out = append(out, "gRPC code mismatch, check metadata/token and interceptor validation.")
		case "missing_field":
			out = append(out, "Expected response field is missing, check DTO mapping and serialization.")
		case "type_mismatch":
			out = append(out, "Response field type changed, check API compatibility.")
		case "value_mismatch":
			out = append(out, "Response value mismatch, check business logic and test data.")
		case "regex_mismatch":
			out = append(out, "Response format mismatch against regex rule.")
		}
	}
	if len(out) == 0 {
		out = append(out, "Assertion failed.")
	}
	return uniqueStrings(out)
}

// uniqueStrings 按首次出现顺序去除字符串切片中的重复项。
func uniqueStrings(in []string) []string {
	// 集合用于去重，同时单独切片保留原始出现顺序。
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
