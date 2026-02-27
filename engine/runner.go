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

var (
	placeholderRe  = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)
	bracketIndexRe = regexp.MustCompile(`\[(\d+)\]`)
	grpcCodeRe     = regexp.MustCompile(`code = ([A-Za-z]+)`)
)

func ValidateSpec(spec *TestSpec) []string {
	if spec == nil {
		return []string{"spec is nil"}
	}
	var errs []string
	if strings.TrimSpace(spec.Meta.Name) == "" {
		errs = append(errs, "meta.name is required")
	}
	if spec.Meta.TimeoutMS <= 0 {
		spec.Meta.TimeoutMS = 5000
	}

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

func RunSpec(ctx context.Context, spec *TestSpec) (*RunReport, error) {
	if spec == nil {
		return nil, errors.New("spec is nil")
	}

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

	start := time.Now()
	results := make([]CaseExecution, 0, len(spec.Cases))
	failed := make([]FailedCase, 0)
	passedCount := 0
	vars := cloneMap(spec.Vars)

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

		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.Meta.TimeoutMS)*time.Millisecond)
		switch protocol {
		case "http":
			var req HTTPRequest
			if err := json.Unmarshal(tc.Request, &req); err != nil {
				runErr = fmt.Errorf("invalid http request: %w", err)
				break
			}
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
			code, body, endpoint, err := executeGRPC(timeoutCtx, spec, req, vars)
			execResult.Endpoint = endpoint
			if err != nil {
				runErr = err
			}
			respCode = &code
			respBody = body
		default:
			runErr = fmt.Errorf("unsupported protocol %q", protocol)
		}
		cancel()

		execResult.Status = respStatus
		execResult.GRPCCode = respCode
		execResult.ResponseBody = respBody
		if runErr != nil {
			execResult.Error = runErr.Error()
		}

		assertions, diffs := evaluateExpect(tc.Expect, protocol, respStatus, respCode, respHeaders, respBody)
		execResult.Assertions = append(execResult.Assertions, assertions...)
		execResult.DurationMS = time.Since(caseStart).Milliseconds()
		results = append(results, execResult)

		if runErr == nil && len(diffs) == 0 {
			applyExtract(vars, tc.Extract, respBody)
			passedCount++
			continue
		}

		failedCase := FailedCase{
			ID:       tc.ID,
			Protocol: protocol,
			Endpoint: execResult.Endpoint,
			Expected: expectedToMap(tc.Expect),
			Actual: map[string]any{
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

func executeHTTP(ctx context.Context, spec *TestSpec, in HTTPRequest, vars map[string]any) (int, map[string]string, any, string, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}

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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil, method + " " + pathRaw, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, nil, method + " " + pathRaw, err
	}
	respHeaders := flattenHeaders(resp.Header)
	return resp.StatusCode, respHeaders, parseMaybeJSON(respBytes), method + " " + pathRaw, nil
}

func executeGRPC(ctx context.Context, spec *TestSpec, in GRPCRequest, vars map[string]any) (string, any, string, error) {
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
		return "UNKNOWN", nil, "", errors.New("grpc target is empty")
	}

	endpoint := strings.TrimSpace(in.Service) + "/" + strings.TrimSpace(in.Method)
	args := make([]string, 0, 10)
	if plaintext {
		args = append(args, "-plaintext")
	}

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

	msg := map[string]any{}
	if in.Message != nil {
		msgAny := substituteAny(in.Message, vars)
		if cast, ok := msgAny.(map[string]any); ok {
			msg = cast
		}
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return "UNKNOWN", nil, endpoint, fmt.Errorf("marshal grpc message: %w", err)
	}

	args = append(args, "-d", string(msgBytes), target, endpoint)
	cmd := exec.CommandContext(ctx, "grpcurl", args...)
	stdout, err := cmd.Output()
	if err == nil {
		return "OK", parseMaybeJSON(stdout), endpoint, nil
	}

	var stderr string
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr = string(exitErr.Stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		stderr = err.Error()
	}

	code := "UNKNOWN"
	match := grpcCodeRe.FindStringSubmatch(stderr)
	if len(match) > 1 {
		code = match[1]
	}

	return code, map[string]any{"error": strings.TrimSpace(stderr)}, endpoint, fmt.Errorf("grpc call failed: %s", strings.TrimSpace(stderr))
}

func evaluateExpect(expect Expect, protocol string, status *int, grpcCode *string, headers map[string]string, body any) ([]AssertionResult, []Diff) {
	assertions := make([]AssertionResult, 0)
	diffs := make([]Diff, 0)

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

	bodyBytes, _ := json.Marshal(body)
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

func applyExtract(vars map[string]any, extract map[string]string, body any) {
	if len(extract) == 0 {
		return
	}
	bodyBytes, _ := json.Marshal(body)
	for key, path := range extract {
		res := gjson.GetBytes(bodyBytes, normalizePath(path))
		if res.Exists() {
			vars[key] = res.Value()
		}
	}
}

func substituteAny(v any, vars map[string]any) any {
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

func substituteString(input string, vars map[string]any) string {
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

func lookupVar(vars map[string]any, key string) (any, bool) {
	if v, ok := vars[key]; ok {
		return v, true
	}
	b, _ := json.Marshal(vars)
	res := gjson.GetBytes(b, normalizePath(key))
	if !res.Exists() {
		return nil, false
	}
	return res.Value(), true
}

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

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ",")
	}
	return out
}

func joinURL(baseURL, path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	if baseURL == "" {
		return "", errors.New("base_url is empty")
	}
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

func normalizePath(path string) string {
	out := bracketIndexRe.ReplaceAllString(path, ".$1")
	return strings.TrimPrefix(out, ".")
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func toString(v any) string {
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

func jsonType(v any) string {
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

func deepEqualLoose(expected, actual any) bool {
	if asFloat(expected) != nil && asFloat(actual) != nil {
		return *asFloat(expected) == *asFloat(actual)
	}
	return reflect.DeepEqual(expected, actual)
}

func asFloat(v any) *float64 {
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

func arrayLen(v any) (int, bool) {
	switch t := v.(type) {
	case []any:
		return len(t), true
	default:
		return 0, false
	}
}

func expectedToMap(expect Expect) map[string]any {
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

func classifyRuntimeError(err error) []Diff {
	if err == nil {
		return nil
	}
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

func diagnose(runErr error, diffs []Diff) []string {
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

func uniqueStrings(in []string) []string {
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
