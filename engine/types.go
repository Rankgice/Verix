package engine

import "encoding/json"

type TestSpec struct {
	Meta  Meta           `json:"meta"`
	Vars  map[string]any `json:"vars"`
	Cases []Case         `json:"cases"`
}

type Meta struct {
	Name             string           `json:"name"`
	ProtocolDefaults ProtocolDefaults `json:"protocol_defaults"`
	TimeoutMS        int              `json:"timeout_ms"`
}

type ProtocolDefaults struct {
	HTTP *HTTPDefaults `json:"http,omitempty"`
	GRPC *GRPCDefaults `json:"grpc,omitempty"`
}

type HTTPDefaults struct {
	BaseURL string            `json:"base_url"`
	Headers map[string]string `json:"headers"`
}

type GRPCDefaults struct {
	Target    string            `json:"target"`
	Plaintext bool              `json:"plaintext"`
	Metadata  map[string]string `json:"metadata"`
}

type Case struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Protocol Protocol          `json:"protocol"`
	Request  json.RawMessage   `json:"request"`
	Expect   Expect            `json:"expect"`
	Extract  map[string]string `json:"extract"`
}

type Protocol struct {
	Type string `json:"type"`
}

type HTTPRequest struct {
	Method  string         `json:"method"`
	Path    string         `json:"path"`
	Headers map[string]any `json:"headers"`
	Query   map[string]any `json:"query"`
	Body    any            `json:"body"`
}

type GRPCRequest struct {
	Service  string         `json:"service"`
	Method   string         `json:"method"`
	Metadata map[string]any `json:"metadata"`
	Message  any            `json:"message"`
}

type Expect struct {
	Success  *bool               `json:"success,omitempty"`
	Status   *int                `json:"status,omitempty"`
	GRPCCode string              `json:"grpc_code,omitempty"`
	Headers  map[string]any      `json:"headers,omitempty"`
	Body     map[string]BodyRule `json:"body,omitempty"`
}

type BodyRule struct {
	Type     string `json:"type,omitempty"`
	Equals   any    `json:"equals,omitempty"`
	NotEmpty bool   `json:"not_empty,omitempty"`
	Exists   *bool  `json:"exists,omitempty"`
	Matches  string `json:"matches,omitempty"`
	MinItems *int   `json:"min_items,omitempty"`
}

type RunReport struct {
	Summary     Summary         `json:"summary"`
	FailedCases []FailedCase    `json:"failed_cases"`
	CaseResults []CaseExecution `json:"case_results"`
}

type Summary struct {
	Total      int   `json:"total"`
	Passed     int   `json:"passed"`
	Failed     int   `json:"failed"`
	DurationMS int64 `json:"duration_ms"`
}

type CaseExecution struct {
	ID           string            `json:"id"`
	Protocol     string            `json:"protocol"`
	Endpoint     string            `json:"endpoint"`
	DurationMS   int64             `json:"duration_ms"`
	Status       *int              `json:"status,omitempty"`
	GRPCCode     *string           `json:"grpc_code,omitempty"`
	ResponseBody any               `json:"response_body,omitempty"`
	Error        string            `json:"error,omitempty"`
	Assertions   []AssertionResult `json:"assertions"`
}

type AssertionResult struct {
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type FailedCase struct {
	ID        string         `json:"id"`
	Protocol  string         `json:"protocol"`
	Endpoint  string         `json:"endpoint"`
	Expected  map[string]any `json:"expected"`
	Actual    map[string]any `json:"actual"`
	Diff      []Diff         `json:"diff"`
	Diagnosis []string       `json:"diagnosis"`
}

type Diff struct {
	Type     string `json:"type"`
	Path     string `json:"path,omitempty"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
}
