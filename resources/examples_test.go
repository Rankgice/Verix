package resources

import (
	"encoding/json"
	"testing"

	"verix/engine"
)

func TestExampleHTTPTestSpecCoversSupportedHTTPAssertions(t *testing.T) {
	spec := mustParseExampleSpec(t, ExampleHTTPTestSpecJSON())
	flags := collectAssertionCoverage(spec)

	if !flags.status {
		t.Fatal("expected HTTP example to include status assertion")
	}
	if !flags.headers {
		t.Fatal("expected HTTP example to include headers assertion")
	}
	assertBodyRuleCoverage(t, flags)
}

func TestExampleGRPCTestSpecCoversSupportedGRPCAssertions(t *testing.T) {
	spec := mustParseExampleSpec(t, ExampleGRPCTestSpecJSON())
	flags := collectAssertionCoverage(spec)

	if !flags.grpcCode {
		t.Fatal("expected gRPC example to include grpc_code assertion")
	}
	if !flags.headers {
		t.Fatal("expected gRPC example to include headers assertion")
	}
	assertBodyRuleCoverage(t, flags)
}

type assertionCoverage struct {
	status   bool
	grpcCode bool
	headers  bool
	typeRule bool
	equals   bool
	notEmpty bool
	exists   bool
	matches  bool
	minItems bool
}

func mustParseExampleSpec(t *testing.T, raw string) *engine.TestSpec {
	t.Helper()
	var spec engine.TestSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	return &spec
}

func collectAssertionCoverage(spec *engine.TestSpec) assertionCoverage {
	var flags assertionCoverage
	for _, tc := range spec.Cases {
		if tc.Expect.Status != nil {
			flags.status = true
		}
		if tc.Expect.GRPCCode != "" {
			flags.grpcCode = true
		}
		if len(tc.Expect.Headers) > 0 {
			flags.headers = true
		}
		for _, rule := range tc.Expect.Body {
			if rule.Type != "" {
				flags.typeRule = true
			}
			if rule.Equals != nil {
				flags.equals = true
			}
			if rule.NotEmpty {
				flags.notEmpty = true
			}
			if rule.Exists != nil {
				flags.exists = true
			}
			if rule.Matches != "" {
				flags.matches = true
			}
			if rule.MinItems != nil {
				flags.minItems = true
			}
		}
	}
	return flags
}

func assertBodyRuleCoverage(t *testing.T, flags assertionCoverage) {
	t.Helper()
	if !flags.typeRule {
		t.Fatal("expected example to include type assertion")
	}
	if !flags.equals {
		t.Fatal("expected example to include equals assertion")
	}
	if !flags.notEmpty {
		t.Fatal("expected example to include not_empty assertion")
	}
	if !flags.exists {
		t.Fatal("expected example to include exists assertion")
	}
	if !flags.matches {
		t.Fatal("expected example to include matches assertion")
	}
	if !flags.minItems {
		t.Fatal("expected example to include min_items assertion")
	}
}
