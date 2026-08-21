package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
)

func TestParseGRPCVerboseOutputExtractsHeadersAndBody(t *testing.T) {
	stdout := "\nRequest metadata to send:\nauthorization: Bearer demo\n\nResponse headers received:\ncontent-type: application/grpc\nx-request-id: req-1\n\nResponse contents:\n{\n  \"user\": {\n    \"id\": \"123\",\n    \"name\": \"User 123\"\n  }\n}\n\nResponse trailers received:\n(empty)\n\nSent 1 request and received 1 response\n"

	headers, body := parseGRPCVerboseOutput([]byte(stdout))

	wantHeaders := map[string]string{
		"content-type": "application/grpc",
		"x-request-id": "req-1",
	}
	if !reflect.DeepEqual(headers, wantHeaders) {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	wantBody := map[string]any{
		"user": map[string]any{
			"id":   "123",
			"name": "User 123",
		},
	}
	if !reflect.DeepEqual(body, wantBody) {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestExecuteGRPCCapturesInitialMetadata(t *testing.T) {
	previousExec := execCommandContext
	t.Cleanup(func() { execCommandContext = previousExec })

	var gotName string
	var gotArgs []string
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return helperCommand(t, helperCommandOptions{
			stdout: "\nResponse headers received:\ncontent-type: application/grpc\nx-request-id: req-9\n\nResponse contents:\n{\n  \"user\": {\n    \"id\": \"123\",\n    \"email\": \"user@example.com\"\n  }\n}\n\nResponse trailers received:\n(empty)\n\nSent 1 request and received 1 response\n",
		})
	}

	spec := &TestSpec{
		Meta: Meta{
			ProtocolDefaults: ProtocolDefaults{
				GRPC: &GRPCDefaults{
					Target:    "{{vars.grpc_target}}",
					Plaintext: true,
					Metadata: map[string]string{
						"authorization": "Bearer {{vars.token}}",
					},
				},
			},
		},
	}
	request := GRPCRequest{
		Service: "user.v1.UserService",
		Method:  "GetUser",
		Metadata: map[string]any{
			"x-tenant-id": "{{vars.tenant_id}}",
		},
		Message: map[string]any{
			"user_id": "{{vars.user_id}}",
		},
	}
	vars := map[string]any{
		"grpc_target": "127.0.0.1:50051",
		"tenant_id":   "tenant-a",
		"token":       "demo-token",
		"user_id":     "123",
	}

	code, headers, body, endpoint, err := executeGRPC(context.Background(), spec, request, vars)
	if err != nil {
		t.Fatalf("executeGRPC returned error: %v", err)
	}
	if gotName != "grpcurl" {
		t.Fatalf("unexpected command name: %s", gotName)
	}
	if endpoint != "user.v1.UserService/GetUser" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
	if code != "OK" {
		t.Fatalf("unexpected code: %s", code)
	}
	if !containsString(gotArgs, "-v") {
		t.Fatalf("expected grpcurl args to include -v: %#v", gotArgs)
	}
	if !containsString(gotArgs, "authorization:Bearer demo-token") {
		t.Fatalf("expected grpcurl args to include default metadata: %#v", gotArgs)
	}
	if !containsString(gotArgs, "x-tenant-id:tenant-a") {
		t.Fatalf("expected grpcurl args to include request metadata: %#v", gotArgs)
	}
	wantHeaders := map[string]string{
		"content-type": "application/grpc",
		"x-request-id": "req-9",
	}
	if !reflect.DeepEqual(headers, wantHeaders) {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	wantBody := map[string]any{
		"user": map[string]any{
			"id":    "123",
			"email": "user@example.com",
		},
	}
	if !reflect.DeepEqual(body, wantBody) {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestExecuteGRPCParsesFormattedStatusCode(t *testing.T) {
	previousExec := execCommandContext
	t.Cleanup(func() { execCommandContext = previousExec })

	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return helperCommand(t, helperCommandOptions{
			stdout:   "\nResponse headers received:\ncontent-type: application/grpc\n\nResponse trailers received:\ngrpc-message: permission denied\ngrpc-status: 7\n",
			stderr:   "ERROR:\n  Code: PermissionDenied\n  Message: permission denied\n",
			exitCode: 1,
		})
	}

	spec := &TestSpec{
		Meta: Meta{
			ProtocolDefaults: ProtocolDefaults{
				GRPC: &GRPCDefaults{Target: "127.0.0.1:50051", Plaintext: true},
			},
		},
	}

	code, headers, body, endpoint, err := executeGRPC(context.Background(), spec, GRPCRequest{
		Service: "user.v1.UserService",
		Method:  "DeleteUser",
		Message: map[string]any{"user_id": "123"},
	}, nil)
	if err == nil {
		t.Fatal("expected executeGRPC to return error")
	}
	if endpoint != "user.v1.UserService/DeleteUser" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
	if code != "PermissionDenied" {
		t.Fatalf("unexpected code: %s", code)
	}
	if headers["content-type"] != "application/grpc" {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	bodyMap, ok := body.(map[string]any)
	if !ok {
		t.Fatalf("unexpected body type: %#v", body)
	}
	if bodyMap["error"] != "ERROR:\n  Code: PermissionDenied\n  Message: permission denied" {
		t.Fatalf("unexpected error body: %#v", bodyMap)
	}
}

func TestEvaluateExpectSupportsGRPCHeaders(t *testing.T) {
	code := "OK"
	expect := Expect{
		GRPCCode: "OK",
		Headers: map[string]any{
			"content-type": "application/grpc",
		},
	}

	assertions, diffs := evaluateExpect(expect, "grpc", nil, &code, map[string]string{"content-type": "application/grpc"}, map[string]any{})
	if len(assertions) != 2 {
		t.Fatalf("unexpected assertion count: %d", len(assertions))
	}
	if len(diffs) != 0 {
		t.Fatalf("unexpected diffs: %#v", diffs)
	}
}

type helperCommandOptions struct {
	stdout   string
	stderr   string
	exitCode int
}

func helperCommand(t *testing.T, opts helperCommandOptions) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"GO_HELPER_STDOUT="+base64.StdEncoding.EncodeToString([]byte(opts.stdout)),
		"GO_HELPER_STDERR="+base64.StdEncoding.EncodeToString([]byte(opts.stderr)),
		fmt.Sprintf("GO_HELPER_EXIT_CODE=%d", opts.exitCode),
	)
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	stdout, _ := base64.StdEncoding.DecodeString(os.Getenv("GO_HELPER_STDOUT"))
	stderr, _ := base64.StdEncoding.DecodeString(os.Getenv("GO_HELPER_STDERR"))
	_, _ = os.Stdout.Write(stdout)
	_, _ = os.Stderr.Write(stderr)
	exitCode, _ := strconv.Atoi(os.Getenv("GO_HELPER_EXIT_CODE"))
	os.Exit(exitCode)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
