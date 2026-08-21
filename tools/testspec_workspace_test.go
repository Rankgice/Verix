package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"verix/engine"
	"verix/resources"
)

func TestInitializeTestSpecWorkspaceCreatesFiles(t *testing.T) {
	root := t.TempDir()

	out, err := initializeTestSpecWorkspace(root, false)
	if err != nil {
		t.Fatalf("initializeTestSpecWorkspace returned error: %v", err)
	}

	wantDir := filepath.Join(root, testspecWorkspaceDirName)
	if out.Directory != wantDir {
		t.Fatalf("unexpected directory: %s", out.Directory)
	}
	if out.GlobalFile.Path != filepath.Join(wantDir, testspecGlobalFileName) {
		t.Fatalf("unexpected global file path: %s", out.GlobalFile.Path)
	}
	if out.ExampleFile.Path != filepath.Join(wantDir, testspecExampleFileName) {
		t.Fatalf("unexpected http example file path: %s", out.ExampleFile.Path)
	}
	if out.GRPCExampleFile.Path != filepath.Join(wantDir, testspecGRPCExampleFileName) {
		t.Fatalf("unexpected grpc example file path: %s", out.GRPCExampleFile.Path)
	}
	if out.GlobalFile.Status != workspaceFileCreated {
		t.Fatalf("unexpected global file status: %s", out.GlobalFile.Status)
	}
	if out.ExampleFile.Status != workspaceFileCreated {
		t.Fatalf("unexpected http example file status: %s", out.ExampleFile.Status)
	}
	if out.GRPCExampleFile.Status != workspaceFileCreated {
		t.Fatalf("unexpected grpc example file status: %s", out.GRPCExampleFile.Status)
	}

	assertGlobalConfig(t, out.GlobalFile.Path)
	assertFileContent(t, out.ExampleFile.Path, resources.ExampleHTTPTestSpecJSON())
	assertFileContent(t, out.GRPCExampleFile.Path, resources.ExampleGRPCTestSpecJSON())
}

func TestInitializeTestSpecWorkspacePreservesExistingFilesWithoutOverwrite(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, testspecWorkspaceDirName)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	globalPath := filepath.Join(workspaceDir, testspecGlobalFileName)
	httpExamplePath := filepath.Join(workspaceDir, testspecExampleFileName)
	grpcExamplePath := filepath.Join(workspaceDir, testspecGRPCExampleFileName)
	wantGlobal := []byte("{\n  \"schema\": \"verix.global.v1\",\n  \"vars\": {\n    \"token\": \"custom\"\n  }\n}\n")
	wantHTTPExample := []byte("{\"http\":true}")
	wantGRPCExample := []byte("{\"grpc\":true}")
	if err := os.WriteFile(globalPath, wantGlobal, 0o600); err != nil {
		t.Fatalf("WriteFile global returned error: %v", err)
	}
	if err := os.WriteFile(httpExamplePath, wantHTTPExample, 0o600); err != nil {
		t.Fatalf("WriteFile http example returned error: %v", err)
	}
	if err := os.WriteFile(grpcExamplePath, wantGRPCExample, 0o600); err != nil {
		t.Fatalf("WriteFile grpc example returned error: %v", err)
	}

	out, err := initializeTestSpecWorkspace(root, false)
	if err != nil {
		t.Fatalf("initializeTestSpecWorkspace returned error: %v", err)
	}
	if out.GlobalFile.Status != workspaceFileExisting {
		t.Fatalf("unexpected global file status: %s", out.GlobalFile.Status)
	}
	if out.ExampleFile.Status != workspaceFileExisting {
		t.Fatalf("unexpected http example file status: %s", out.ExampleFile.Status)
	}
	if out.GRPCExampleFile.Status != workspaceFileExisting {
		t.Fatalf("unexpected grpc example file status: %s", out.GRPCExampleFile.Status)
	}

	assertFileContent(t, globalPath, string(wantGlobal))
	assertFileContent(t, httpExamplePath, string(wantHTTPExample))
	assertFileContent(t, grpcExamplePath, string(wantGRPCExample))
}

func TestInitializeTestSpecWorkspaceOverwritesFilesWhenRequested(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, testspecWorkspaceDirName)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	globalPath := filepath.Join(workspaceDir, testspecGlobalFileName)
	httpExamplePath := filepath.Join(workspaceDir, testspecExampleFileName)
	grpcExamplePath := filepath.Join(workspaceDir, testspecGRPCExampleFileName)
	if err := os.WriteFile(globalPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile global returned error: %v", err)
	}
	if err := os.WriteFile(httpExamplePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile http example returned error: %v", err)
	}
	if err := os.WriteFile(grpcExamplePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile grpc example returned error: %v", err)
	}

	out, err := initializeTestSpecWorkspace(root, true)
	if err != nil {
		t.Fatalf("initializeTestSpecWorkspace returned error: %v", err)
	}
	if out.GlobalFile.Status != workspaceFileUpdated {
		t.Fatalf("unexpected global file status: %s", out.GlobalFile.Status)
	}
	if out.ExampleFile.Status != workspaceFileUpdated {
		t.Fatalf("unexpected http example file status: %s", out.ExampleFile.Status)
	}
	if out.GRPCExampleFile.Status != workspaceFileUpdated {
		t.Fatalf("unexpected grpc example file status: %s", out.GRPCExampleFile.Status)
	}

	assertGlobalConfig(t, globalPath)
	assertFileContent(t, httpExamplePath, resources.ExampleHTTPTestSpecJSON())
	assertFileContent(t, grpcExamplePath, resources.ExampleGRPCTestSpecJSON())
}

func TestLoadGlobalConfigReturnsDefaultWhenMissing(t *testing.T) {
	root := t.TempDir()

	cfg, err := loadGlobalConfig(root)
	if err != nil {
		t.Fatalf("loadGlobalConfig returned error: %v", err)
	}
	if cfg.Schema != testspecGlobalSchemaV1 {
		t.Fatalf("unexpected schema: %s", cfg.Schema)
	}
	if len(cfg.Vars) != 0 {
		t.Fatalf("expected empty vars, got: %#v", cfg.Vars)
	}
}

func TestApplyGlobalVarsToSpecMergesDeepAndLetsSpecOverride(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, testspecWorkspaceDirName)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	globalPath := filepath.Join(workspaceDir, testspecGlobalFileName)
	rawGlobal := []byte(`{
	  "schema": "verix.global.v1",
	  "vars": {
	    "env": "local",
	    "auth": {
	      "token": "global-token",
	      "tenant": "tenant-a"
	    },
	    "list": ["global"],
	    "only_global": "yes"
	  }
	}`)
	if err := os.WriteFile(globalPath, rawGlobal, 0o600); err != nil {
		t.Fatalf("WriteFile global returned error: %v", err)
	}

	spec := &engine.TestSpec{
		Vars: map[string]any{
			"env": "dev",
			"auth": map[string]any{
				"token":   "spec-token",
				"project": "project-x",
			},
			"list":      []any{"spec"},
			"only_spec": "yes",
		},
	}

	if err := applyGlobalVarsToSpec(spec, root); err != nil {
		t.Fatalf("applyGlobalVarsToSpec returned error: %v", err)
	}

	want := map[string]any{
		"env": "dev",
		"auth": map[string]any{
			"token":   "spec-token",
			"tenant":  "tenant-a",
			"project": "project-x",
		},
		"list":        []any{"spec"},
		"only_global": "yes",
		"only_spec":   "yes",
	}
	if !reflect.DeepEqual(spec.Vars, want) {
		t.Fatalf("unexpected merged vars: %#v", spec.Vars)
	}
}

func TestLoadGlobalConfigRejectsUnknownSchema(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, testspecWorkspaceDirName)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	globalPath := filepath.Join(workspaceDir, testspecGlobalFileName)
	if err := os.WriteFile(globalPath, []byte(`{"schema":"verix.global.v2","vars":{}}`), 0o600); err != nil {
		t.Fatalf("WriteFile global returned error: %v", err)
	}

	if _, err := loadGlobalConfig(root); err == nil {
		t.Fatal("expected loadGlobalConfig to fail for unknown schema")
	}
}

func assertGlobalConfig(t *testing.T, path string) {
	t.Helper()
	rawGlobal, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile global returned error: %v", err)
	}
	var cfg GlobalConfig
	if err := json.Unmarshal(rawGlobal, &cfg); err != nil {
		t.Fatalf("Unmarshal global returned error: %v", err)
	}
	if cfg.Schema != testspecGlobalSchemaV1 {
		t.Fatalf("unexpected schema: %s", cfg.Schema)
	}
	if len(cfg.Vars) != 0 {
		t.Fatalf("expected empty vars, got: %#v", cfg.Vars)
	}
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s returned error: %v", path, err)
	}
	if string(raw) != want {
		t.Fatalf("unexpected file content for %s: %s", path, string(raw))
	}
}
