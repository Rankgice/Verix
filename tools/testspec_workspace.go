package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"verix/engine"
	"verix/resources"
)

const (
	testspecWorkspaceDirName    = ".mcp"
	testspecGlobalFileName      = "global.json"
	testspecExampleFileName     = "example.json"
	testspecGRPCExampleFileName = "example-grpc.json"

	testspecGlobalSchemaV1 = "verix.global.v1"

	workspaceFileCreated  = "created"
	workspaceFileUpdated  = "updated"
	workspaceFileExisting = "existing"
)

type GlobalConfig struct {
	Schema string         `json:"schema,omitempty"`
	Vars   map[string]any `json:"vars"`
}

func initializeTestSpecWorkspace(root string, overwrite bool) (*InitializeTestSpecData, error) {
	workspaceRoot, err := resolveWorkspaceRoot(root)
	if err != nil {
		return nil, err
	}

	directory := testspecWorkspaceDirPath(workspaceRoot)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create testspec workspace directory %q: %w", directory, err)
	}

	globalContent, err := defaultGlobalConfigJSON()
	if err != nil {
		return nil, err
	}
	globalPath := testspecGlobalFilePath(workspaceRoot)
	globalStatus, err := writeWorkspaceFile(globalPath, globalContent, overwrite)
	if err != nil {
		return nil, err
	}

	httpExamplePath := testspecExampleFilePath(workspaceRoot)
	httpExampleStatus, err := writeWorkspaceFile(httpExamplePath, []byte(resources.ExampleHTTPTestSpecJSON()), overwrite)
	if err != nil {
		return nil, err
	}

	grpcExamplePath := testspecGRPCExampleFilePath(workspaceRoot)
	grpcExampleStatus, err := writeWorkspaceFile(grpcExamplePath, []byte(resources.ExampleGRPCTestSpecJSON()), overwrite)
	if err != nil {
		return nil, err
	}

	return &InitializeTestSpecData{
		Directory: directory,
		GlobalFile: WorkspaceFile{
			Path:   globalPath,
			Status: globalStatus,
		},
		ExampleFile: WorkspaceFile{
			Path:   httpExamplePath,
			Status: httpExampleStatus,
		},
		GRPCExampleFile: WorkspaceFile{
			Path:   grpcExamplePath,
			Status: grpcExampleStatus,
		},
	}, nil
}

func applyGlobalVarsToSpec(spec *engine.TestSpec, root string) error {
	if spec == nil {
		return fmt.Errorf("spec is nil")
	}

	config, err := loadGlobalConfig(root)
	if err != nil {
		return err
	}
	spec.Vars = mergeVarMaps(config.Vars, spec.Vars)
	return nil
}

func loadGlobalConfig(root string) (*GlobalConfig, error) {
	workspaceRoot, err := resolveWorkspaceRoot(root)
	if err != nil {
		return nil, err
	}

	path := testspecGlobalFilePath(workspaceRoot)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := defaultGlobalConfig()
			return &cfg, nil
		}
		return nil, fmt.Errorf("read global testspec config %q: %w", path, err)
	}

	var cfg GlobalConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse global testspec config %q: %w", path, err)
	}

	normalized, err := normalizeGlobalConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid global testspec config %q: %w", path, err)
	}
	return &normalized, nil
}

func normalizeGlobalConfig(cfg GlobalConfig) (GlobalConfig, error) {
	cfg.Schema = strings.TrimSpace(cfg.Schema)
	if cfg.Schema == "" {
		cfg.Schema = testspecGlobalSchemaV1
	}
	if cfg.Schema != testspecGlobalSchemaV1 {
		return GlobalConfig{}, fmt.Errorf("unsupported schema %q", cfg.Schema)
	}
	if cfg.Vars == nil {
		cfg.Vars = map[string]any{}
	}
	return cfg, nil
}

func defaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
		Schema: testspecGlobalSchemaV1,
		Vars:   map[string]any{},
	}
}

func defaultGlobalConfigJSON() ([]byte, error) {
	raw, err := json.MarshalIndent(defaultGlobalConfig(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal default global testspec config: %w", err)
	}
	return append(raw, byte(10)), nil
}

func writeWorkspaceFile(path string, content []byte, overwrite bool) (string, error) {
	_, err := os.Stat(path)
	if err == nil {
		if !overwrite {
			return workspaceFileExisting, nil
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return "", fmt.Errorf("write workspace file %q: %w", path, err)
		}
		return workspaceFileUpdated, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat workspace file %q: %w", path, err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return "", fmt.Errorf("write workspace file %q: %w", path, err)
	}
	return workspaceFileCreated, nil
}

func mergeVarMaps(base, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return map[string]any{}
	}

	out := make(map[string]any, len(base)+len(override))
	for key, value := range base {
		out[key] = cloneVarValue(value)
	}
	for key, value := range override {
		if existing, ok := out[key]; ok {
			if merged, ok := mergeVarValue(existing, value); ok {
				out[key] = merged
				continue
			}
		}
		out[key] = cloneVarValue(value)
	}
	return out
}

func mergeVarValue(base, override any) (any, bool) {
	baseMap, ok := base.(map[string]any)
	if !ok {
		return nil, false
	}
	overrideMap, ok := override.(map[string]any)
	if !ok {
		return nil, false
	}
	return mergeVarMaps(baseMap, overrideMap), true
}

func cloneVarValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for key, value := range t {
			out[key] = cloneVarValue(value)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cloneVarValue(t[i])
		}
		return out
	default:
		return v
	}
}

func resolveWorkspaceRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve workspace root: %w", err)
		}
		root = cwd
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve workspace root %q: %w", root, err)
	}
	return absRoot, nil
}

func testspecWorkspaceDirPath(root string) string {
	return filepath.Join(root, testspecWorkspaceDirName)
}

func testspecGlobalFilePath(root string) string {
	return filepath.Join(testspecWorkspaceDirPath(root), testspecGlobalFileName)
}

func testspecExampleFilePath(root string) string {
	return filepath.Join(testspecWorkspaceDirPath(root), testspecExampleFileName)
}

func testspecGRPCExampleFilePath(root string) string {
	return filepath.Join(testspecWorkspaceDirPath(root), testspecGRPCExampleFileName)
}
