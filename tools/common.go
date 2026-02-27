package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"verix/engine"
)

type SpecInput struct {
	SpecPath string `json:"spec_path,omitempty" jsonschema:"Path to TestSpec JSON file"`
	SpecJSON string `json:"spec_json,omitempty" jsonschema:"Raw TestSpec JSON content"`
}

func loadSpec(in SpecInput) (*engine.TestSpec, error) {
	var data []byte
	switch {
	case strings.TrimSpace(in.SpecPath) != "":
		b, err := os.ReadFile(in.SpecPath)
		if err != nil {
			return nil, fmt.Errorf("read spec_path: %w", err)
		}
		data = b
	case strings.TrimSpace(in.SpecJSON) != "":
		data = []byte(in.SpecJSON)
	default:
		return nil, errors.New("either spec_path or spec_json is required")
	}

	var spec engine.TestSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("decode spec: %w", err)
	}
	return &spec, nil
}
