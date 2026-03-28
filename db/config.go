package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VERIX_DB_CONNECTIONS is a JSON object keyed by connection name so DB tools can
// stay optional: startup succeeds without it, and DB tool calls fail lazily with
// a clear runtime error when no connection is configured.
const connectionEnvExample = `{"analytics":{"driver":"mysql","dsn":"user:pass@tcp(127.0.0.1:3306)/app?parseTime=true"}}`

func parseConnectionConfigs(envVar string, raw string) (map[string]ConnectionConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]ConnectionConfig{}, nil
	}

	var configs map[string]ConnectionConfig
	if err := json.Unmarshal([]byte(raw), &configs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", envVar, err)
	}

	normalized := make(map[string]ConnectionConfig, len(configs))
	for name, cfg := range configs {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			return nil, fmt.Errorf("%s contains an empty connection name", envVar)
		}

		cfg.Driver = strings.ToLower(strings.TrimSpace(cfg.Driver))
		if cfg.Driver == "" {
			cfg.Driver = DriverMySQL
		}
		if cfg.Driver != DriverMySQL {
			return nil, fmt.Errorf("connection %q uses unsupported driver %q", trimmedName, cfg.Driver)
		}
		if strings.TrimSpace(cfg.DSN) == "" {
			return nil, fmt.Errorf("connection %q is missing dsn", trimmedName)
		}

		normalized[trimmedName] = cfg
	}

	return normalized, nil
}

func missingConnectionConfigError(envVar string, name string, hasConfiguredConnections bool) error {
	if !hasConfiguredConnections {
		return fmt.Errorf("no database connections configured; set %s to a JSON object keyed by connection name, for example %s", envVar, connectionEnvExample)
	}
	return fmt.Errorf("database connection %q is not configured in %s", name, envVar)
}
