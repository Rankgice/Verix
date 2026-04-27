package db

import (
	"encoding/json"
	"fmt"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
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

		normalizedCfg, err := normalizeConnectionConfig(trimmedName, cfg)
		if err != nil {
			return nil, err
		}
		normalized[trimmedName] = normalizedCfg
	}

	return normalized, nil
}

func normalizeConnectionConfig(name string, cfg ConnectionConfig) (ConnectionConfig, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return ConnectionConfig{}, fmt.Errorf("connection name is required")
	}

	cfg.Driver = strings.ToLower(strings.TrimSpace(cfg.Driver))
	if cfg.Driver == "" {
		cfg.Driver = DriverMySQL
	}
	if cfg.Driver != DriverMySQL {
		return ConnectionConfig{}, fmt.Errorf("connection %q uses unsupported driver %q", trimmedName, cfg.Driver)
	}

	cfg.DSN = strings.TrimSpace(cfg.DSN)
	if cfg.DSN == "" {
		return ConnectionConfig{}, fmt.Errorf("connection %q is missing dsn", trimmedName)
	}

	return cfg, nil
}

func normalizeRuntimeStateFile(state runtimeStateFile) (runtimeStateFile, error) {
	state.DatabaseURL = strings.TrimSpace(state.DatabaseURL)
	if state.DatabaseURL == "" {
		return runtimeStateFile{}, fmt.Errorf("runtime database state is missing database_url")
	}

	state.DBType = strings.ToLower(strings.TrimSpace(state.DBType))
	if state.DBType == "" {
		state.DBType = DriverMySQL
	}
	if state.DBType != DriverMySQL {
		return runtimeStateFile{}, fmt.Errorf("runtime database type %q is unsupported; only %q is supported", state.DBType, DriverMySQL)
	}

	return state, nil
}

func runtimeConnectionConfig(state runtimeStateFile) (ConnectionConfig, runtimeStateFile, error) {
	normalizedState, err := normalizeRuntimeStateFile(state)
	if err != nil {
		return ConnectionConfig{}, runtimeStateFile{}, err
	}

	effectiveDSN := normalizedState.DatabaseURL
	if normalizedState.IsReadOnly {
		effectiveDSN, err = runtimeReadOnlyDSN(effectiveDSN, normalizedState.DBType)
		if err != nil {
			return ConnectionConfig{}, runtimeStateFile{}, err
		}
	}

	cfg, err := normalizeConnectionConfig(runtimeConnectionName, ConnectionConfig{
		Driver:       normalizedState.DBType,
		DSN:          effectiveDSN,
		MaxOpenConns: DefaultRuntimeMaxOpenConns,
		MaxIdleConns: DefaultRuntimeMaxIdleConns,
	})
	if err != nil {
		return ConnectionConfig{}, runtimeStateFile{}, err
	}

	return cfg, normalizedState, nil
}

func runtimeReadOnlyDSN(databaseURL string, dbType string) (string, error) {
	switch dbType {
	case DriverMySQL:
		cfg, err := mysqldriver.ParseDSN(databaseURL)
		if err != nil {
			return "", fmt.Errorf("parse mysql dsn: %w", err)
		}
		if cfg.Params == nil {
			cfg.Params = make(map[string]string)
		}
		cfg.Params["transaction_read_only"] = "1"
		return cfg.FormatDSN(), nil
	default:
		return "", fmt.Errorf("runtime database type %q is unsupported for readonly mode", dbType)
	}
}

func missingConnectionConfigError(envVar string, name string, hasConfiguredConnections bool) error {
	if !hasConfiguredConnections {
		return fmt.Errorf("no database connections configured; set %s to a JSON object keyed by connection name, for example %s", envVar, connectionEnvExample)
	}
	return fmt.Errorf("database connection %q is not configured in %s", name, envVar)
}
