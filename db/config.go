package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// connectionEnvExample 展示 VERIX_DB_CONNECTIONS 的命名连接格式；数据库能力保持可选，未配置时仅在调用 DB Tool 时返回错误。
const connectionEnvExample = `{"analytics":{"driver":"mysql","dsn":"user:pass@tcp(127.0.0.1:3306)/app?parseTime=true"},"local":{"driver":"sqlite","dsn":"file:local.db"}}`

// parseConnectionConfigs 解析环境变量中的命名连接 JSON，并规范化每个连接配置。
func parseConnectionConfigs(envVar string, raw string) (map[string]ConnectionConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]ConnectionConfig{}, nil
	}

	// 顶层对象的键作为连接名，值保存驱动、DSN 和连接池配置。
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

// normalizeConnectionConfig 清理连接名和驱动，并校验 MySQL、SQLite 共用的必填配置。
func normalizeConnectionConfig(name string, cfg ConnectionConfig) (ConnectionConfig, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return ConnectionConfig{}, fmt.Errorf("connection name is required")
	}

	// 保留历史行为：未声明驱动的连接仍默认解释为 MySQL。
	cfg.Driver = strings.ToLower(strings.TrimSpace(cfg.Driver))
	if cfg.Driver == "" {
		cfg.Driver = DriverMySQL
	}
	if cfg.Driver != DriverMySQL && cfg.Driver != DriverSQLite {
		return ConnectionConfig{}, fmt.Errorf("connection %q uses unsupported driver %q", trimmedName, cfg.Driver)
	}

	cfg.DSN = strings.TrimSpace(cfg.DSN)
	if cfg.DSN == "" {
		return ConnectionConfig{}, fmt.Errorf("connection %q is missing dsn", trimmedName)
	}

	return cfg, nil
}

// normalizeRuntimeStateFile 校验从 initialize_db 或状态文件读取的运行时连接信息。
func normalizeRuntimeStateFile(state runtimeStateFile) (runtimeStateFile, error) {
	state.DatabaseURL = strings.TrimSpace(state.DatabaseURL)
	if state.DatabaseURL == "" {
		return runtimeStateFile{}, fmt.Errorf("runtime database state is missing database_url")
	}

	state.DBType = strings.ToLower(strings.TrimSpace(state.DBType))
	if state.DBType == "" {
		state.DBType = DriverMySQL
	}
	if state.DBType != DriverMySQL && state.DBType != DriverSQLite {
		return runtimeStateFile{}, fmt.Errorf("runtime database type %q is unsupported; supported types are %q and %q", state.DBType, DriverMySQL, DriverSQLite)
	}

	return state, nil
}

// runtimeConnectionConfig 将运行时状态转换为可打开的连接配置，并按数据库类型应用只读 DSN。
func runtimeConnectionConfig(state runtimeStateFile) (ConnectionConfig, runtimeStateFile, error) {
	normalizedState, err := normalizeRuntimeStateFile(state)
	if err != nil {
		return ConnectionConfig{}, runtimeStateFile{}, err
	}

	// 状态文件始终保留用户输入的原始 DSN，只在本次连接配置中追加只读参数。
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

// runtimeReadOnlyDSN 按数据库类型生成驱动层只读 DSN。
func runtimeReadOnlyDSN(databaseURL string, dbType string) (string, error) {
	switch dbType {
	case DriverMySQL:
		// MySQL 驱动使用连接参数在会话建立时启用 transaction_read_only。
		cfg, err := mysqldriver.ParseDSN(databaseURL)
		if err != nil {
			return "", fmt.Errorf("parse mysql dsn: %w", err)
		}
		if cfg.Params == nil {
			cfg.Params = make(map[string]string)
		}
		cfg.Params["transaction_read_only"] = "1"
		return cfg.FormatDSN(), nil
	case DriverSQLite:
		return sqliteReadOnlyDSN(databaseURL)
	default:
		return "", fmt.Errorf("runtime database type %q is unsupported for readonly mode", dbType)
	}
}

// sqliteReadOnlyDSN 将 SQLite 文件 DSN 转换为 mode=ro URI，确保数据库驱动在连接层拒绝写操作。
func sqliteReadOnlyDSN(databaseURL string) (string, error) {
	trimmedURL := strings.TrimSpace(databaseURL)
	base, rawQuery, _ := strings.Cut(trimmedURL, "?")
	if strings.EqualFold(base, ":memory:") || strings.EqualFold(base, "file::memory:") {
		return "", fmt.Errorf("readonly mode is not supported for an in-memory sqlite database")
	}

	// SQLite 的只读打开模式仅适用于 file: URI；普通文件路径需要先补齐 URI 前缀。
	if !strings.HasPrefix(strings.ToLower(base), "file:") {
		base = "file:" + base
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("parse sqlite dsn query: %w", err)
	}
	if strings.EqualFold(query.Get("mode"), "memory") {
		return "", fmt.Errorf("readonly mode is not supported for an in-memory sqlite database")
	}
	query.Set("mode", "ro")
	return base + "?" + query.Encode(), nil
}

// isSQLiteMemoryDSN 判断 DSN 是否指向 SQLite 内存数据库，用于选择安全的连接池配置。
func isSQLiteMemoryDSN(dsn string) bool {
	trimmedDSN := strings.TrimSpace(dsn)
	base, rawQuery, _ := strings.Cut(trimmedDSN, "?")
	if strings.EqualFold(base, ":memory:") || strings.EqualFold(base, "file::memory:") {
		return true
	}
	query, err := url.ParseQuery(rawQuery)
	return err == nil && strings.EqualFold(query.Get("mode"), "memory")
}

// missingConnectionConfigError 根据是否存在任意命名连接，生成针对性的配置提示。
func missingConnectionConfigError(envVar string, name string, hasConfiguredConnections bool) error {
	if !hasConfiguredConnections {
		return fmt.Errorf("no database connections configured; set %s to a JSON object keyed by connection name, for example %s", envVar, connectionEnvExample)
	}
	return fmt.Errorf("database connection %q is not configured in %s", name, envVar)
}
