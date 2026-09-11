package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gormmysql "gorm.io/driver/mysql"
	gormsqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	// 为 GORM SQLite Dialector 注册纯 Go sqlite 驱动，插件运行时不依赖 CGO。
	_ "modernc.org/sqlite"
)

const (
	// databaseTypeMySQL 是兼容旧调用的默认数据库类型。
	databaseTypeMySQL = "mysql"
	// databaseTypeSQLite 是 SQLite 数据库类型。
	databaseTypeSQLite = "sqlite"
)

// columnInfo 是通过 GORM Migrator 读取并规范化后的数据库列信息。
type columnInfo struct {
	// Name 是原始数据库列名。
	Name string
	// DataType 是不包含长度等修饰信息的数据库类型。
	DataType string
	// ColumnType 是包含长度或精度的完整数据库类型。
	ColumnType string
	// Nullable 表示列是否允许 NULL。
	Nullable bool
	// ColumnKey 使用 PRI 标记主键，以兼容现有代码生成逻辑。
	ColumnKey string
	// Default 是数据库返回的默认值表达式。
	Default string
	// Extra 保存 auto_increment 等附加属性。
	Extra string
	// Comment 是数据库列注释；SQLite 通常不提供该信息。
	Comment string
}

// normalizeDatabaseType 规范化数据库类型；空值默认使用 MySQL 以兼容旧版调用。
func normalizeDatabaseType(databaseType string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(databaseType))
	if normalized == "" {
		return databaseTypeMySQL, nil
	}
	switch normalized {
	case databaseTypeMySQL, databaseTypeSQLite:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported db_type %q: want mysql or sqlite", databaseType)
	}
}

// connect 使用指定数据库类型和 DSN 创建 GORM 连接，并在返回前验证数据库可访问。
func connect(ctx context.Context, databaseType string, dsn string) (*gorm.DB, error) {
	normalizedType, err := normalizeDatabaseType(databaseType)
	if err != nil {
		return nil, err
	}
	trimmedDSN := strings.TrimSpace(dsn)
	if trimmedDSN == "" {
		return nil, fmt.Errorf("dsn is required")
	}

	// Dialector 隔离数据库差异；上层生成流程只依赖 GORM Migrator，不包含方言 SQL。
	var dialector gorm.Dialector
	switch normalizedType {
	case databaseTypeMySQL:
		dialector = gormmysql.New(gormmysql.Config{
			DSN:                       trimmedDSN,
			SkipInitializeWithVersion: true,
		})
	case databaseTypeSQLite:
		// DriverName 指向 modernc 注册的 sqlite，避免使用默认的 CGO sqlite3 驱动。
		dialector = gormsqlite.New(gormsqlite.Config{DriverName: databaseTypeSQLite, DSN: trimmedDSN})
	}

	// 插件通过 stdout 传输 RPC，必须关闭 GORM SQL 日志，避免日志破坏协议帧。
	database, err := gorm.Open(dialector, &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := database.DB()
	if err != nil {
		return nil, err
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return database.WithContext(ctx), nil
}

// closeDatabase 关闭 GORM 持有的底层 database/sql 连接池。
func closeDatabase(database *gorm.DB) {
	if database == nil {
		return
	}
	sqlDB, err := database.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

// listTables 通过 GORM Migrator 列出业务表，并过滤 SQLite 内部表。
func listTables(ctx context.Context, database *gorm.DB) ([]string, error) {
	tables, err := database.WithContext(ctx).Migrator().GetTables()
	if err != nil {
		return nil, err
	}

	// 排除 sqlite_sequence 等内部表，同时去重并排序，保证不同方言返回一致。
	seen := make(map[string]struct{}, len(tables))
	result := make([]string, 0, len(tables))
	for _, table := range tables {
		table = strings.TrimSpace(table)
		if table == "" || strings.HasPrefix(strings.ToLower(table), "sqlite_") {
			continue
		}
		if _, exists := seen[table]; exists {
			continue
		}
		seen[table] = struct{}{}
		result = append(result, table)
	}
	sort.Strings(result)
	return result, nil
}

// readTableColumns 通过 GORM Migrator 读取单表列信息，并转换为生成器内部结构。
func readTableColumns(ctx context.Context, database *gorm.DB, table string) ([]columnInfo, error) {
	trimmedTable := strings.TrimSpace(table)
	if trimmedTable == "" {
		return nil, fmt.Errorf("table is required")
	}
	migrator := database.WithContext(ctx).Migrator()
	if !migrator.HasTable(trimmedTable) {
		return nil, fmt.Errorf("table %q not found in current database", trimmedTable)
	}

	// ColumnTypes 由各 GORM Dialector 适配 information_schema 或 SQLite DDL/PRAGMA。
	columnTypes, err := migrator.ColumnTypes(trimmedTable)
	if err != nil {
		return nil, err
	}
	columns := make([]columnInfo, 0, len(columnTypes))
	for _, columnType := range columnTypes {
		dataType := strings.ToLower(strings.TrimSpace(columnType.DatabaseTypeName()))
		fullType, ok := columnType.ColumnType()
		if !ok || strings.TrimSpace(fullType) == "" {
			fullType = dataType
		}

		// 元数据缺失时默认允许 NULL，避免生成错误的 not null 约束。
		nullable := true
		if value, ok := columnType.Nullable(); ok {
			nullable = value
		}
		primaryKey, _ := columnType.PrimaryKey()
		autoIncrement, _ := columnType.AutoIncrement()
		defaultValue, hasDefault := columnType.DefaultValue()
		comment, _ := columnType.Comment()

		column := columnInfo{
			Name:       columnType.Name(),
			DataType:   dataType,
			ColumnType: strings.ToLower(fullType),
			Nullable:   nullable,
			Comment:    comment,
		}
		if primaryKey {
			column.ColumnKey = "PRI"
		}
		if autoIncrement {
			column.Extra = "auto_increment"
		}
		if hasDefault {
			column.Default = defaultValue
		}
		columns = append(columns, column)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("table %q has no readable columns", trimmedTable)
	}
	return columns, nil
}
