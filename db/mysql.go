package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// mysqlExecutor 实现 MySQL 的 SQL 执行和 information_schema 元数据读取。
type mysqlExecutor struct {
	// db 是由 Manager 创建并统一管理生命周期的连接池。
	db *sql.DB
}

// newMySQLExecutor 使用已有连接池创建 MySQL 执行器。
func newMySQLExecutor(db *sql.DB) *mysqlExecutor {
	return &mysqlExecutor{db: db}
}

// Query 执行返回结果集的 MySQL 语句，并转换为统一查询结果。
func (m *mysqlExecutor) Query(ctx context.Context, sqlText string, args ...any) (*QueryResult, error) {
	rows, err := m.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// ColumnTypes 提供结果列名称及 MySQL 类型，供 Tool 返回结构化元数据。
	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}

	columns := make([]ResultColumn, len(columnTypes))
	for i, columnType := range columnTypes {
		columns[i] = ResultColumn{
			Name: columnType.Name(),
			Type: strings.ToLower(columnType.DatabaseTypeName()),
		}
	}

	// Scan 目标在行间复用，每次读取后复制并规范化为独立结果行。
	scanValues := make([]any, len(columns))
	scanTargets := make([]any, len(columns))
	for i := range scanTargets {
		scanTargets[i] = &scanValues[i]
	}

	resultRows := make([][]any, 0)
	for rows.Next() {
		if err := rows.Scan(scanTargets...); err != nil {
			return nil, err
		}
		row := make([]any, len(scanValues))
		for i, value := range scanValues {
			row[i] = normalizeSQLValue(value)
		}
		resultRows = append(resultRows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &QueryResult{
		Columns:  columns,
		Rows:     resultRows,
		RowCount: len(resultRows),
	}, nil
}

// Exec 执行不返回结果集的 MySQL 语句，并读取影响行数和最后插入 ID。
func (m *mysqlExecutor) Exec(ctx context.Context, sqlText string, args ...any) (*ExecResult, error) {
	result, err := m.db.ExecContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}

	// 并非所有语句都支持 LastInsertId，不支持时保持 nil 而不影响执行结果。
	var lastInsertID *int64
	if id, err := result.LastInsertId(); err == nil {
		lastInsertID = &id
	}

	return &ExecResult{
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

// ListTables 使用 SHOW TABLES 返回当前 MySQL 数据库中的表名。
func (m *mysqlExecutor) ListTables(ctx context.Context) ([]string, error) {
	rows, err := m.db.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tables := make([]string, 0)
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, err
		}
		tables = append(tables, tableName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 排序保证不同 MySQL 版本和连接设置下输出顺序稳定。
	sort.Strings(tables)
	return tables, nil
}

// GetSchema 从 information_schema 返回当前数据库的表名和列名概览。
func (m *mysqlExecutor) GetSchema(ctx context.Context) (*Schema, error) {
	tables, err := m.ListTables(ctx)
	if err != nil {
		return nil, err
	}

	// information_schema.columns 按表和列序号返回，保留建表时的列顺序。
	rows, err := m.db.QueryContext(ctx, `
SELECT TABLE_NAME, COLUMN_NAME
FROM information_schema.columns
WHERE table_schema = DATABASE()
ORDER BY TABLE_NAME, ORDINAL_POSITION`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columnsByTable := make(map[string][]string)
	for rows.Next() {
		var tableName string
		var columnName string
		if err := rows.Scan(&tableName, &columnName); err != nil {
			return nil, err
		}
		columnsByTable[tableName] = append(columnsByTable[tableName], columnName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	schemaTables := make([]SchemaTable, 0, len(tables))
	for _, tableName := range tables {
		schemaTables = append(schemaTables, SchemaTable{
			Name:    tableName,
			Columns: columnsByTable[tableName],
		})
	}

	return &Schema{Tables: schemaTables}, nil
}

// DescribeTable 从 information_schema 读取指定 MySQL 表的列、外键和索引。
func (m *mysqlExecutor) DescribeTable(ctx context.Context, table string) (*TableSchema, error) {
	// 第一步读取列定义，并建立列名到结果下标的映射供外键回填。
	columnRows, err := m.db.QueryContext(ctx, `
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA
FROM information_schema.columns
WHERE table_schema = DATABASE() AND table_name = ?
ORDER BY ORDINAL_POSITION`, table)
	if err != nil {
		return nil, err
	}
	defer columnRows.Close()

	columns := make([]TableColumn, 0)
	columnIndex := make(map[string]int)
	for columnRows.Next() {
		var name string
		var dataType string
		var isNullable string
		var columnKey string
		var defaultValue sql.NullString
		var extra string
		if err := columnRows.Scan(&name, &dataType, &isNullable, &columnKey, &defaultValue, &extra); err != nil {
			return nil, err
		}

		column := TableColumn{
			Name:         name,
			Type:         dataType,
			Nullable:     strings.EqualFold(isNullable, "YES"),
			IsPrimaryKey: strings.EqualFold(columnKey, "PRI"),
			Extra:        extra,
		}
		if defaultValue.Valid {
			value := defaultValue.String
			column.DefaultValue = &value
		}

		columns = append(columns, column)
		columnIndex[name] = len(columns) - 1
	}
	if err := columnRows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("table %q not found in current database", table)
	}

	// 第二步读取外键，并将引用目标合并到对应列。
	foreignKeyRows, err := m.db.QueryContext(ctx, `
SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
FROM information_schema.key_column_usage
WHERE table_schema = DATABASE() AND table_name = ? AND REFERENCED_TABLE_NAME IS NOT NULL
ORDER BY ORDINAL_POSITION`, table)
	if err != nil {
		return nil, err
	}
	defer foreignKeyRows.Close()

	for foreignKeyRows.Next() {
		var columnName string
		var refTable string
		var refColumn string
		if err := foreignKeyRows.Scan(&columnName, &refTable, &refColumn); err != nil {
			return nil, err
		}
		idx, ok := columnIndex[columnName]
		if !ok {
			continue
		}
		columns[idx].IsForeignKey = true
		columns[idx].References = &ForeignKeyReference{
			Table:  refTable,
			Column: refColumn,
		}
	}
	if err := foreignKeyRows.Err(); err != nil {
		return nil, err
	}

	// 第三步读取索引；复合索引的多行按索引名聚合并保留列顺序。
	indexRows, err := m.db.QueryContext(ctx, `
SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME
FROM information_schema.statistics
WHERE table_schema = DATABASE() AND table_name = ?
ORDER BY INDEX_NAME, SEQ_IN_INDEX`, table)
	if err != nil {
		return nil, err
	}
	defer indexRows.Close()

	indexes := make([]Index, 0)
	indexByName := make(map[string]int)
	for indexRows.Next() {
		var indexName string
		var nonUnique int
		var columnName string
		if err := indexRows.Scan(&indexName, &nonUnique, &columnName); err != nil {
			return nil, err
		}
		if idx, ok := indexByName[indexName]; ok {
			indexes[idx].Columns = append(indexes[idx].Columns, columnName)
			continue
		}
		indexes = append(indexes, Index{
			Name:    indexName,
			Columns: []string{columnName},
			Unique:  nonUnique == 0,
		})
		indexByName[indexName] = len(indexes) - 1
	}
	if err := indexRows.Err(); err != nil {
		return nil, err
	}

	return &TableSchema{
		Table:   table,
		Columns: columns,
		Indexes: indexes,
	}, nil
}

// normalizeSQLValue 将数据库驱动值转换为稳定且可 JSON 序列化的值。
func normalizeSQLValue(value any) any {
	// []byte 默认转换为文本，时间值统一输出 RFC3339Nano。
	switch v := value.(type) {
	case nil:
		return nil
	case []byte:
		return string(v)
	case time.Time:
		return v.Format(time.RFC3339Nano)
	default:
		return v
	}
}
