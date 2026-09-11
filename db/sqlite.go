package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	// 注册名为 sqlite 的纯 Go database/sql 驱动，避免部署环境依赖 CGO。
	_ "modernc.org/sqlite"
)

// sqliteExecutor 实现 SQLite 的 SQL 执行和 Schema 元数据读取能力。
type sqliteExecutor struct {
	// db 是由 Manager 创建并统一管理生命周期的连接池。
	db *sql.DB
}

// newSQLiteExecutor 使用已有连接池创建 SQLite 执行器。
func newSQLiteExecutor(db *sql.DB) *sqliteExecutor {
	return &sqliteExecutor{db: db}
}

// Query 执行返回结果集的 SQLite 语句，并将驱动值转换为可 JSON 序列化的数据。
func (s *sqliteExecutor) Query(ctx context.Context, sqlText string, args ...any) (*QueryResult, error) {
	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// ColumnTypes 同时提供列名和 SQLite 声明类型，供 Tool 返回结构化元数据。
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

	// database/sql 要求 Scan 接收指针，因此先复用目标切片，再为每一行复制独立结果。
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

// Exec 执行不返回结果集的 SQLite 语句，并读取影响行数和可用的自增主键。
func (s *sqliteExecutor) Exec(ctx context.Context, sqlText string, args ...any) (*ExecResult, error) {
	result, err := s.db.ExecContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	var lastInsertID *int64
	if id, err := result.LastInsertId(); err == nil {
		lastInsertID = &id
	}

	return &ExecResult{
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

// ListTables 返回当前 SQLite 主 Schema 中的业务表，并过滤 sqlite_ 前缀的内部表。
func (s *sqliteExecutor) ListTables(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name
FROM sqlite_schema
WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
ORDER BY name`)
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

	// SQL 已经排序，此处再次排序可确保未来查询调整后仍保持稳定输出。
	sort.Strings(tables)
	return tables, nil
}

// GetSchema 返回 SQLite 数据库中的表名及其按声明顺序排列的列名。
func (s *sqliteExecutor) GetSchema(ctx context.Context) (*Schema, error) {
	tables, err := s.ListTables(ctx)
	if err != nil {
		return nil, err
	}

	schemaTables := make([]SchemaTable, 0, len(tables))
	for _, tableName := range tables {
		// pragma_table_xinfo(?) 支持参数绑定，避免将表名拼入 SQL 造成标识符转义问题。
		rows, err := s.db.QueryContext(ctx, `
SELECT name
FROM pragma_table_xinfo(?)
ORDER BY cid`, tableName)
		if err != nil {
			return nil, err
		}

		columns := make([]string, 0)
		for rows.Next() {
			var columnName string
			if err := rows.Scan(&columnName); err != nil {
				_ = rows.Close()
				return nil, err
			}
			columns = append(columns, columnName)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close()

		schemaTables = append(schemaTables, SchemaTable{Name: tableName, Columns: columns})
	}

	return &Schema{Tables: schemaTables}, nil
}

// DescribeTable 返回 SQLite 表的列、主键、外键和索引信息。
func (s *sqliteExecutor) DescribeTable(ctx context.Context, table string) (*TableSchema, error) {
	columns, primaryKeyColumns, err := s.describeColumns(ctx, table)
	if err != nil {
		return nil, err
	}

	// 外键结果会回填到对应列，保持与 MySQL DescribeTable 的统一返回结构。
	if err := s.applyForeignKeys(ctx, table, columns); err != nil {
		return nil, err
	}
	indexes, err := s.describeIndexes(ctx, table, primaryKeyColumns)
	if err != nil {
		return nil, err
	}

	return &TableSchema{
		Table:   table,
		Columns: columns,
		Indexes: indexes,
	}, nil
}

// describeColumns 读取 SQLite 列定义，并额外返回按主键序号排序的主键列。
func (s *sqliteExecutor) describeColumns(ctx context.Context, table string) ([]TableColumn, []string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name, type, "notnull", dflt_value, pk, hidden
FROM pragma_table_xinfo(?)
ORDER BY cid`, table)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	columns := make([]TableColumn, 0)
	primaryKeyByOrder := make(map[int]string)
	maxPrimaryKeyOrder := 0
	for rows.Next() {
		var name string
		var dataType string
		var notNull int
		var defaultValue sql.NullString
		var primaryKeyOrder int
		var hidden int
		if err := rows.Scan(&name, &dataType, &notNull, &defaultValue, &primaryKeyOrder, &hidden); err != nil {
			return nil, nil, err
		}

		column := TableColumn{
			Name:         name,
			Type:         strings.ToLower(dataType),
			Nullable:     notNull == 0 && primaryKeyOrder == 0,
			IsPrimaryKey: primaryKeyOrder > 0,
			Extra:        sqliteColumnExtra(hidden),
		}
		if defaultValue.Valid {
			value := defaultValue.String
			column.DefaultValue = &value
		}
		columns = append(columns, column)

		if primaryKeyOrder > 0 {
			primaryKeyByOrder[primaryKeyOrder] = name
			if primaryKeyOrder > maxPrimaryKeyOrder {
				maxPrimaryKeyOrder = primaryKeyOrder
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(columns) == 0 {
		return nil, nil, fmt.Errorf("table %q not found in current database", table)
	}

	primaryKeyColumns := make([]string, 0, maxPrimaryKeyOrder)
	for order := 1; order <= maxPrimaryKeyOrder; order++ {
		if name, ok := primaryKeyByOrder[order]; ok {
			primaryKeyColumns = append(primaryKeyColumns, name)
		}
	}
	return columns, primaryKeyColumns, nil
}

// applyForeignKeys 读取 SQLite 外键列表，并将引用关系标记到对应列定义中。
func (s *sqliteExecutor) applyForeignKeys(ctx context.Context, table string, columns []TableColumn) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT "from", "table", "to"
FROM pragma_foreign_key_list(?)
ORDER BY id, seq`, table)
	if err != nil {
		return err
	}
	defer rows.Close()

	columnIndex := make(map[string]int, len(columns))
	for i, column := range columns {
		columnIndex[column.Name] = i
	}
	for rows.Next() {
		var columnName string
		var refTable string
		var refColumn sql.NullString
		if err := rows.Scan(&columnName, &refTable, &refColumn); err != nil {
			return err
		}
		index, ok := columnIndex[columnName]
		if !ok {
			continue
		}
		columns[index].IsForeignKey = true
		columns[index].References = &ForeignKeyReference{
			Table:  refTable,
			Column: refColumn.String,
		}
	}
	return rows.Err()
}

// describeIndexes 读取 SQLite 索引及其列，并补充可能未出现在 pragma_index_list 中的行主键。
func (s *sqliteExecutor) describeIndexes(ctx context.Context, table string, primaryKeyColumns []string) ([]Index, error) {
	indexes := make([]Index, 0)
	if len(primaryKeyColumns) > 0 {
		// INTEGER PRIMARY KEY 通常映射到 rowid，不会出现在索引列表中，因此统一合成 PRIMARY 项。
		indexes = append(indexes, Index{Name: "PRIMARY", Columns: primaryKeyColumns, Unique: true})
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT name, "unique", origin
FROM pragma_index_list(?)
ORDER BY seq`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// sqliteIndex 暂存索引名称和唯一性，关闭列表结果集后再查询每个索引的列。
	type sqliteIndex struct {
		name   string
		unique bool
	}
	metadata := make([]sqliteIndex, 0)
	for rows.Next() {
		var name string
		var unique int
		var origin string
		if err := rows.Scan(&name, &unique, &origin); err != nil {
			return nil, err
		}
		// 已经用稳定的 PRIMARY 名称表示主键，跳过 SQLite 自动生成的同义主键索引。
		if origin == "pk" {
			continue
		}
		metadata = append(metadata, sqliteIndex{name: name, unique: unique != 0})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, item := range metadata {
		columnRows, err := s.db.QueryContext(ctx, `
SELECT name
FROM pragma_index_info(?)
ORDER BY seqno`, item.name)
		if err != nil {
			return nil, err
		}
		columns := make([]string, 0)
		for columnRows.Next() {
			var columnName sql.NullString
			if err := columnRows.Scan(&columnName); err != nil {
				_ = columnRows.Close()
				return nil, err
			}
			// 表达式索引没有直接列名，返回结构无法准确表达时不制造虚假名称。
			if columnName.Valid {
				columns = append(columns, columnName.String)
			}
		}
		if err := columnRows.Err(); err != nil {
			_ = columnRows.Close()
			return nil, err
		}
		_ = columnRows.Close()
		indexes = append(indexes, Index{Name: item.name, Columns: columns, Unique: item.unique})
	}

	return indexes, nil
}

// sqliteColumnExtra 将 pragma_table_xinfo 的 hidden 标记转换为可读的附加列属性。
func sqliteColumnExtra(hidden int) string {
	switch hidden {
	case 1:
		return "hidden"
	case 2:
		return "generated virtual"
	case 3:
		return "generated stored"
	default:
		return ""
	}
}
