package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// columnInfo 是从 information_schema 读到的原始列信息。
type columnInfo struct {
	Name       string
	DataType   string
	ColumnType string
	Nullable   bool
	ColumnKey  string
	Default    string
	Extra      string
	Comment    string
}

// FieldModel 是传给模板的单个字段描述。
type FieldModel struct {
	Column    string // 数据库列名，如 group_id
	GoName    string // Go 字段名，如 GroupId
	GoType    string // Go 类型，如 int64
	JSONName  string // JSON 名，如 group_id
	GormTag   string // 完整 GORM tag 内容，如 column:group_id;not null
	Comment   string // 字段注释
	OmitEmpty bool   // 是否在 json tag 加 omitempty
	VarName   string // 用作变量的名字，如 id
	ZeroValue string // 等值比较用的零值，如 "0" 或 `""`
}

// TimeRangeField 描述时间字段的查询范围参数。
type TimeRangeField struct {
	GoName    string // 如 CreatedAt
	Column    string // 如 created_at
	JSONStart string // 如 created_at_start
	JSONEnd   string // 如 created_at_end
}

// TableModel 是传给模板的单个表的数据模型。
type TableModel struct {
	PackageName       string
	ImportBlock       string
	EntityName        string // 如 User
	TableName         string // 如 user
	LowerEntityName   string // 如 user（用于排序白名单变量名）
	Comment           string // 表注释，用于注释和日志
	VarName           string // 单数变量名，如 user
	VarNameList       string // 复数变量名，如 users
	PrimaryKey        *FieldModel
	Fields            []FieldModel     // entity 的全部字段（含主键）
	SortFields        []FieldModel     // 可排序字段（主键 + 可排序普通字段）
	QueryStringFields []FieldModel     // 用于 LIKE 过滤的字符串字段
	IntegerFields     []FieldModel     // 用于等值和 IN 过滤的整形字段（不含主键）
	TimeFields        []TimeRangeField // 用于范围过滤的时间字段
	UpdatableFields   []FieldModel     // 更新参数里的非主键字段
}

// connect 使用 DSN 打开 MySQL 连接并做连通性校验。
func connect(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// listTables 返回当前数据库的所有表名。
func listTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

// readTableColumns 读取单张表的字段信息，按定义顺序返回。
func readTableColumns(ctx context.Context, db *sql.DB, table string) ([]columnInfo, error) {
	rows, err := db.QueryContext(ctx, `
SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA, COLUMN_COMMENT
FROM information_schema.columns
WHERE table_schema = DATABASE() AND table_name = ?
ORDER BY ORDINAL_POSITION`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []columnInfo
	for rows.Next() {
		var c columnInfo
		var nullable string
		var def sql.NullString
		if err := rows.Scan(&c.Name, &c.DataType, &c.ColumnType, &nullable, &c.ColumnKey, &def, &c.Extra, &c.Comment); err != nil {
			return nil, err
		}
		c.Nullable = strings.EqualFold(nullable, "YES")
		if def.Valid {
			c.Default = def.String
		}
		columns = append(columns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("table %q not found in current database", table)
	}
	return columns, nil
}

// goTypeFor 将 MySQL 类型映射为 Go 类型。
func goTypeFor(dataType, columnType string) string {
	dt := strings.ToLower(dataType)
	switch dt {
	case "bigint":
		return "int64"
	case "int", "integer", "mediumint":
		return "int"
	case "smallint":
		return "int16"
	case "tinyint":
		if strings.HasPrefix(strings.ToLower(columnType), "tinyint(1)") {
			return "bool"
		}
		return "int8"
	case "float":
		return "float32"
	case "double", "decimal", "numeric":
		return "float64"
	case "varchar", "char", "enum", "set", "json":
		return "string"
	case "text", "tinytext", "mediumtext", "longtext":
		return "string"
	case "datetime", "timestamp", "date", "time":
		return "time.Time"
	case "blob", "tinyblob", "mediumblob", "longblob", "binary", "varbinary":
		return "[]byte"
	default:
		return "string"
	}
}

// isTimeType 判断是否映射为 time.Time。
func isTimeType(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "datetime", "timestamp", "date", "time":
		return true
	}
	return false
}

// isSortable 判断字段是否适合作为排序字段。
func isSortable(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "text", "tinytext", "mediumtext", "longtext", "blob", "tinyblob", "mediumblob", "longblob", "json", "binary", "varbinary":
		return false
	}
	return true
}

// isIntegerType 判断字段是否为整形类型。
// tinyint(1) 会映射为 bool，因此不作为整形过滤字段。
func isIntegerType(dataType, columnType string) bool {
	switch strings.ToLower(dataType) {
	case "bigint", "int", "integer", "mediumint", "smallint":
		return true
	case "tinyint":
		return !strings.HasPrefix(strings.ToLower(columnType), "tinyint(1)")
	}
	return false
}

// isLikeQueryable 判断字符串字段是否适合 LIKE 过滤。
func isLikeQueryable(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "varchar", "char", "enum", "set":
		return true
	}
	return false
}

// toGoName 将 snake_case 列名转换为 Go 字段名，如 group_id -> GroupId。
func toGoName(column string) string {
	parts := strings.Split(column, "_")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

// lowerFirst 将首字母转小写，用于生成变量名。
func lowerFirst(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// buildGormTag 根据列信息构造 GORM tag。
func buildGormTag(c columnInfo) string {
	parts := []string{"column:" + c.Name}
	isPrimary := strings.EqualFold(c.ColumnKey, "PRI")
	if isPrimary {
		parts = append(parts, "primaryKey")
	}
	if strings.Contains(strings.ToLower(c.Extra), "auto_increment") {
		parts = append(parts, "autoIncrement")
	}
	if !c.Nullable {
		parts = append(parts, "not null")
	}
	if d, ok := gormDefault(c.Default); ok {
		parts = append(parts, "default:"+d)
	}
	if c.Comment != "" {
		parts = append(parts, "comment:"+c.Comment)
	}
	return strings.Join(parts, ";")
}

// gormDefault 判断默认值是否可安全放入 GORM tag，返回可用的默认值。
func gormDefault(def string) (string, bool) {
	if def == "" {
		return "", false
	}
	upper := strings.ToUpper(def)
	if upper == "CURRENT_TIMESTAMP" || strings.HasPrefix(upper, "CURRENT_TIMESTAMP") {
		return def, true
	}
	for _, r := range def {
		if r == ' ' || r == '\'' || r == '"' || r == ';' {
			return "", false
		}
	}
	return def, true
}

// buildTableModel 将一张表的原始列信息组装成模板数据。
func buildTableModel(packageName, table string, columns []columnInfo) *TableModel {
	m := &TableModel{
		PackageName:     packageName,
		TableName:       table,
		EntityName:      toGoName(table),
		LowerEntityName: lowerFirst(toGoName(table)),
		Comment:         table,
	}
	m.VarName = lowerFirst(m.EntityName)
	m.VarNameList = m.VarName + "s"

	var hasTime, hasSort bool
	for _, c := range columns {
		f := FieldModel{
			Column:    c.Name,
			GoName:    toGoName(c.Name),
			GoType:    goTypeFor(c.DataType, c.ColumnType),
			JSONName:  c.Name,
			GormTag:   buildGormTag(c),
			Comment:   c.Comment,
			OmitEmpty: c.Nullable,
			VarName:   lowerFirst(toGoName(c.Name)),
		}
		if f.GoType == "string" {
			f.ZeroValue = `""`
		} else {
			f.ZeroValue = "0"
		}

		isPrimary := strings.EqualFold(c.ColumnKey, "PRI")
		if isPrimary {
			f.OmitEmpty = false
			pk := f
			m.PrimaryKey = &pk
		}

		m.Fields = append(m.Fields, f)

		if f.GoType == "time.Time" {
			hasTime = true
		}
		if isSortable(c.DataType) {
			m.SortFields = append(m.SortFields, f)
			hasSort = true
		}
		if isLikeQueryable(c.DataType) {
			m.QueryStringFields = append(m.QueryStringFields, f)
		}
		if !isPrimary && isIntegerType(c.DataType, c.ColumnType) {
			m.IntegerFields = append(m.IntegerFields, f)
		}
		if isTimeType(c.DataType) {
			m.TimeFields = append(m.TimeFields, TimeRangeField{
				GoName:    f.GoName,
				Column:    f.Column,
				JSONStart: f.Column + "_start",
				JSONEnd:   f.Column + "_end",
			})
		}
		if !isPrimary {
			m.UpdatableFields = append(m.UpdatableFields, f)
		}
	}

	m.ImportBlock = buildImportBlock(hasTime, hasSort)
	return m
}

// buildImportBlock 根据字段情况构造 import 块字符串。
func buildImportBlock(hasTime, hasSort bool) string {
	var std, third []string
	if hasTime {
		std = append(std, `"time"`)
	}
	third = append(third, `"gorm.io/gorm"`)
	if hasSort {
		third = append(third, `"gorm.io/gorm/clause"`)
	}

	var b strings.Builder
	b.WriteString("import (\n")
	for _, s := range std {
		b.WriteString("\t" + s + "\n")
	}
	if len(std) > 0 && len(third) > 0 {
		b.WriteString("\n")
	}
	for _, s := range third {
		b.WriteString("\t" + s + "\n")
	}
	b.WriteString(")")
	return b.String()
}
