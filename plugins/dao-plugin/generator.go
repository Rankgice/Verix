package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var outputDirLocks sync.Map

// FieldModel 是传给模板的单个字段描述。
type FieldModel struct {
	Column       string // 数据库列名，如 group_id
	GoName       string // Go 字段名，如 GroupId
	GoType       string // Go 类型，如 int64
	JSONName     string // JSON 名，如 group_id
	GormTag      string // 完整 GORM tag 内容，如 column:group_id;not null
	Comment      string // 字段注释
	OmitEmpty    bool   // 是否在 json tag 加 omitempty
	VarName      string // 用作变量的名字，如 id
	ZeroValue    string // 等值比较用的零值，如 "0" 或 `""`
	SupportsList bool   // 是否生成 XxxList，用于以 _id 结尾的整形外键字段和主键
}

// TimeRangeField 描述时间字段的查询范围参数。
type TimeRangeField struct {
	GoName    string
	Column    string
	JSONStart string
	JSONEnd   string
}

// TableModel 是传给模板的单个表的数据模型。
type TableModel struct {
	PackageName        string
	ImportBlock        string
	EntityName         string
	TableName          string
	LowerEntityName    string
	Comment            string
	VarName            string
	VarNameList        string
	PrimaryKey         *FieldModel
	Fields             []FieldModel
	SortFields         []FieldModel
	QueryStringFields  []FieldModel
	QueryFilterFields  []FieldModel
	DeleteFilterFields []FieldModel
	TimeFields         []TimeRangeField
	UpdatableFields    []FieldModel
}

// goTypeFor 将常见 MySQL、SQLite 及兼容数据库类型映射为 Go 类型。
func goTypeFor(dataType, columnType string) string {
	switch dt := strings.ToLower(dataType); dt {
	case "bigint", "bigserial":
		return "int64"
	case "int", "integer", "mediumint", "serial":
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
	case "double", "double precision", "real", "decimal", "numeric":
		return "float64"
	case "bool", "boolean":
		return "bool"
	case "varchar", "character varying", "char", "enum", "set", "json", "jsonb", "uuid", "text", "tinytext", "mediumtext", "longtext":
		return "string"
	case "datetime", "timestamp", "timestamptz", "timestamp with time zone", "timestamp without time zone", "date", "time":
		return "time.Time"
	case "blob", "tinyblob", "mediumblob", "longblob", "binary", "varbinary", "bytea":
		return "[]byte"
	default:
		return "string"
	}
}

// isTimeType 判断字段是否映射为 time.Time。
func isTimeType(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "datetime", "timestamp", "timestamptz", "timestamp with time zone", "timestamp without time zone", "date", "time":
		return true
	}
	return false
}

// isSortable 判断字段是否适合作为排序字段。
func isSortable(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "text", "tinytext", "mediumtext", "longtext", "blob", "tinyblob", "mediumblob", "longblob", "json", "jsonb", "binary", "varbinary", "bytea":
		return false
	}
	return true
}

// isIntegerType 判断字段是否为整形类型。
func isIntegerType(dataType, columnType string) bool {
	switch strings.ToLower(dataType) {
	case "bigint", "bigserial", "int", "integer", "mediumint", "serial", "smallint":
		return true
	case "tinyint":
		return !strings.HasPrefix(strings.ToLower(columnType), "tinyint(1)")
	}
	return false
}

// isListField 判断整形字段是否应该生成 XxxList。
func isListField(column string, isPrimary bool) bool {
	return isPrimary || strings.HasSuffix(strings.ToLower(column), "_id")
}

// isLikeQueryable 判断字符串字段是否适合 LIKE 过滤。
func isLikeQueryable(dataType string) bool {
	switch strings.ToLower(dataType) {
	case "varchar", "character varying", "char", "enum", "set", "text":
		return true
	}
	return false
}

// toGoName 将 snake_case 列名转换为 Go 字段名。
func toGoName(column string) string {
	var b strings.Builder
	for _, p := range strings.Split(column, "_") {
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
	if strings.EqualFold(c.ColumnKey, "PRI") {
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

// gormDefault 判断默认值是否可安全放入 GORM tag。
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
	m := &TableModel{PackageName: packageName, TableName: table, EntityName: toGoName(table), LowerEntityName: lowerFirst(toGoName(table)), Comment: table}
	m.VarName = lowerFirst(m.EntityName)
	m.VarNameList = m.VarName + "s"
	var hasTime, hasSort bool
	for _, c := range columns {
		f := FieldModel{Column: c.Name, GoName: toGoName(c.Name), GoType: goTypeFor(c.DataType, c.ColumnType), JSONName: c.Name, GormTag: buildGormTag(c), Comment: c.Comment, OmitEmpty: c.Nullable, VarName: lowerFirst(toGoName(c.Name))}
		isPrimary := strings.EqualFold(c.ColumnKey, "PRI")
		f.SupportsList = isListField(c.Name, isPrimary)
		if f.GoType == "string" {
			f.ZeroValue = `""`
		} else {
			f.ZeroValue = "0"
		}
		if isPrimary {
			f.OmitEmpty = false
			pk := f
			m.PrimaryKey = &pk
			m.QueryFilterFields = append(m.QueryFilterFields, f)
			m.DeleteFilterFields = append(m.DeleteFilterFields, f)
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
			m.QueryFilterFields = append(m.QueryFilterFields, f)
			m.DeleteFilterFields = append(m.DeleteFilterFields, f)
		}
		if isTimeType(c.DataType) {
			m.TimeFields = append(m.TimeFields, TimeRangeField{GoName: f.GoName, Column: f.Column, JSONStart: f.Column + "_start", JSONEnd: f.Column + "_end"})
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

// resolveOutputDir 校验并规范化 file mode 的输出目录。
func resolveOutputDir(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("output_dir is required in file mode")
	}
	if strings.ContainsRune(raw, 0) {
		return "", errors.New("output_dir contains NUL")
	}
	clean := filepath.Clean(raw)
	if clean == "." || clean == ".." {
		return "", errors.New("output_dir must identify a real directory")
	}
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("resolve output_dir: %w", err)
	}
	if info, err := os.Stat(abs); err == nil && !info.IsDir() {
		return "", fmt.Errorf("output_dir is not a directory: %s", abs)
	}
	return abs, nil
}

// resolveTableFile 将表名安全地映射为输出目录下的 .go 文件。
func resolveTableFile(outputDir, table string) (string, error) {
	if table == "" || strings.ContainsRune(table, 0) || strings.ContainsAny(table, `/\\`) || table == "." || table == ".." {
		return "", fmt.Errorf("unsafe table name: %q", table)
	}
	return filepath.Join(outputDir, table+".go"), nil
}

// writeGeneratedFile 原子写入一个生成文件，允许覆盖已有文件并返回文件信息。
func writeGeneratedFile(outputDir, table, entity, packageName, code string) (GeneratedFileInfo, error) {
	path, err := resolveTableFile(outputDir, table)
	if err != nil {
		return GeneratedFileInfo{}, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return GeneratedFileInfo{}, fmt.Errorf("create output_dir: %w", err)
	}
	key := filepath.Clean(outputDir)
	lockValue, _ := outputDirLocks.LoadOrStore(key, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	_, statErr := os.Stat(path)
	existed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return GeneratedFileInfo{}, fmt.Errorf("stat target: %w", statErr)
	}
	tmp, err := os.CreateTemp(outputDir, ".verix-dao-*.tmp")
	if err != nil {
		return GeneratedFileInfo{}, fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.WriteString(tmp, code); err != nil {
		tmp.Close()
		return GeneratedFileInfo{}, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return GeneratedFileInfo{}, fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return GeneratedFileInfo{}, fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return GeneratedFileInfo{}, fmt.Errorf("replace target %s: %w", path, err)
	}
	digest := sha256.Sum256([]byte(code))
	return GeneratedFileInfo{Table: table, Entity: entity, Package: packageName, Path: path, Bytes: len(code), SHA256: hex.EncodeToString(digest[:]), Created: !existed, Overwritten: existed}, nil
}
