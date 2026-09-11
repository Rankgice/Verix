package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// buildUserGroupColumns 构造一张 user_group 表的列信息，用于验证类型映射和命名转换。
func buildUserGroupColumns() []columnInfo {
	return []columnInfo{
		{Name: "id", DataType: "bigint", ColumnType: "bigint", ColumnKey: "PRI", Extra: "auto_increment", Comment: "数据库主键ID"},
		{Name: "group_id", DataType: "bigint", ColumnType: "bigint", ColumnKey: "", Comment: "分组ID"},
		{Name: "age", DataType: "int", ColumnType: "int", ColumnKey: "", Comment: "年龄"},
		{Name: "name", DataType: "varchar", ColumnType: "varchar(255)", ColumnKey: "", Comment: "名称"},
		{Name: "description", DataType: "varchar", ColumnType: "varchar(255)", Nullable: true, ColumnKey: "", Comment: "描述"},
		{Name: "created_at", DataType: "datetime", ColumnType: "datetime", ColumnKey: "", Default: "CURRENT_TIMESTAMP", Comment: "创建时间"},
		{Name: "updated_at", DataType: "datetime", ColumnType: "datetime", ColumnKey: "", Default: "CURRENT_TIMESTAMP", Comment: "更新时间"},
	}
}

// TestToGoName 验证数据库 snake_case 列名能够转换为项目约定的 Go 字段名。
func TestToGoName(t *testing.T) {
	cases := map[string]string{
		"id":          "Id",
		"group_id":    "GroupId",
		"user_name":   "UserName",
		"created_at":  "CreatedAt",
		"category_id": "CategoryId",
	}
	for in, want := range cases {
		if got := toGoName(in); got != want {
			t.Errorf("toGoName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIntegerFieldSelection 验证 MySQL 和 SQLite 整形字段的查询条件入选规则。
func TestIntegerFieldSelection(t *testing.T) {
	tests := []struct {
		dataType   string
		columnType string
		want       bool
	}{
		{dataType: "bigint", columnType: "bigint", want: true},
		{dataType: "int", columnType: "int", want: true},
		{dataType: "integer", columnType: "integer", want: true},
		{dataType: "mediumint", columnType: "mediumint", want: true},
		{dataType: "smallint", columnType: "smallint", want: true},
		{dataType: "tinyint", columnType: "tinyint(4)", want: true},
		{dataType: "tinyint", columnType: "tinyint(1)", want: false},
		{dataType: "decimal", columnType: "decimal(10,2)", want: false},
		{dataType: "varchar", columnType: "varchar(255)", want: false},
	}
	for _, tt := range tests {
		if got := isIntegerType(tt.dataType, tt.columnType); got != tt.want {
			t.Errorf("isIntegerType(%q, %q) = %v, want %v", tt.dataType, tt.columnType, got, tt.want)
		}
	}
}

// TestGoTypeFor 验证 MySQL 和 SQLite 常用字段类型能够稳定映射为 Go 类型。
func TestGoTypeFor(t *testing.T) {
	cases := map[string]string{
		"bigint":   "int64",
		"int":      "int",
		"integer":  "int",
		"varchar":  "string",
		"text":     "string",
		"datetime": "time.Time",
		"decimal":  "float64",
		"real":     "float64",
		"boolean":  "bool",
		"blob":     "[]byte",
	}
	for dataType, want := range cases {
		if got := goTypeFor(dataType, dataType); got != want {
			t.Errorf("goTypeFor(%q) = %q, want %q", dataType, got, want)
		}
	}
	if got := goTypeFor("tinyint", "tinyint(1)"); got != "bool" {
		t.Errorf("tinyint(1) = %q, want bool", got)
	}
}

// TestNormalizeDatabaseType 验证数据库类型规范化、旧调用默认值和非法类型校验。
func TestNormalizeDatabaseType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "旧调用默认 MySQL", input: "", want: databaseTypeMySQL},
		{name: "规范化 MySQL", input: " MySQL ", want: databaseTypeMySQL},
		{name: "规范化 SQLite", input: "SQLITE", want: databaseTypeSQLite},
		{name: "拒绝未支持类型", input: "postgres", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDatabaseType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeDatabaseType(%q) 应返回错误", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeDatabaseType(%q) 返回错误: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("normalizeDatabaseType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestSQLiteSchemaAndGeneration 验证 SQLite 表发现、字段读取和代码生成的完整链路。
func TestSQLiteSchemaAndGeneration(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "dao.sqlite")
	database, err := connect(ctx, databaseTypeSQLite, dsn)
	if err != nil {
		t.Fatalf("连接临时 SQLite 数据库失败: %v", err)
	}
	defer closeDatabase(database)

	// 使用 SQLite 的典型字段类型建表，覆盖主键、数值、布尔、二进制和时间映射。
	ddl := `CREATE TABLE user_profile (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL,
		display_name TEXT NOT NULL,
		balance REAL NOT NULL DEFAULT 0,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		payload BLOB,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`
	if err := database.WithContext(ctx).Exec(ddl).Error; err != nil {
		t.Fatalf("创建 SQLite 测试表失败: %v", err)
	}

	// AUTOINCREMENT 会创建 sqlite_sequence；业务接口不应把该内部表暴露给调用方。
	tables, err := listTables(ctx, database)
	if err != nil {
		t.Fatalf("列举 SQLite 表失败: %v", err)
	}
	if len(tables) != 1 || tables[0] != "user_profile" {
		t.Fatalf("listTables() = %v, want [user_profile]", tables)
	}

	columns, err := readTableColumns(ctx, database, "user_profile")
	if err != nil {
		t.Fatalf("读取 SQLite 表结构失败: %v", err)
	}
	columnsByName := make(map[string]columnInfo, len(columns))
	for _, column := range columns {
		columnsByName[column.Name] = column
	}
	if columnsByName["id"].ColumnKey != "PRI" {
		t.Errorf("SQLite 主键未被识别: %+v", columnsByName["id"])
	}

	wantTypes := map[string]string{
		"id":           "int",
		"account_id":   "int",
		"display_name": "string",
		"balance":      "float64",
		"enabled":      "bool",
		"payload":      "[]byte",
		"created_at":   "time.Time",
	}
	for name, wantType := range wantTypes {
		column, ok := columnsByName[name]
		if !ok {
			t.Errorf("SQLite 列信息缺少 %q", name)
			continue
		}
		if got := goTypeFor(column.DataType, column.ColumnType); got != wantType {
			t.Errorf("列 %q 映射为 %q, want %q（数据库类型=%q）", name, got, wantType, column.ColumnType)
		}
	}

	code, err := renderModel(buildTableModel("model", "user_profile", columns))
	if err != nil {
		t.Fatalf("根据 SQLite 表结构生成代码失败: %v\n%s", err, code)
	}
	compactCode := strings.Join(strings.Fields(code), " ")
	for field, fieldType := range map[string]string{
		"Id": "int", "AccountId": "int", "DisplayName": "string", "Balance": "float64",
		"Enabled": "bool", "Payload": "[]byte", "CreatedAt": "time.Time",
	} {
		if !strings.Contains(compactCode, field+" "+fieldType+" `gorm:") {
			t.Errorf("SQLite 生成代码缺少字段声明 %s %s", field, fieldType)
		}
	}
}

// TestRenderUserGroupModel 验证完整 DAO 模板包含约定的模型、筛选和事务方法。
func TestRenderUserGroupModel(t *testing.T) {
	m := buildTableModel("model", "user_group", buildUserGroupColumns())
	code, err := renderModel(m)
	if err != nil {
		t.Fatalf("renderModel 返回错误（生成代码语法非法）: %v\n%s", err, code)
	}

	wants := []string{
		"package model",
		"type UserGroup struct",
		"func (UserGroup) TableName() string",
		`return "user_group"`,
		"GroupId",
		"column:id;primaryKey;autoIncrement",
		"NewUserGroupModel",
		"func (m *UserGroupModel) GetById(",
		"func (m *UserGroupModel) ListByParam",
		"func (m *UserGroupModel) ListByParamWithTx",
		"func (m *UserGroupModel) UpdateByParam",
		"func (m *UserGroupModel) DeleteByParam",
		"func (m *UserGroupModel) BatchDelete",
		"UserGroupOrderFieldId",
		"UserGroupOrderFieldName",
		`"gorm.io/gorm"`,
		`"gorm.io/gorm/clause"`,
		`"time"`,
		"gorm.ErrRecordNotFound",
		// 整形普通字段进入 QueryParams：单值 + List，并生成等值/IN 过滤。
		"GroupId     int64",
		"GroupIdList []int64",
		"Age         int",
		"if params.GroupId != 0",
		`db.Where("group_id = ?", params.GroupId)`,
		"len(params.GroupIdList) > 0",
		`db.Where("group_id IN ?", params.GroupIdList)`,
		// 整形普通字段进入 DeleteParams：指针单值 + List，并生成等值/IN 删除条件。
		"GroupId     *int64",
		"Age         *int",
		"if params.GroupId != nil",
		`db.Where("group_id = ?", *params.GroupId)`,
	}
	for _, want := range wants {
		if !strings.Contains(code, want) {
			t.Errorf("生成代码缺少 %q", want)
		}
	}
	if strings.Contains(code, "IdList") && strings.Count(code, "IdList") < 2 {
		t.Errorf("主键 IdList 应在查询和删除参数中生成")
	}
	if strings.Count(code, `json:"group_id_list"`) != 2 {
		t.Errorf("GroupIdList 字段声明应只在 QueryParams 和 DeleteParams 各生成一次，实际次数=%d", strings.Count(code, `json:"group_id_list"`))
	}
	if strings.Contains(code, "AgeList") {
		t.Errorf("普通整形字段 age 不应生成 AgeList")
	}
	if !strings.Contains(code, "GroupIdList") {
		t.Errorf("_id 结尾的整形字段 group_id 应生成 GroupIdList")
	}
	// 不应出现全大写 ID 命名。
	if strings.Contains(code, "GroupID") || strings.Contains(code, "ID int64") {
		t.Errorf("命名不符合 Id 约定: 不应出现 GroupID 或 ID 全大写")
	}
}
