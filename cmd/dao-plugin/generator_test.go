package main

import (
	"strings"
	"testing"
)

// buildUserGroupColumns 构造一张 user_group 表的列信息，用于验证类型映射和命名转换。
func buildUserGroupColumns() []columnInfo {
	return []columnInfo{
		{Name: "id", DataType: "bigint", ColumnType: "bigint", ColumnKey: "PRI", Extra: "auto_increment", Comment: "数据库主键ID"},
		{Name: "group_id", DataType: "bigint", ColumnType: "bigint", ColumnKey: "", Comment: "分组ID"},
		{Name: "name", DataType: "varchar", ColumnType: "varchar(255)", ColumnKey: "", Comment: "名称"},
		{Name: "description", DataType: "varchar", ColumnType: "varchar(255)", Nullable: true, ColumnKey: "", Comment: "描述"},
		{Name: "created_at", DataType: "datetime", ColumnType: "datetime", ColumnKey: "", Default: "CURRENT_TIMESTAMP", Comment: "创建时间"},
		{Name: "updated_at", DataType: "datetime", ColumnType: "datetime", ColumnKey: "", Default: "CURRENT_TIMESTAMP", Comment: "更新时间"},
	}
}

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

func TestGoTypeFor(t *testing.T) {
	cases := map[string]string{
		"bigint":   "int64",
		"int":      "int",
		"varchar":  "string",
		"text":     "string",
		"datetime": "time.Time",
		"decimal":  "float64",
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
	}
	for _, want := range wants {
		if !strings.Contains(code, want) {
			t.Errorf("生成代码缺少 %q", want)
		}
	}
	// 不应出现全大写 ID 命名。
	if strings.Contains(code, "GroupID") || strings.Contains(code, "ID int64") {
		t.Errorf("命名不符合 Id 约定: 不应出现 GroupID 或 ID 全大写")
	}
}
