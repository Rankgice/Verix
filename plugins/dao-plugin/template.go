package main

import (
	"bytes"
	_ "embed"
	"go/format"
	"text/template"
)

// modelTemplate 是生成 GORM model 代码的 text/template 模板。
//
//go:embed model.go.tmpl
var modelTemplate string

var tmpl = template.Must(template.New("model").Parse(modelTemplate))

// renderModel 用模板渲染一个表，并用 go/format 保证输出格式正确。
func renderModel(m *TableModel) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, m); err != nil {
		return "", err
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		// 模板生成了非法 Go 代码时，返回原始内容便于排查。
		return buf.String(), err
	}
	return string(formatted), nil
}
