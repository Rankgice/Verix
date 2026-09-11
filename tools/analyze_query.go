package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"verix/db"
)

// AnalyzeQueryInput 保存仅分析而不执行的 SQL 文本。
type AnalyzeQueryInput struct {
	// SQL 是待做风险分析的单条 SQL，不会发送到数据库。
	SQL string `json:"sql" jsonschema:"SQL statement to analyze without executing"`
}

// AnalyzeQueryOutput 复用数据库层定义的 SQL 分析结果。
type AnalyzeQueryOutput = db.AnalyzeQueryResult

// RegisterAnalyzeQuery 注册与具体数据库驱动无关的 SQL 安全分析 Tool。
func RegisterAnalyzeQuery(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_query",
		Description: "Analyze SQL safety, operation type, and referenced tables without executing it.",
	}, analyzeQueryHandler)
}

// analyzeQueryHandler 对 SQL 做静态分析，不会建立数据库连接或执行语句。
func analyzeQueryHandler(ctx context.Context, req *mcp.CallToolRequest, in AnalyzeQueryInput) (*mcp.CallToolResult, AnalyzeQueryOutput, error) {
	_ = ctx
	_ = req

	// 分析结果包含操作类型、引用表、风险等级和安全警告。
	out, err := db.AnalyzeQuery(in.SQL)
	if err != nil {
		return nil, AnalyzeQueryOutput{}, err
	}

	return nil, *out, nil
}
