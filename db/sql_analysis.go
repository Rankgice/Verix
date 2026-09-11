package db

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

// trailingLockClauseRE 匹配 SELECT 尾部锁定子句，自动 LIMIT 必须插入到它们之前。
var trailingLockClauseRE = regexp.MustCompile(`(?is)\s+(FOR\s+UPDATE|LOCK\s+IN\s+SHARE\s+MODE)\s*$`)

// sqlToken 是忽略注释和字符串字面量后的轻量 SQL 词法单元。
type sqlToken struct {
	// Text 保存 SQL 中的原始标识符或符号。
	Text string
	// Upper 保存便于大小写无关比较的标识符。
	Upper string
	// Word 标识该 Token 是否为关键字或普通标识符。
	Word bool
}

// AnalyzeQuery 包装 AnalyzeSQL，生成 analyze_query Tool 使用的输出结构。
func AnalyzeQuery(sqlText string) (*AnalyzeQueryResult, error) {
	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return nil, err
	}
	return &AnalyzeQueryResult{Data: analysis}, nil
}

// AnalyzeSQL 识别顶层操作、引用表、安全风险以及 WHERE、LIMIT 和多语句特征。
func AnalyzeSQL(sqlText string) (SQLAnalysis, error) {
	if strings.TrimSpace(sqlText) == "" {
		return SQLAnalysis{}, fmt.Errorf("sql is required")
	}

	// 轻量 Tokenizer 会忽略注释和字面量，避免其中的关键字影响分析。
	tokens := tokenizeSQL(sqlText)
	operation := detectOperation(tokens)
	if operation == "" {
		return SQLAnalysis{}, fmt.Errorf("could not determine SQL operation")
	}

	// WHERE 和 LIMIT 仅识别顶层关键字，子查询中的子句不影响主语句安全判断。
	analysis := SQLAnalysis{
		Operation:             operation,
		Tables:                uniqueStrings(extractTables(tokens, operation)),
		RiskLevel:             "low",
		HasWhere:              hasTopLevelWord(tokens, "WHERE"),
		HasLimit:              hasTopLevelWord(tokens, "LIMIT"),
		HasMultipleStatements: hasMultipleStatements(tokens),
	}

	// 风险等级按操作类型确定，无 WHERE 的更新和删除会提升为高风险。
	switch operation {
	case "DROP":
		analysis.RiskLevel = "high"
		analysis.Warnings = append(analysis.Warnings, "DROP statements are not allowed")
	case "TRUNCATE":
		analysis.RiskLevel = "high"
		analysis.Warnings = append(analysis.Warnings, "TRUNCATE statements are not allowed")
	case "DELETE":
		analysis.RiskLevel = "medium"
		if !analysis.HasWhere {
			analysis.RiskLevel = "high"
			analysis.Warnings = append(analysis.Warnings, "DELETE without WHERE is not allowed")
		}
	case "UPDATE":
		analysis.RiskLevel = "medium"
		if !analysis.HasWhere {
			analysis.RiskLevel = "high"
			analysis.Warnings = append(analysis.Warnings, "UPDATE without WHERE is not allowed")
		}
	case "INSERT", "REPLACE":
		analysis.RiskLevel = "medium"
	case "ALTER", "CREATE", "RENAME":
		analysis.RiskLevel = "high"
	default:
		analysis.RiskLevel = "low"
	}

	if operation == "SELECT" && !analysis.HasLimit {
		analysis.Warnings = append(analysis.Warnings, "No LIMIT clause")
	}
	if analysis.HasMultipleStatements {
		analysis.RiskLevel = "high"
		analysis.Warnings = append(analysis.Warnings, "Multiple SQL statements are not allowed")
	}

	return analysis, nil
}

// ValidateExecution 拒绝危险语句、多语句输入以及只读模式下的写操作。
func ValidateExecution(analysis SQLAnalysis, readOnly bool) error {
	switch analysis.Operation {
	case "":
		return fmt.Errorf("could not determine SQL operation")
	case "DROP", "TRUNCATE":
		return fmt.Errorf("dangerous SQL is not allowed: %s", analysis.Operation)
	case "DELETE":
		if !analysis.HasWhere {
			return fmt.Errorf("dangerous SQL is not allowed: DELETE without WHERE")
		}
	case "UPDATE":
		if !analysis.HasWhere {
			return fmt.Errorf("dangerous SQL is not allowed: UPDATE without WHERE")
		}
	}
	if analysis.HasMultipleStatements {
		return fmt.Errorf("multiple SQL statements are not allowed")
	}

	// 默认只读策略只允许 SELECT，避免调用方遗漏 readonly 字段时发生写入。
	if readOnly && analysis.Operation != "SELECT" {
		return fmt.Errorf("readonly mode only allows SELECT statements, got %s", analysis.Operation)
	}

	return nil
}

// RewriteSelectLimit 为缺少顶层 LIMIT 的 SELECT 追加行数限制，并返回是否发生改写。
func RewriteSelectLimit(sqlText string, limit int) (string, bool, error) {
	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return "", false, err
	}
	if analysis.Operation != "SELECT" || analysis.HasLimit {
		return sqlText, false, nil
	}

	resolvedLimit := NormalizeLimit(limit)
	// 保留原始尾部分号和空白，并确保 LIMIT 位于 FOR UPDATE 等锁子句之前。
	base, suffix := splitStatementSuffix(sqlText)
	if loc := trailingLockClauseRE.FindStringIndex(base); loc != nil {
		return fmt.Sprintf("%s LIMIT %d%s%s", base[:loc[0]], resolvedLimit, base[loc[0]:], suffix), true, nil
	}
	return fmt.Sprintf("%s LIMIT %d%s", base, resolvedLimit, suffix), true, nil
}

// BindNamedParams 将 :name 参数替换为 ?，并按出现顺序返回安全绑定值。
func BindNamedParams(sqlText string, params map[string]any) (string, []any, error) {
	if strings.TrimSpace(sqlText) == "" {
		return "", nil, fmt.Errorf("sql is required")
	}

	var out strings.Builder
	out.Grow(len(sqlText))
	args := make([]any, 0)

	// 单次扫描 SQL，只替换注释、字面量和标识符之外的命名参数。
	for i := 0; i < len(sqlText); {
		if startsLineComment(sqlText, i) {
			end := skipLineComment(sqlText, i)
			out.WriteString(sqlText[i:end])
			i = end
			continue
		}
		if startsBlockComment(sqlText, i) {
			end := skipBlockComment(sqlText, i)
			out.WriteString(sqlText[i:end])
			i = end
			continue
		}

		switch sqlText[i] {
		case '\'':
			end := skipQuotedLiteral(sqlText, i, '\'')
			out.WriteString(sqlText[i:end])
			i = end
			continue
		case '"':
			end := skipQuotedLiteral(sqlText, i, '"')
			out.WriteString(sqlText[i:end])
			i = end
			continue
		case '`':
			end := skipBacktickIdentifier(sqlText, i)
			out.WriteString(sqlText[i:end])
			i = end
			continue
		case ':':
			// PostgreSQL 风格 :: 强制转换不是命名参数，原样保留。
			if i > 0 && sqlText[i-1] == ':' {
				out.WriteByte(sqlText[i])
				i++
				continue
			}
			if i+1 < len(sqlText) && isPlaceholderStart(sqlText[i+1]) {
				end := i + 2
				for end < len(sqlText) && isPlaceholderPart(sqlText[end]) {
					end++
				}
				name := sqlText[i+1 : end]
				value, ok := params[name]
				if !ok {
					return "", nil, fmt.Errorf("missing value for SQL parameter %q", name)
				}
				placeholder, expandedArgs, err := expandParamValue(name, value)
				if err != nil {
					return "", nil, err
				}
				out.WriteString(placeholder)
				args = append(args, expandedArgs...)
				i = end
				continue
			}
		}

		out.WriteByte(sqlText[i])
		i++
	}

	return out.String(), args, nil
}

// NormalizeLimit 将非正数限制替换为默认最大返回行数。
func NormalizeLimit(limit int) int {
	if limit <= 0 {
		return DefaultLimit
	}
	return limit
}

// NormalizeTimeoutMS 将非正数超时替换为默认执行超时。
func NormalizeTimeoutMS(timeoutMS int) int {
	if timeoutMS <= 0 {
		return DefaultTimeoutMS
	}
	return timeoutMS
}

// normalizeReadOnly 将未提供的只读选项规范化为安全默认值 true。
func normalizeReadOnly(readOnly *bool) bool {
	if readOnly == nil {
		return true
	}
	return *readOnly
}

// usesQueryExecution 判断 SQL 操作应走 Query 还是 Exec 执行路径。
func usesQueryExecution(operation string) bool {
	switch operation {
	case "SELECT", "SHOW", "DESCRIBE", "EXPLAIN":
		return true
	default:
		return false
	}
}

// detectOperation 识别普通 SQL 或 WITH CTE 后的主语句操作。
func detectOperation(tokens []sqlToken) string {
	firstWord := firstWordToken(tokens)
	if firstWord == "" {
		return ""
	}
	// 普通语句直接使用首个关键字；WITH 需要越过 CTE 括号寻找主操作。
	if firstWord != "WITH" {
		return firstWord
	}

	// depth 只跟踪括号层级，确保子查询关键字不会被当作主语句特征。
	depth := 0
	for _, token := range tokens {
		switch token.Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || !token.Word {
			continue
		}
		switch token.Upper {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "SHOW", "DESCRIBE", "EXPLAIN", "DROP", "TRUNCATE", "ALTER", "CREATE", "RENAME":
			if token.Upper != "WITH" {
				return token.Upper
			}
		}
	}

	return ""
}

// firstWordToken 返回词法单元中的第一个关键字。
func firstWordToken(tokens []sqlToken) string {
	for _, token := range tokens {
		if token.Word {
			return token.Upper
		}
	}
	return ""
}

// hasTopLevelWord 判断指定关键字是否出现在括号之外的顶层语句中。
func hasTopLevelWord(tokens []sqlToken, word string) bool {
	depth := 0
	for _, token := range tokens {
		switch token.Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && token.Word && token.Upper == word {
			return true
		}
	}
	return false
}

// hasMultipleStatements 判断顶层分号后是否还存在另一条语句。
func hasMultipleStatements(tokens []sqlToken) bool {
	depth := 0
	hasTerminator := false
	for _, token := range tokens {
		switch token.Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if token.Text == ";" {
			hasTerminator = true
			continue
		}
		if hasTerminator {
			return true
		}
	}
	return false
}

// extractTables 按顶层 SQL 操作选择对应的表名提取策略。
func extractTables(tokens []sqlToken, operation string) []string {
	switch operation {
	case "SELECT":
		return extractSelectTables(tokens)
	case "DELETE":
		return extractTablesAfterKeyword(tokens, "FROM")
	case "UPDATE":
		return extractTableAfterOperation(tokens, "UPDATE")
	case "INSERT", "REPLACE":
		return extractTablesAfterKeyword(tokens, "INTO")
	case "DROP", "TRUNCATE", "ALTER", "CREATE", "RENAME":
		return extractTablesAfterKeyword(tokens, "TABLE")
	default:
		return nil
	}
}

// extractSelectTables 提取 SELECT 顶层 FROM 和 JOIN 后的表名。
func extractSelectTables(tokens []sqlToken) []string {
	tables := make([]string, 0)
	depth := 0
	for i := 0; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || !tokens[i].Word {
			continue
		}
		if tokens[i].Upper == "FROM" || tokens[i].Upper == "JOIN" {
			if table, next := parseTableName(tokens, i+1); table != "" {
				tables = append(tables, table)
				i = next - 1
			}
		}
	}
	return tables
}

// extractTablesAfterKeyword 提取顶层指定关键字后的表名。
func extractTablesAfterKeyword(tokens []sqlToken, keyword string) []string {
	tables := make([]string, 0)
	depth := 0
	for i := 0; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || !tokens[i].Word || tokens[i].Upper != keyword {
			continue
		}
		if table, _ := parseTableName(tokens, i+1); table != "" {
			tables = append(tables, table)
		}
	}
	return tables
}

// extractTableAfterOperation 提取 UPDATE 等操作关键字后紧随的目标表。
func extractTableAfterOperation(tokens []sqlToken, operation string) []string {
	depth := 0
	for i := 0; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || !tokens[i].Word || tokens[i].Upper != operation {
			continue
		}
		if table, _ := parseTableName(tokens, i+1); table != "" {
			return []string{table}
		}
	}
	return nil
}

// parseTableName 从指定位置读取可包含 Schema 前缀的表名及结束下标。
func parseTableName(tokens []sqlToken, start int) (string, int) {
	i := start
	for i < len(tokens) {
		if tokens[i].Text == "(" {
			return "", i
		}
		if tokens[i].Word || tokens[i].Text == "." {
			break
		}
		i++
	}
	if i >= len(tokens) || !tokens[i].Word {
		return "", i
	}

	// 连续读取 schema.table 等由点号连接的限定名称。
	parts := []string{tokens[i].Text}
	i++
	for i+1 < len(tokens) && tokens[i].Text == "." && tokens[i+1].Word {
		parts = append(parts, tokens[i+1].Text)
		i += 2
	}
	return strings.Join(parts, "."), i
}

// uniqueStrings 按首次出现顺序去除空表名和重复表名。
func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	uniq := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		uniq = append(uniq, value)
	}
	return uniq
}

// tokenizeSQL 对 SQL 做轻量词法分析，并跳过注释与字符串字面量。
func tokenizeSQL(sqlText string) []sqlToken {
	tokens := make([]sqlToken, 0)
	var current strings.Builder
	// flushWord 将累积标识符写为大小写归一化的 Word Token。
	flushWord := func() {
		if current.Len() == 0 {
			return
		}
		text := current.String()
		tokens = append(tokens, sqlToken{Text: text, Upper: strings.ToUpper(text), Word: true})
		current.Reset()
	}

	for i := 0; i < len(sqlText); {
		if startsLineComment(sqlText, i) {
			flushWord()
			i = skipLineComment(sqlText, i)
			continue
		}
		if startsBlockComment(sqlText, i) {
			flushWord()
			i = skipBlockComment(sqlText, i)
			continue
		}

		switch sqlText[i] {
		case '\'':
			flushWord()
			i = skipQuotedLiteral(sqlText, i, '\'')
			continue
		case '"':
			flushWord()
			i = skipQuotedLiteral(sqlText, i, '"')
			continue
		case '`':
			flushWord()
			identifier, end := readBacktickIdentifier(sqlText, i)
			if identifier != "" {
				tokens = append(tokens, sqlToken{Text: identifier, Upper: strings.ToUpper(identifier), Word: true})
			}
			i = end
			continue
		}

		if isWordChar(sqlText[i]) {
			current.WriteByte(sqlText[i])
			i++
			continue
		}

		flushWord()
		switch sqlText[i] {
		case '(', ')', ',', ';', '.':
			tokens = append(tokens, sqlToken{Text: string(sqlText[i])})
		}
		i++
	}

	flushWord()
	return tokens
}

// splitStatementSuffix 分离 SQL 主体与尾部分号、空白，便于无损追加 LIMIT。
func splitStatementSuffix(sqlText string) (string, string) {
	trimmed := strings.TrimRightFunc(sqlText, unicode.IsSpace)
	suffix := sqlText[len(trimmed):]
	if strings.HasSuffix(trimmed, ";") {
		return strings.TrimRightFunc(trimmed[:len(trimmed)-1], unicode.IsSpace), ";" + suffix
	}
	return trimmed, suffix
}

// expandParamValue 将标量参数绑定为一个占位符，将非空切片展开为多个占位符。
func expandParamValue(name string, value any) (string, []any, error) {
	if value == nil {
		return "?", []any{nil}, nil
	}

	rv := reflect.ValueOf(value)
	kind := rv.Kind()
	// []byte 是单个二进制参数；其他切片和数组用于展开 IN 列表。
	if kind == reflect.Slice || kind == reflect.Array {
		if kind == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			return "?", []any{value}, nil
		}
		if rv.Len() == 0 {
			return "", nil, fmt.Errorf("SQL parameter %q cannot be an empty slice", name)
		}
		placeholders := make([]string, rv.Len())
		args := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			placeholders[i] = "?"
			args[i] = rv.Index(i).Interface()
		}
		return strings.Join(placeholders, ", "), args, nil
	}

	return "?", []any{value}, nil
}

// startsLineComment 判断当前位置是否为 MySQL 或通用 SQL 行注释起点。
func startsLineComment(sqlText string, i int) bool {
	if i >= len(sqlText) {
		return false
	}
	if sqlText[i] == '#' {
		return true
	}
	if i+1 >= len(sqlText) || sqlText[i] != '-' || sqlText[i+1] != '-' {
		return false
	}
	if i+2 >= len(sqlText) {
		return true
	}
	return unicode.IsSpace(rune(sqlText[i+2]))
}

// startsBlockComment 判断当前位置是否为块注释起点。
func startsBlockComment(sqlText string, i int) bool {
	return i+1 < len(sqlText) && sqlText[i] == '/' && sqlText[i+1] == '*'
}

// skipLineComment 返回行注释结束位置。
func skipLineComment(sqlText string, start int) int {
	i := start
	for i < len(sqlText) && sqlText[i] != '\n' {
		i++
	}
	return i
}

// skipBlockComment 返回块注释结束位置，未闭合时返回 SQL 末尾。
func skipBlockComment(sqlText string, start int) int {
	i := start + 2
	for i+1 < len(sqlText) {
		if sqlText[i] == '*' && sqlText[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return len(sqlText)
}

// skipQuotedLiteral 跳过单引号或双引号内容，并处理转义和重复引号。
func skipQuotedLiteral(sqlText string, start int, quote byte) int {
	i := start + 1
	for i < len(sqlText) {
		if sqlText[i] == '\\' {
			i += 2
			continue
		}
		if sqlText[i] == quote {
			if i+1 < len(sqlText) && sqlText[i+1] == quote {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return len(sqlText)
}

// skipBacktickIdentifier 返回反引号标识符结束位置。
func skipBacktickIdentifier(sqlText string, start int) int {
	_, end := readBacktickIdentifier(sqlText, start)
	return end
}

// readBacktickIdentifier 读取并解码可包含重复反引号的标识符。
func readBacktickIdentifier(sqlText string, start int) (string, int) {
	var value strings.Builder
	i := start + 1
	for i < len(sqlText) {
		if sqlText[i] == '`' {
			if i+1 < len(sqlText) && sqlText[i+1] == '`' {
				value.WriteByte('`')
				i += 2
				continue
			}
			return value.String(), i + 1
		}
		value.WriteByte(sqlText[i])
		i++
	}
	return value.String(), len(sqlText)
}

// isWordChar 判断字节是否可属于 SQL 关键字或标识符。
func isWordChar(ch byte) bool {
	return ch == '_' || ch == '$' || unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch))
}

// isPlaceholderStart 判断字节是否可作为命名参数首字符。
func isPlaceholderStart(ch byte) bool {
	return ch == '_' || unicode.IsLetter(rune(ch))
}

// isPlaceholderPart 判断字节是否可作为命名参数后续字符。
func isPlaceholderPart(ch byte) bool {
	return isPlaceholderStart(ch) || unicode.IsDigit(rune(ch))
}
