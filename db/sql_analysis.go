package db

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

var trailingLockClauseRE = regexp.MustCompile(`(?is)\s+(FOR\s+UPDATE|LOCK\s+IN\s+SHARE\s+MODE)\s*$`)

type sqlToken struct {
	Text  string
	Upper string
	Word  bool
}

func AnalyzeQuery(sqlText string) (*AnalyzeQueryResult, error) {
	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return nil, err
	}
	return &AnalyzeQueryResult{Data: analysis}, nil
}

func AnalyzeSQL(sqlText string) (SQLAnalysis, error) {
	if strings.TrimSpace(sqlText) == "" {
		return SQLAnalysis{}, fmt.Errorf("sql is required")
	}

	tokens := tokenizeSQL(sqlText)
	operation := detectOperation(tokens)
	if operation == "" {
		return SQLAnalysis{}, fmt.Errorf("could not determine SQL operation")
	}

	analysis := SQLAnalysis{
		Operation:             operation,
		Tables:                uniqueStrings(extractTables(tokens, operation)),
		RiskLevel:             "low",
		HasWhere:              hasTopLevelWord(tokens, "WHERE"),
		HasLimit:              hasTopLevelWord(tokens, "LIMIT"),
		HasMultipleStatements: hasMultipleStatements(tokens),
	}

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

	if readOnly && analysis.Operation != "SELECT" {
		return fmt.Errorf("readonly mode only allows SELECT statements, got %s", analysis.Operation)
	}

	return nil
}

func RewriteSelectLimit(sqlText string, limit int) (string, bool, error) {
	analysis, err := AnalyzeSQL(sqlText)
	if err != nil {
		return "", false, err
	}
	if analysis.Operation != "SELECT" || analysis.HasLimit {
		return sqlText, false, nil
	}

	resolvedLimit := NormalizeLimit(limit)
	base, suffix := splitStatementSuffix(sqlText)
	if loc := trailingLockClauseRE.FindStringIndex(base); loc != nil {
		return fmt.Sprintf("%s LIMIT %d%s%s", base[:loc[0]], resolvedLimit, base[loc[0]:], suffix), true, nil
	}
	return fmt.Sprintf("%s LIMIT %d%s", base, resolvedLimit, suffix), true, nil
}

func BindNamedParams(sqlText string, params map[string]any) (string, []any, error) {
	if strings.TrimSpace(sqlText) == "" {
		return "", nil, fmt.Errorf("sql is required")
	}

	var out strings.Builder
	out.Grow(len(sqlText))
	args := make([]any, 0)

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

func NormalizeLimit(limit int) int {
	if limit <= 0 {
		return DefaultLimit
	}
	return limit
}

func NormalizeTimeoutMS(timeoutMS int) int {
	if timeoutMS <= 0 {
		return DefaultTimeoutMS
	}
	return timeoutMS
}

func normalizeReadOnly(readOnly *bool) bool {
	if readOnly == nil {
		return true
	}
	return *readOnly
}

func usesQueryExecution(operation string) bool {
	switch operation {
	case "SELECT", "SHOW", "DESCRIBE", "EXPLAIN":
		return true
	default:
		return false
	}
}

func detectOperation(tokens []sqlToken) string {
	firstWord := firstWordToken(tokens)
	if firstWord == "" {
		return ""
	}
	if firstWord != "WITH" {
		return firstWord
	}

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

func firstWordToken(tokens []sqlToken) string {
	for _, token := range tokens {
		if token.Word {
			return token.Upper
		}
	}
	return ""
}

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

	parts := []string{tokens[i].Text}
	i++
	for i+1 < len(tokens) && tokens[i].Text == "." && tokens[i+1].Word {
		parts = append(parts, tokens[i+1].Text)
		i += 2
	}
	return strings.Join(parts, "."), i
}

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

func tokenizeSQL(sqlText string) []sqlToken {
	tokens := make([]sqlToken, 0)
	var current strings.Builder
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

func splitStatementSuffix(sqlText string) (string, string) {
	trimmed := strings.TrimRightFunc(sqlText, unicode.IsSpace)
	suffix := sqlText[len(trimmed):]
	if strings.HasSuffix(trimmed, ";") {
		return strings.TrimRightFunc(trimmed[:len(trimmed)-1], unicode.IsSpace), ";" + suffix
	}
	return trimmed, suffix
}

func expandParamValue(name string, value any) (string, []any, error) {
	if value == nil {
		return "?", []any{nil}, nil
	}

	rv := reflect.ValueOf(value)
	kind := rv.Kind()
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

func startsBlockComment(sqlText string, i int) bool {
	return i+1 < len(sqlText) && sqlText[i] == '/' && sqlText[i+1] == '*'
}

func skipLineComment(sqlText string, start int) int {
	i := start
	for i < len(sqlText) && sqlText[i] != '\n' {
		i++
	}
	return i
}

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

func skipBacktickIdentifier(sqlText string, start int) int {
	_, end := readBacktickIdentifier(sqlText, start)
	return end
}

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

func isWordChar(ch byte) bool {
	return ch == '_' || ch == '$' || unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch))
}

func isPlaceholderStart(ch byte) bool {
	return ch == '_' || unicode.IsLetter(rune(ch))
}

func isPlaceholderPart(ch byte) bool {
	return isPlaceholderStart(ch) || unicode.IsDigit(rune(ch))
}
