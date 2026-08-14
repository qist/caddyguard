package caddyguard

import (
	"fmt"
	"testing"
)

func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		pattern string
		want    [][]byte
		name    string
	}{
		{
			name:    "path_traversal",
			pattern: `\.\./`,
			want:    [][]byte{[]byte("../")},
		},
		{
			name:    "php_var",
			pattern: `\$`,
			want:    [][]byte{},
		},
		{
			name:    "template_injection",
			pattern: `\$\{`,
			want:    [][]byte{[]byte("${")},
		},
		{
			name:    "sql_select",
			pattern: `select.+(from|limit)`,
			want:    [][]byte{[]byte("select"), []byte("from"), []byte("limit")},
		},
		{
			name:    "sql_union",
			pattern: `(?:(union(.*?)select))`,
			want:    [][]byte{[]byte("union"), []byte("select")},
		},
		{
			name:    "xss_tags",
			pattern: `\<(iframe|script|body|img|layer|div|meta|style|base|object|input)`,
			want:    [][]byte{[]byte("iframe"), []byte("script"), []byte("body"), []byte("img"), []byte("layer"), []byte("div"), []byte("meta"), []byte("style"), []byte("base"), []byte("object"), []byte("input")},
		},
		{
			name:    "base64_decode",
			pattern: `base64_decode\(`,
			want:    [][]byte{[]byte("base64_decode(")},
		},
		{
			name:    "javascript",
			pattern: `javascript\:`,
			want:    [][]byte{[]byte("javascript:")},
		},
		{
			name:    "document_cookie",
			pattern: `document\.cookie`,
			want:    [][]byte{[]byte("document.cookie")},
		},
		{
			name:    "nosql_eq",
			pattern: `\$eq\(`,
			want:    [][]byte{[]byte("$eq(")},
		},
		{
			name:    "ssti",
			pattern: `\{\{.*(__class__|__subclasses__|__init__|__globals__|__builtins__|__import__)\}\}`,
			want:    [][]byte{[]byte("{{"), []byte("__class__"), []byte("__subclasses__"), []byte("__init__"), []byte("__globals__"), []byte("__builtins__"), []byte("__import__"), []byte("}}")},
		},
		{
			name:    "case_insensitive_group",
			pattern: `(?i:alert|confirm|prompt)\s*\(`,
			want:    [][]byte{[]byte("alert"), []byte("confirm"), []byte("prompt")},
		},
		{
			name:    "percent_encoded",
			pattern: `%3Cscript`,
			want:    [][]byte{[]byte("%3cscript")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKeywords(tt.pattern)
			if !equalKeywordSets(got, tt.want) {
				t.Errorf("extractKeywords(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

// equalKeywordSets 比较两个关键词集合是否相同（顺序无关）
func equalKeywordSets(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool)
	for _, kw := range a {
		seen[string(kw)] = true
	}
	for _, kw := range b {
		if !seen[string(kw)] {
			return false
		}
	}
	return true
}

// TestParseAndCompileRulesWithKeywords 验证从 post.rule 加载的规则确实有关键词
func TestParseAndCompileRulesWithKeywords(t *testing.T) {
	content := `\.\./
select.+(from|limit)
base64_decode\(
javascript\:
document\.cookie
\$eq\(
child_process
mosconfig\[a-z0-9_]{1,200}=
`

	rules := parseAndCompileRules(content)
	if len(rules) != 8 {
		t.Fatalf("expected 8 rules, got %d", len(rules))
	}

	// 第一条 \.\./ → should have "../"
	if len(rules[0].Keywords) == 0 {
		t.Errorf("rule %q should have keywords", rules[0].Raw)
	}
	t.Logf("rule %q → keywords: %s", rules[0].Raw, formatKeywords(rules[0].Keywords))

	// select.+(from|limit) → should have "select", "from", "limit"
	if len(rules[1].Keywords) < 2 {
		t.Errorf("rule %q should have at least 2 keywords, got %d", rules[1].Raw, len(rules[1].Keywords))
	}
	t.Logf("rule %q → keywords: %s", rules[1].Raw, formatKeywords(rules[1].Keywords))

	// base64_decode\( → should have "base64_decode("
	if len(rules[2].Keywords) == 0 {
		t.Errorf("rule %q should have keywords", rules[2].Raw)
	}
	t.Logf("rule %q → keywords: %s", rules[2].Raw, formatKeywords(rules[2].Keywords))

	// child_process → should have "child_process"
	if len(rules[5].Keywords) == 0 {
		t.Errorf("rule %q should have keywords", rules[5].Raw)
	}
	t.Logf("rule %q → keywords: %s", rules[5].Raw, formatKeywords(rules[5].Keywords))
}

func formatKeywords(kws [][]byte) string {
	var s string
	for i, kw := range kws {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%q", string(kw))
	}
	return "[" + s + "]"
}

// TestMatchRulesBytesWithKeywordPrefilter 验证关键词预过滤正常工作
func TestMatchRulesBytesWithKeywordPrefilter(t *testing.T) {
	rules := parseAndCompileRules(`base64_decode\(
select.+(from|limit)
child_process
`)

	// 正常 body 不包含任何关键词 → 不应命中
	normalBody := []byte(`{"name":"hello","age":30,"city":"Beijing"}`)
	if matched := matchRulesBytes(normalBody, rules, true); matched != nil {
		t.Errorf("normal body should not match, but matched %q", matched.Raw)
	}

	// 攻击 body 包含 "base64_decode(" → 应命中
	attackBody := []byte(`payload=base64_decode(aGVsbG8=)`)
	if matched := matchRulesBytes(attackBody, rules, true); matched == nil {
		t.Errorf("attack body should match base64_decode rule")
	}

	// 攻击 body 包含 "select" 和 "from" → 应命中
	attackBody2 := []byte(`id=1 union select * from users`)
	if matched := matchRulesBytes(attackBody2, rules, true); matched == nil {
		t.Errorf("SQL injection body should match select rule")
	}

	// 攻击 body 包含 "child_process" → 应命中
	attackBody3 := []byte(`require('child_process')`)
	if matched := matchRulesBytes(attackBody3, rules, true); matched == nil {
		t.Errorf("child_process body should match rule")
	}
}
