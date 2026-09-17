package caddyguard

import (
	"net/http"
	"strings"
	"testing"
)

// newUATestGuard 使用仓库自带 rule-config 构造 Guard（UA 检测用例）
func newUATestGuard(t *testing.T) *Guard {
	t.Helper()
	return &Guard{
		RuleDir:   "rule-config",
		ruleCache: NewRuleCache("rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger(t.TempDir()),
	}
}

// TestUserAgentRuleBlocksScanners 攻击扫描器 UA 仍应 403
func TestUserAgentRuleBlocksScanners(t *testing.T) {
	g := newUATestGuard(t)
	cases := []struct {
		name string
		ua   string
	}{
		{"sqlmap", "sqlmap/1.0"},
		{"nmap", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"},
		{"burp suite", "Mozilla/5.0 (compatible; Burp Suite Professional)"},
		{"burpsuite", "BurpSuite/2.1"},
		{"httpx tool", "httpx/1.3.0"},
		{"httpx tool in UA", "Mozilla/5.0 projectdiscovery httpx/1.3.0"},
		{"httpx cli", "httpx-cli/1.0"},
		{"amass", "Amass/3.23.0"},
		{"owasp zap", "Mozilla/5.0 (compatible; OWASP ZAP/2.14.0)"},
		{"zap without owasp", "Mozilla/5.0 (X11; Linux) ZAP/2.15.0"},
		{"nuclei", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"},
		{"feroxbuster", "feroxbuster/2.7.0"},
		{"xray", "xray/1.9.0"},
		{"goby", "Goby/1.0"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code := doWAFRequest(t, g, "GET", "/", "example.com", map[string]string{"User-Agent": tt.ua}, "")
			if code != http.StatusForbidden {
				t.Fatalf("expected 403 for UA %q, got %d", tt.ua, code)
			}
		})
	}
}

// TestUserAgentRuleNoFalsePositive 修复后的短词规则不应误杀正常 UA
func TestUserAgentRuleNoFalsePositive(t *testing.T) {
	g := newUATestGuard(t)
	cases := []struct {
		name string
		ua   string
	}{
		{"normal browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"},
		{"burp mobile app", "BurpMobile/1.0 (iPhone; iOS 17.5)"},
		{"burp cloud app", "BurpCloud/2.0"},
		{"burp helper", "BurpHelper/1.2"},
		{"httpx client lib", "httpx-client/1.0"},
		{"python httpx", "python-httpx/0.27.0"},
		{"amass client", "amass-client/1.0"},
		{"owasp dependency check", "OWASP-Dependency-Check/8.4.0"},
		{"amazonbot", "Amazonbot/0.1 (+http://www.amazon.com/amazonbot)"},
		{"applebot extended", "Mozilla/5.0 (Device; OS) AppleWebKit/605.1.15 Applebot-Extended/0.1"},
		{"wayback archiver", "ia_archiver/3.0 (+http://www.archive.org/details/ia_archiver)"},
		{"postman runtime", "PostmanRuntime/7.36.0"},
		{"charles proxy", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Charles/4.6.6"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code := doWAFRequest(t, g, "GET", "/", "example.com", map[string]string{"User-Agent": tt.ua}, "")
			if code != http.StatusOK {
				t.Fatalf("expected 200 for UA %q, got %d", tt.ua, code)
			}
		})
	}
}

// TestUserAgentRuleNoDuplicateEntries 同一工具不应在多条规则中重复出现（避免维护漏改）
func TestUserAgentRuleNoDuplicateEntries(t *testing.T) {
	rules := NewRuleCache("rule-config").GetRule("useragent.rule", "")
	if len(rules) == 0 {
		t.Fatal("useragent.rule loaded 0 rules")
	}
	// 合并后的重复检查：ffuf/dirmap/feroxbuster/nuclei/naabu/subfinder/amass/nikto 等
	// 只应出现在一条规则里（amass/httpx 单独成行属预期）
	duplicated := map[string]int{}
	for _, entry := range rules {
		raw := strings.ToLower(entry.Raw)
		for _, token := range []string{"ffuf", "dirmap", "feroxbuster", "nuclei", "naabu", "subfinder", "nikto", "gobuster", "whatweb", "shodan", "censys"} {
			if strings.Contains(raw, token) {
				duplicated[token]++
			}
		}
	}
	for token, count := range duplicated {
		if count > 1 {
			t.Errorf("token %q appears in %d rules, expected 1", token, count)
		}
	}
}
