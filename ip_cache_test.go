package caddyguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompileIPRules_CIDR(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "192.168.1.0/24"},
		{Raw: "10.0.0.0/8"},
		{Raw: "172.16.0.0/12"},
	}
	rs := compileIPRules(rules)

	if rs == nil || !rs.hasRules {
		t.Fatal("expected non-empty rule set")
	}
	if len(rs.ipv4Ranges) != 3 {
		t.Fatalf("expected 3 ipv4 ranges, got %d", len(rs.ipv4Ranges))
	}
	// 验证排序
	if rs.ipv4Ranges[0].lo > rs.ipv4Ranges[1].lo {
		t.Fatal("ipv4 ranges not sorted")
	}

	// 匹配测试
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.100", true},
		{"192.168.1.1", true},
		{"192.168.2.1", false},
		{"10.5.5.5", true},
		{"10.0.0.0", true},
		{"11.0.0.0", false},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		got := rs.match(c.ip)
		if got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCompileIPRules_Exact(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "8.8.8.8"},
		{Raw: "1.2.3.4"},
		{Raw: "::1"},
	}
	rs := compileIPRules(rules)

	if rs == nil || !rs.hasRules {
		t.Fatal("expected non-empty rule set")
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.2.3.4", true},
		{"::1", true},
		{"8.8.4.4", false},
		{"9.9.9.9", false},
	}
	for _, c := range cases {
		got := rs.match(c.ip)
		if got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCompileIPRules_Glob(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "192.168.*.*"},
		{Raw: "10.0.*.0"},
	}
	rs := compileIPRules(rules)

	if rs == nil || !rs.hasRules {
		t.Fatal("expected non-empty rule set")
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.100", true},
		{"192.168.0.0", true},
		{"192.169.1.1", false},
		{"10.0.5.0", true},
		{"10.0.5.1", false},
	}
	for _, c := range cases {
		got := rs.match(c.ip)
		if got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCompileIPRules_Mixed(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "10.0.0.0/8"},
		{Raw: "8.8.8.8"},
		{Raw: "192.168.*.*"},
		{Raw: "# comment"},
		{Raw: ""},
	}
	rs := compileIPRules(rules)

	if rs == nil || !rs.hasRules {
		t.Fatal("expected non-empty rule set")
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"172.16.0.1", false},
		{"8.8.4.4", false},
	}
	for _, c := range cases {
		got := rs.match(c.ip)
		if got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestCompileIPRules_Empty(t *testing.T) {
	rules := []RuleEntry{}
	rs := compileIPRules(rules)

	if rs == nil {
		t.Fatal("expected non-nil rule set")
	}
	if rs.hasRules {
		t.Fatal("expected hasRules=false for empty rules")
	}
}

func TestCompileIPRules_AllComments(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "# comment 1"},
		{Raw: "# comment 2"},
	}
	rs := compileIPRules(rules)

	if rs == nil {
		t.Fatal("expected non-nil rule set")
	}
	if rs.hasRules {
		t.Fatal("expected hasRules=false for all-comment rules")
	}
}

func TestCompileIPRules_IPv6CIDR(t *testing.T) {
	rules := []RuleEntry{
		{Raw: "2001:db8::/32"},
		{Raw: "::1/128"},
	}
	rs := compileIPRules(rules)

	if rs == nil || !rs.hasRules {
		t.Fatal("expected non-empty rule set")
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:db8:ffff:ffff::1", true},
		{"2001:db9::1", false},
		{"::1", true},
		{"::2", false},
	}
	for _, c := range cases {
		got := rs.match(c.ip)
		if got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestBinarySearchIPv4(t *testing.T) {
	// ranges must be sorted by lo (compileIPRules does this via sort.Slice)
	ranges := []ipv4Range{
		{lo: 0x0A000000, hi: 0x0AFFFFFF}, // 10.0.0.0/8
		{lo: 0xAC100000, hi: 0xAC10FFFF}, // 172.16.0.0/12 (0xAC100000 < 0xC0A80000)
		{lo: 0xC0A80000, hi: 0xC0A800FF}, // 192.168.0.0/24
	}

	cases := []struct {
		ipVal uint32
		want  bool
	}{
		{0x0A000001, true},  // 10.0.0.1
		{0x0AFFFFFF, true},  // 10.255.255.255
		{0x0B000000, false}, // 11.0.0.0
		{0xC0A80001, true},  // 192.168.0.1
		{0xC0A80100, false}, // 192.168.1.0 (not in 192.168.0.0/24)
		{0xAC100001, true},  // 172.16.0.1
		{0xAC10FFFF, true},  // 172.31.255.255
		{0xAC110000, false}, // 172.17.0.0 (not in /12)
	}

	for _, c := range cases {
		got := binarySearchIPv4(ranges, c.ipVal)
		if got != c.want {
			t.Errorf("binarySearchIPv4(%x) = %v, want %v", c.ipVal, got, c.want)
		}
	}
}

func TestGetCompiledIPRules_Caching(t *testing.T) {
	// 创建临时规则文件
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_ip.rule")
	os.WriteFile(ruleFile, []byte("10.0.0.0/8\n8.8.8.8\n# comment\n"), 0644)

	g := &Guard{ruleCache: NewRuleCache(tmpDir)}

	// 第一次调用：编译并缓存
	rs1 := g.getCompiledIPRules("test_ip.rule", "")
	if rs1 == nil {
		t.Fatal("expected non-nil rule set")
	}

	// 第二次调用：应命中缓存
	rs2 := g.getCompiledIPRules("test_ip.rule", "")
	if rs2 == nil {
		t.Fatal("expected non-nil rule set")
	}

	// 验证匹配结果一致
	if rs1.match("10.1.2.3") != rs2.match("10.1.2.3") {
		t.Fatal("cache mismatch")
	}
	if !rs1.match("10.1.2.3") {
		t.Fatal("expected match for 10.1.2.3")
	}
	if !rs1.match("8.8.8.8") {
		t.Fatal("expected match for 8.8.8.8")
	}
	if rs1.match("9.9.9.9") {
		t.Fatal("expected no match for 9.9.9.9")
	}
}

func TestGetCompiledIPRules_MtimeReload(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_reload.rule")
	os.WriteFile(ruleFile, []byte("10.0.0.0/8\n"), 0644)

	g := &Guard{ruleCache: NewRuleCache(tmpDir)}

	// 第一次：规则包含 10.0.0.0/8
	rs1 := g.getCompiledIPRules("test_reload.rule", "")
	if rs1 == nil || !rs1.match("10.1.2.3") {
		t.Fatal("expected match for 10.1.2.3")
	}
	if rs1.match("192.168.1.1") {
		t.Fatal("expected no match for 192.168.1.1")
	}

	// 修改文件 mtime（需要确保 mtime 变化，使用 os.Chtimes）
	os.WriteFile(ruleFile, []byte("192.168.0.0/16\n"), 0644)
	future := time.Now().Add(10 * time.Second)
	os.Chtimes(ruleFile, future, future)

	// 第二次：规则变为 192.168.0.0/16
	rs2 := g.getCompiledIPRules("test_reload.rule", "")
	if rs2 == nil {
		t.Fatal("expected non-nil rule set after reload")
	}
	if rs2.match("10.1.2.3") {
		t.Fatal("expected no match for 10.1.2.3 after reload")
	}
	if !rs2.match("192.168.1.1") {
		t.Fatal("expected match for 192.168.1.1 after reload")
	}
}
