package caddyguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================
// 辅助函数：创建测试用 Guard
// ============================================================

func newTestGuard() *Guard {
	g := &Guard{
		RuleDir:   "../rule-config",
		ruleCache: NewRuleCache("../rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger("/tmp"),
	}
	return g
}

func newTestRequest(method, url string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, url, nil)
	r.RemoteAddr = "192.168.1.100:12345"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// ============================================================
// Benchmark: GetEffectiveConfig (优化前 vs 优化后)
// ============================================================

func BenchmarkGetEffectiveConfig_NoDomain(b *testing.B) {
	g := newTestGuard()
	r := newTestRequest("GET", "/hello?name=world", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = g.GetEffectiveConfig(r)
	}
}

func BenchmarkGetEffectiveConfig_WithDomain(b *testing.B) {
	g := newTestGuard()
	r := newTestRequest("GET", "/hello?name=world", nil)
	r.Host = "www.tycng.com:8080"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = g.GetEffectiveConfig(r)
	}
}

func BenchmarkGetEffectiveConfig_WildcardDomain(b *testing.B) {
	g := newTestGuard()
	r := newTestRequest("GET", "/hello?name=world", nil)
	r.Host = "anything.tycng.com:8080"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = g.GetEffectiveConfig(r)
	}
}

// ============================================================
// Benchmark: matchRules (ToLower 优化)
// ============================================================

func BenchmarkMatchRules_CaseInsensitive(b *testing.B) {
	g := newTestGuard()
	rules := g.ruleCache.GetRule("useragent.rule", "")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matchRules("Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.0", rules, true)
	}
}

func BenchmarkMatchRules_CaseSensitive(b *testing.B) {
	g := newTestGuard()
	rules := g.ruleCache.GetRule("url.rule", "")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matchRules("/wp-login.php?test=123", rules, false)
	}
}

// ============================================================
// Benchmark: CC Store Incr (分片锁优化)
// ============================================================

func BenchmarkCCStore_Incr_SingleKey(b *testing.B) {
	store := NewMemoryStore()
	ttl := 60 * time.Second

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Incr("192.168.1.1/api/test", ttl)
	}
}

func BenchmarkCCStore_Incr_DifferentKeys(b *testing.B) {
	store := NewMemoryStore()
	ttl := 60 * time.Second

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Incr("192.168.1.1/api/test"+itoa(i), ttl)
	}
}

// BenchmarkCCStore_Incr_Parallel 并发压测 CC Incr
// 这是优化前全局锁 vs 优化后 64 分片的关键对比
func BenchmarkCCStore_Incr_Parallel(b *testing.B) {
	store := NewMemoryStore()
	ttl := 60 * time.Second

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			store.Incr("192.168.1.1/api/test"+itoa(i%100), ttl)
			i++
		}
	})
}

// BenchmarkCCStore_IsBanned 并发压测 IsBanned
func BenchmarkCCStore_IsBanned_Parallel(b *testing.B) {
	store := NewMemoryStore()
	ttl := 600 * time.Second
	// 预热：封禁一些 IP
	for i := 0; i < 100; i++ {
		store.Ban("192.168.1."+itoa(i), ttl)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			store.IsBanned("192.168.1." + itoa(i%100))
			i++
		}
	})
}

// ============================================================
// Benchmark: 完整检测链 (runChecks)
// ============================================================

func BenchmarkRunChecks_NormalRequest(b *testing.B) {
	g := newTestGuard()
	w := httptest.NewRecorder()
	r := newTestRequest("GET", "/api/users?page=1&size=10", nil)
	r.Host = "www.tycng.com"
	cfg := g.GetEffectiveConfig(r)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.runChecks(w, r, cfg)
	}
}

func BenchmarkRunChecks_AttackRequest(b *testing.B) {
	g := newTestGuard()
	w := httptest.NewRecorder()
	r := newTestRequest("GET", "/?id=1+union+select+1", nil)
	r.Host = "www.tycng.com"
	cfg := g.GetEffectiveConfig(r)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.runChecks(w, r, cfg)
	}
}

// ============================================================
// Benchmark: Glob → Regex (IP 匹配)
// ============================================================

func BenchmarkGlobToRegex_Match(b *testing.B) {
	store := NewMemoryStore()
	_ = store

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matchRegex("192.168.1.100", globToRegex("192.168.*.*"), false)
	}
}

// ============================================================
// 辅助：轻量 itoa（避免 strconv.Itoa 分配）
// ============================================================

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
