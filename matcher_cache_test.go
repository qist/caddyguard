package caddyguard

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// 缓存专项测试（对应 NginxGuard test/test_match_cache.lua 的验收口径）：
// 核心原则 —— 缓存只优化检测速度，绝不改变检测结果。
// 真值函数：matchRulesInternal（无缓存完整检测），任何缓存路径的结果都必须与之逐请求一致。

var cacheTestRuleSrc = "unionselect\netc/passwd\nalertscript\nevil[0-9]+payload\nselect.+from"

func mustCacheTestRules(t *testing.T, src string) []RuleEntry {
	t.Helper()
	rules := parseAndCompileRules(src, false)
	if len(rules) == 0 {
		t.Fatal("no rules compiled from source")
	}
	return rules
}

// cacheTestInputs: 恶意/良性/边界(512/513)/短输入混合
func cacheTestInputs() []string {
	return []string{
		"hello world",
		"/index.html?id=123&name=test",
		"unionselect",
		"xxx unionselect yyy",
		"UNIONSELECT-UPPER-CASE",
		"cat /etc/passwd please",
		"<alertscript>tag</alertscript>",
		"evil123payload",
		"evil99887766payload",
		"select username from users",
		"selesct username form users", // 负缓存
		"normal text without any signature",
		strings.Repeat("a", 512),
		strings.Repeat("a", 512) + "unionselect",
		strings.Repeat("b", 513),
		strings.Repeat("b", 513) + "unionselect",
		"<", // 短输入早退
	}
}

func assertSameAsInternal(t *testing.T, rules []RuleEntry, input string, ci bool) {
	t.Helper()
	got := matchRules(input, rules, ci)
	want := matchRulesInternal(input, rules, ci)
	if (got == nil) != (want == nil) {
		t.Errorf("input %q: cached=%v internal=%v (mismatch)", trunc(input), got != nil, want != nil)
		return
	}
	if got != nil && want != nil && got.Raw != want.Raw {
		t.Errorf("input %q: cached rule=%q internal rule=%q", trunc(input), got.Raw, want.Raw)
	}
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// T1 缓存开启下逐请求 100% 一致 (冷路径/暂存命中晋升/热点命中三轮)
func TestMatchRules_CacheConsistency(t *testing.T) {
	rules := mustCacheTestRules(t, cacheTestRuleSrc)
	inputs := cacheTestInputs()
	for pass := 0; pass < 3; pass++ {
		for _, input := range inputs {
			assertSameAsInternal(t, rules, input, true)
		}
	}
}

// T2 4096 条填满 + 100000 唯一输入: 占用始终有界, 不整体清空
func TestMatchRules_CacheBounded(t *testing.T) {
	rules := mustCacheTestRules(t, "zznomatchhere")
	for i := 0; i < 100000; i++ {
		input := fmt.Sprintf("flood%d_padding_%d", i, i*7919)
		assertSameAsInternal(t, rules, input, true)
		if i%10000 == 0 {
			hot, prob := matchCacheStats()
			if hot+prob > 4096 {
				t.Fatalf("bound violated at %d: hot=%d probation=%d", i, hot, prob)
			}
		}
	}
	hot, prob := matchCacheStats()
	if prob != 1024 {
		t.Errorf("probation should be full (1024), got %d", prob)
	}
	if hot+prob > 4096 {
		t.Errorf("total %d exceeds capacity 4096", hot+prob)
	}
}

// T3 热点条目在高基数洪水下完整保留
func TestMatchRules_HotZoneSurvival(t *testing.T) {
	rules := mustCacheTestRules(t, "pollutesig")
	hotInputs := make([]string, 500)
	for i := range hotInputs {
		if i%2 == 0 {
			hotInputs[i] = fmt.Sprintf("hotcase%d has pollutesig inside", i)
		} else {
			hotInputs[i] = fmt.Sprintf("hotcase%d benign only", i)
		}
	}
	// 二次命中 → 全部晋升热点区 (delta 口径, 排除前置测试遗留条目)
	hot0, _ := matchCacheStats()
	for _, input := range hotInputs {
		matchRules(input, rules, true)
		matchRules(input, rules, true)
	}
	hotBefore, probBefore := matchCacheStats()
	if hotBefore-hot0 != 500 {
		t.Fatalf("expected +500 hot entries, got +%d (probation=%d)", hotBefore-hot0, probBefore)
	}
	// 高基数洪水穿插热点复检
	for i := 0; i < 20000; i++ {
		matchRules(fmt.Sprintf("floodcase%d_%d", i, i*7919), rules, true)
		if i%1000 == 0 {
			for j := 0; j < 50; j++ {
				matchRules(hotInputs[(i+j)%500], rules, true)
			}
		}
	}
	hotAfter, _ := matchCacheStats()
	if hotAfter != hotBefore {
		t.Errorf("hot zone changed under flood: %d -> %d", hotBefore, hotAfter)
	}
	// 热点条目逐条复核
	for _, input := range hotInputs {
		assertSameAsInternal(t, rules, input, true)
	}
}

// T4 规则热加载后旧缓存必须失效 (中间条目变化, 条数与首末条不变 —— 旧签名方案下必失败的场景)
func TestMatchRules_RuleUpdateInvalidation(t *testing.T) {
	v1 := mustCacheTestRules(t, "ruleA_prefix\noldsignature\nruleC_suffix")
	v2 := mustCacheTestRules(t, "ruleA_prefix\nnewsignature\nruleC_suffix")
	input := "x oldsignature y"
	// v1 下检出并缓存（含二次命中晋升热点区）
	if got := matchRules(input, v1, true); got == nil || got.Raw != "oldsignature" {
		t.Fatalf("v1 rules should match oldsignature, got %v", got)
	}
	matchRules(input, v1, true)
	// 规则更新: 同一输入必须按新规则检测 (返回新规则集的真值)
	got := matchRules(input, v2, true)
	want := matchRulesInternal(input, v2, true)
	if (got == nil) != (want == nil) || (got != nil && got.Raw != want.Raw) {
		t.Errorf("stale cache leaked across rule update: got=%v want=%v", got, want)
	}
	// 新规则检出 newsignature 且旧签名不再检出
	if got2 := matchRules("x newsignature y", v2, true); got2 == nil || got2.Raw != "newsignature" {
		t.Errorf("new rule not applied after update, got %v", got2)
	}
	if got3 := matchRules(input, v2, true); got3 != nil {
		t.Errorf("old signature input should not match new rules, got %v", got3)
	}
}

// T5 并发 hammer: 混合热点命中/暂存晋升/高基数洪水, -race 下无竞争且结果始终正确
func TestMatchRules_Concurrent(t *testing.T) {
	rules := mustCacheTestRules(t, cacheTestRuleSrc)
	var wg sync.WaitGroup
	errCh := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				var input string
				switch i % 10 {
				case 0, 1:
					input = "hot_goroutine_fixed_input_unionselect" // 热点重复
				default:
					input = fmt.Sprintf("g%d_flood%d_%d", g, i, i*7919) // 高基数
				}
				got := matchRules(input, rules, true)
				want := matchRulesInternal(input, rules, true)
				if (got == nil) != (want == nil) || (got != nil && got.Raw != want.Raw) {
					errCh <- fmt.Sprintf("g%d i%d input=%q got=%v want=%v", g, i, trunc(input), got, want)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Error(e)
	}
}
