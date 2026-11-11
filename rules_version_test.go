package caddyguard

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// 同秒连续修改热加载测试: 秒级 mtime 在同秒双改时不变 (旧方案漏检),
// fileVersion (mtime 纳秒 + 大小) 必须检出并重新加载规则
func TestRuleHotReload_SameSecondModification(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.rule")
	if err := os.WriteFile(p, []byte("oldsignature\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rc := NewRuleCache(dir)
	rules1 := rc.GetRule("test.rule", "")
	if got := matchRules("x oldsignature y", rules1, true); got == nil || got.Raw != "oldsignature" {
		t.Fatalf("v1 rules should match oldsignature, got %v", got)
	}

	// 同秒内重写 (签名变化: 纳秒 + 大小)
	if err := os.WriteFile(p, []byte("newsignature_here\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// 清除节流窗口, 强制下一次 GetRule 执行 os.Stat 检查
	rc.mu.Lock()
	for _, e := range rc.files {
		atomic.StoreInt64(&e.lastCheckNano, 0)
	}
	rc.mu.Unlock()

	rules2 := rc.GetRule("test.rule", "")
	if got := matchRules("x newsignature_here y", rules2, true); got == nil || got.Raw != "newsignature_here" {
		t.Fatalf("same-second modification not detected by hot reload, got %v", got)
	}
	if got := matchRules("x oldsignature y", rules2, true); got != nil {
		t.Fatalf("old signature still matched after same-second update, got %v", got)
	}
}

// getFileVersion 签名唯一性: 同一文件两次 stat 相同内容签名一致, 内容变化签名变化
func TestFileVersion_ChangesOnChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	os.WriteFile(p, []byte("aaa"), 0644)
	v1, ok := getFileVersion(p)
	if !ok {
		t.Fatal("stat failed")
	}
	v2, _ := getFileVersion(p)
	if v1 != v2 {
		t.Fatalf("same content should have identical version: %v vs %v", v1, v2)
	}
	os.WriteFile(p, []byte("bbbb"), 0644)
	v3, _ := getFileVersion(p)
	if v3 == v1 {
		t.Fatal("version must change after file modification (same-second write)")
	}
}
