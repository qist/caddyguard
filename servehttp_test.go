package caddyguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 最小化测试：验证 Guard.ServeHTTP 基本流程
func TestServeHTTP_Minimal(t *testing.T) {
	g := &Guard{
		RuleDir:   "../rule-config",
		ruleCache: NewRuleCache("../rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger("/tmp"),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	r.Host = "localhost:8888"

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	err := g.ServeHTTP(w, r, caddyhttpHandler(next))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !nextCalled {
		t.Fatal("next handler was not called")
	}

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	t.Logf("Response: %s, Status: %d", w.Body.String(), w.Code)
}

// caddyhttpHandler wraps http.HandlerFunc to implement caddyhttp.Handler
type caddyHandler struct {
	h http.HandlerFunc
}

func (c *caddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	c.h(w, r)
	return nil
}

func caddyhttpHandler(h http.HandlerFunc) *caddyHandler {
	return &caddyHandler{h: h}
}

// TestServeHTTP_RepanicAbortHandler 验证下游 handler panic http.ErrAbortHandler 时
// caddyguard 按标准语义 re-panic（不吞掉、不记 error、不写响应）
// 对应线上问题: reverse_proxy 流式接口（SSE 日志流）中止时被误记为 caddyguard panic
func TestServeHTTP_RepanicAbortHandler(t *testing.T) {
	g := &Guard{
		RuleDir:   "../rule-config",
		ruleCache: NewRuleCache("../rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger("/tmp"),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/log-manage/nodes/1/logs/xray/stream", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	r.Host = "panel.example.com"

	aborted := false
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				aborted = true
				if rv != http.ErrAbortHandler {
					t.Fatalf("expected http.ErrAbortHandler to propagate, got %v", rv)
				}
			}
		}()
		_ = g.ServeHTTP(w, r, caddyhttpHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler) // reverse_proxy 流式中止的故意 panic
		})))
	}()

	if !aborted {
		t.Fatal("http.ErrAbortHandler must re-panic (not be swallowed by caddyguard)")
	}
}

// TestServeHTTP_RecoverRealPanic 验证真实 panic 仍被 caddyguard 恢复为 500
func TestServeHTTP_RecoverRealPanic(t *testing.T) {
	g := &Guard{
		RuleDir:   "../rule-config",
		ruleCache: NewRuleCache("../rule-config"),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger("/tmp"),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	r.Host = "localhost:8888"

	err := g.ServeHTTP(w, r, caddyhttpHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})))
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after real panic, got %d", w.Code)
	}
}
