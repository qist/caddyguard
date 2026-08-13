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
