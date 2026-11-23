package caddyguard

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newComboTestGuard(t *testing.T, combo string) *Guard {
	t.Helper()
	dir := t.TempDir()
	if combo != "" {
		if err := os.WriteFile(filepath.Join(dir, comboRuleFile), []byte(combo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Guard{
		RuleDir:   dir,
		ruleCache: NewRuleCache(dir),
		ccStore:   NewMemoryStore(),
		logger:    NewWAFLogger(t.TempDir()),
	}
}

func runComboRequest(g *Guard, cfg Config, r *http.Request) bool {
	w := httptest.NewRecorder()
	return g.runCombo(w, r, cfg)
}

func TestComboInlineCaseInsensitiveDefaults(t *testing.T) {
	g := newComboTestGuard(t, strings.Join([]string{
		`{"id":"re","if":{"cond":"args","op":"re","value":"secret="},"action":"BLOCK"}`,
		`{"id":"contains","if":{"cond":"args","op":"contains","value":"evil"},"action":"BLOCK"}`,
		`{"id":"prefix","if":{"cond":"uri","op":"prefix","value":"/ADMIN"},"action":"BLOCK"}`,
		`{"id":"eq","if":{"cond":"args","op":"eq","value":"A=1"},"action":"BLOCK"}`,
	}, "\n"))
	cfg := DefaultConfig()

	for name, target := range map[string]string{
		"re":       "/?SECRET=1",
		"contains": "/?x=EVIL",
		"prefix":   "/admin",
		"eq":       "/?a=1",
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if !runComboRequest(g, cfg, r) {
			t.Fatalf("%s: expected combo block with case-insensitive default", name)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/?x=good", nil)
	if runComboRequest(g, cfg, r) {
		t.Fatal("unexpected block for non-matching request")
	}
}

func TestComboCaseInsensitiveOptOut(t *testing.T) {
	g := newComboTestGuard(t, strings.Join([]string{
		`{"id":"re-cs","if":{"cond":"args","op":"re","value":"secret=","flags":"jo"},"action":"BLOCK"}`,
		`{"id":"contains-cs","if":{"cond":"args","op":"contains","value":"evil","icase":false},"action":"BLOCK"}`,
		`{"id":"prefix-cs","if":{"cond":"uri","op":"prefix","value":"/ADMIN","icase":false},"action":"BLOCK"}`,
	}, "\n"))
	cfg := DefaultConfig()

	for name, target := range map[string]string{
		"re-cs":       "/?SECRET=1",
		"contains-cs": "/?x=EVIL",
		"prefix-cs":   "/admin",
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if runComboRequest(g, cfg, r) {
			t.Fatalf("%s: expected no match after opt-out", name)
		}
	}
}

func TestComboMethodEqStaysCaseSensitive(t *testing.T) {
	g := newComboTestGuard(t, `{"id":"lower","if":{"cond":"method","op":"eq","value":"post"},"action":"BLOCK"}`)
	cfg := DefaultConfig()

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if runComboRequest(g, cfg, r) {
		t.Fatal("method eq must stay case-sensitive for 'post' vs POST")
	}

	g = newComboTestGuard(t, `{"id":"upper","if":{"cond":"method","op":"eq","value":"POST"},"action":"BLOCK"}`)
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	if !runComboRequest(g, cfg, r) {
		t.Fatal("POST should match eq POST")
	}
}

func TestComboScoreThreshold(t *testing.T) {
	g := newComboTestGuard(t, strings.Join([]string{
		`{"id":"s1","if":{"cond":"uri","op":"prefix","value":"/score"},"action":"SCORE","score":10}`,
		`{"id":"s2","if":{"cond":"uri","op":"prefix","value":"/score"},"action":"SCORE","score":10}`,
	}, "\n"))

	cfg := DefaultConfig()
	cfg.ScoreBlockThreshold = 0
	if runComboRequest(g, cfg, httptest.NewRequest(http.MethodGet, "/score", nil)) {
		t.Fatal("threshold 0 must not block SCORE")
	}

	cfg.ScoreBlockThreshold = 1
	if !runComboRequest(g, cfg, httptest.NewRequest(http.MethodGet, "/score", nil)) {
		t.Fatal("threshold 1 must block on first SCORE")
	}

	cfg.ScoreBlockThreshold = 20
	if !runComboRequest(g, cfg, httptest.NewRequest(http.MethodGet, "/score", nil)) {
		t.Fatal("threshold 20 must block after two SCORE rules")
	}
}

func TestComboBodyLimit(t *testing.T) {
	g := newComboTestGuard(t, `{"id":"body","if":{"cond":"body","op":"re","value":"secret"},"action":"BLOCK"}`)
	cfg := DefaultConfig()

	body := strings.Repeat("a", 1024) + "secret"
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if !runComboRequest(g, cfg, r) {
		t.Fatal("body match under 2MiB should block")
	}
	restored, err := io.ReadAll(r.Body)
	if err != nil || string(restored) != body {
		t.Fatalf("body not restored after scan: len=%d err=%v", len(restored), err)
	}

	large := strings.Repeat("a", comboBodyLimit+1)
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(large))
	if !runComboRequest(g, cfg, r) {
		t.Fatal("truncated body with BLOCK rule must fail closed")
	}
	restored, err = io.ReadAll(r.Body)
	if err != nil || len(restored) != len(large) {
		t.Fatalf("large body not fully restored: len=%d want=%d err=%v", len(restored), len(large), err)
	}
}

func TestComboInvalidRegexSkipped(t *testing.T) {
	g := newComboTestGuard(t, strings.Join([]string{
		`{"id":"bad","if":{"cond":"uri","op":"re","value":"["},"action":"BLOCK"}`,
		`{"id":"good","if":{"cond":"uri","op":"prefix","value":"/admin"},"action":"BLOCK"}`,
	}, "\n"))
	cfg := DefaultConfig()

	if runComboRequest(g, cfg, httptest.NewRequest(http.MethodGet, "/bad", nil)) {
		t.Fatal("invalid regex rule should be skipped")
	}
	if !runComboRequest(g, cfg, httptest.NewRequest(http.MethodGet, "/admin", nil)) {
		t.Fatal("valid rule should still work")
	}
}

func TestComboHeaderCountAndContentLength(t *testing.T) {
	g := newComboTestGuard(t, `{"id":"hdr","if":{"cond":"header_count","op":"gte","value":80},"action":"BLOCK"}`)
	cfg := DefaultConfig()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < 80; i++ {
		r.Header.Set(fmt.Sprintf("X-Test-%d", i), "v")
	}
	if !runComboRequest(g, cfg, r) {
		t.Fatal("header_count >= 80 should block")
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < 10; i++ {
		r.Header.Set(fmt.Sprintf("X-Test-%d", i), "v")
	}
	if runComboRequest(g, cfg, r) {
		t.Fatal("header_count below threshold must not block")
	}
}

func TestComboH2HeaderFlood(t *testing.T) {
	g := newComboTestGuard(t, `{"id":"h2","if":["AND",{"cond":"protocol","op":"eq","value":"HTTP/2.0"},{"cond":"content_type","op":"exists"},["NOT",{"cond":"content_length","op":"exists"}],{"cond":"header_count","op":"gte","value":80}],"action":"BLOCK"}`)
	cfg := DefaultConfig()

	addHeaders := func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain")
		for i := 0; i < 80; i++ {
			r.Header.Set(fmt.Sprintf("X-Test-%d", i), "v")
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Proto = "HTTP/2.0"
	addHeaders(r)
	if !runComboRequest(g, cfg, r) {
		t.Fatal("HTTP/2 header flood should block")
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Proto = "HTTP/2.0"
	addHeaders(r)
	r.Header.Set("Content-Length", "0")
	if runComboRequest(g, cfg, r) {
		t.Fatal("Content-Length present must not block")
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Proto = "HTTP/1.1"
	addHeaders(r)
	if runComboRequest(g, cfg, r) {
		t.Fatal("HTTP/1.1 must not match HTTP/2 rule")
	}
}

func TestComboLegacyUsesCachedDetectorFact(t *testing.T) {
	g := newComboTestGuard(t, `{"id":"observe-url","if":"url","action":"LOG"}`)
	dir := g.RuleDir
	if err := os.WriteFile(filepath.Join(dir, "url.rule"), []byte("/etc/passwd"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	r := httptest.NewRequest(http.MethodGet, "/etc/passwd", nil)
	w := httptest.NewRecorder()

	if g.runCombo(w, r, cfg) {
		t.Fatal("LOG rule must not block")
	}
	if !g.legacyBlock(w, r, cfg, "url") {
		t.Fatal("legacy block should reuse cached URL detector fact")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}
