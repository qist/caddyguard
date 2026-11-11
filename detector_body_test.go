package caddyguard

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// body 完整性与 multipart 检测语义测试 (对齐 Lua 修复后行为):
//   - 业务 body 永不截断 (原 32MB 硬上限会把超大上传截断后恢复给 handler, 属于业务损坏)
//   - multipart streaming on: 超 post_body_scan_limit 拒绝; 未超限全文件分块扫描 (64KB+2KB overlap)
//   - multipart streaming off: 跳过内容扫描, body 完整转发 (对应 Lua 跳过行为)
//   - 非 multipart: 超限拒绝 (原行为)

// buildMultipart 构造 multipart body: 一个文件 part (可含攻击 payload) + 可选普通字段
func buildMultipart(t *testing.T, fileContentSize int, filePayload string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("upload", "data.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(strings.Repeat("A", fileContentSize))); err != nil {
		t.Fatal(err)
	}
	if filePayload != "" {
		if _, err := fw.Write([]byte(filePayload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func runBodyRequest(t *testing.T, g *Guard, contentType string, body []byte, nextBodyLen *int) int {
	t.Helper()
	r := httptest.NewRequest("POST", "http://test.local/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	err := g.ServeHTTP(w, r, caddyhttpHandler(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if nextBodyLen != nil {
			*nextBodyLen = len(b)
		}
		w.WriteHeader(200)
	}))
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	return w.Code
}

func newBodyTestGuard(t *testing.T, streamingOn bool) *Guard {
	t.Helper()
	streaming := "off"
	if streamingOn {
		streaming = "on"
	}
	return newTempGuard(t, map[string]any{
		"waf_enable":                "on",
		"post_check":                "on",
		"file_upload_check":         "on",
		"multipart_streaming_check": streaming,
	}, map[string]string{
		"post.rule":    "unionselect\n",
		"fileext.rule": ".php\n",
	})
}

// T1 超大 multipart (超过原 32MB 硬上限, streaming off): body 必须完整恢复给 handler
func TestMultipartLargeBodyNotTruncated(t *testing.T) {
	g := newBodyTestGuard(t, false)
	contentType, body := buildMultipart(t, 40*1024*1024, "")
	var nextLen int
	code := runBodyRequest(t, g, contentType, body, &nextLen)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if nextLen != len(body) {
		t.Fatalf("body truncated: handler got %d bytes, sent %d (old 32MB cap bug)", nextLen, len(body))
	}
}

// T2 multipart streaming on 超 post_body_scan_limit: 拒绝 (部分扫描放行 = fail-open)
func TestMultipartStreamingOn_OversizeDenied(t *testing.T) {
	g := newBodyTestGuard(t, true)
	contentType, body := buildMultipart(t, 3*1024*1024, "")
	code := runBodyRequest(t, g, contentType, body, nil)
	if code != 403 {
		t.Fatalf("expected 403 (oversize multipart with streaming on), got %d", code)
	}
}

// T3 multipart streaming off: 跳过内容扫描 (对齐 Lua 跳过行为), body 完整
func TestMultipartStreamingOff_PayloadSkipped(t *testing.T) {
	g := newBodyTestGuard(t, false)
	contentType, body := buildMultipart(t, 1024*1024, "unionselect123")
	var nextLen int
	code := runBodyRequest(t, g, contentType, body, &nextLen)
	if code != 200 {
		t.Fatalf("streaming off should skip multipart content scan, got %d", code)
	}
	if nextLen != len(body) {
		t.Fatalf("body truncated: got %d, sent %d", nextLen, len(body))
	}
}

// T4 multipart streaming on 未超限: 文件 part 内容中的 payload 分块扫描检出
func TestMultipartStreamingOn_PayloadDetected(t *testing.T) {
	g := newBodyTestGuard(t, true)
	contentType, body := buildMultipart(t, 1024*1024, "unionselect123")
	code := runBodyRequest(t, g, contentType, body, nil)
	if code != 403 {
		t.Fatalf("streaming on should detect payload in file part (chunk scan), got %d", code)
	}
}

// T5 multipart streaming on 无 payload: 放行且 body 完整
func TestMultipartStreamingOn_CleanBodyIntact(t *testing.T) {
	g := newBodyTestGuard(t, true)
	contentType, body := buildMultipart(t, 1024*1024, "")
	var nextLen int
	code := runBodyRequest(t, g, contentType, body, &nextLen)
	if code != 200 {
		t.Fatalf("clean multipart under limit should pass, got %d", code)
	}
	if nextLen != len(body) {
		t.Fatalf("body truncated: got %d, sent %d", nextLen, len(body))
	}
}

// T6 非 multipart 超限: 拒绝 (原行为回归)
func TestNonMultipartOversizeDenied(t *testing.T) {
	g := newBodyTestGuard(t, true)
	body := []byte(strings.Repeat("A", 3*1024*1024))
	code := runBodyRequest(t, g, "application/json", body, nil)
	if code != 403 {
		t.Fatalf("expected 403 for oversize non-multipart body, got %d", code)
	}
}

// T7 大 body (落盘路径, >8MB 内存阈值) 负缓存/晋升路径混跑无泄漏: 连续请求复检一致
func TestMultipartLargeBodyRepeated(t *testing.T) {
	g := newBodyTestGuard(t, false)
	contentType, body := buildMultipart(t, 9*1024*1024, "")
	for i := 0; i < 3; i++ {
		var nextLen int
		code := runBodyRequest(t, g, contentType, body, &nextLen)
		if code != 200 {
			t.Fatalf("run %d: expected 200, got %d", i, code)
		}
		if nextLen != len(body) {
			t.Fatalf("run %d: body truncated: got %d, sent %d", i, nextLen, len(body))
		}
	}
}
