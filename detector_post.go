package caddyguard

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

// postAttackCheck POST body 检测
// 读取 body 并进行规则匹配，同时保证 body 可被后续 handler 重新读取
func (g *Guard) postAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.PostCheck != "on" {
		return false
	}

	// 仅检查 POST/PUT/PATCH
	method := r.Method
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}

	if r.Body == nil {
		return false
	}

	// 只检测有 body 的请求
	if r.ContentLength == 0 {
		return false
	}

	// Multipart bodies are handled by fileUploadCheck. Scanning the entire
	// multipart payload with all POST rules would duplicate both the read and
	// the regex work before the upload detector reads it again.
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil && strings.EqualFold(mediaType, "multipart/form-data") {
			return false
		}
	}

	// Load rules before touching the body. An enabled detector with an empty
	// rule file should be a true no-op and must not consume/rebuild the body.
	rules := g.ruleCache.GetRule("post.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	// 限制读取大小（防止超大 body 消耗内存）
	maxSize := int64(10 * 1024 * 1024) // 10MB
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	r.Body.Close()
	if err != nil || len(bodyBytes) == 0 {
		return false
	}

	// 恢复 body 供后续 handler 使用（用 bytes.NewReader 避免额外的 string 拷贝）
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Match []byte directly. This avoids a second allocation the size of the
	// request body caused by converting bodyBytes to string.
	if matched := matchRulesBytes(bodyBytes, rules, true); matched != nil {
		// 截断过长的 body 用于日志
		logBody := bodyBytes
		if len(logBody) > 1024 {
			logBody = logBody[:1024]
		}
		logData := string(logBody)
		if len(bodyBytes) > 1024 {
			logData += "..."
		}
		g.logger.Record("POST", reqURICached(r), logData, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
