package caddyguard

import (
	"io"
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

	// 限制读取大小（防止超大 body 消耗内存）
	maxSize := int64(10 * 1024 * 1024) // 10MB
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	r.Body.Close()
	if err != nil {
		return false
	}

	// 恢复 body 供后续 handler 使用
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	bodyStr := string(bodyBytes)
	if bodyStr == "" {
		return false
	}

	rules := g.ruleCache.GetRule("post.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	if matched := matchRules(bodyStr, rules, true); matched != nil {
		// 截断过长的 body 用于日志
		logBody := bodyStr
		if len(logBody) > 1024 {
			logBody = logBody[:1024] + "..."
		}
		g.logger.Record("POST", r.URL.RequestURI(), logBody, matched.Raw, g.getClientIP(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
