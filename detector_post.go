package caddyguard

import (
	"bytes"
	"io"
	"net/http"
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
	if err != nil || len(bodyBytes) == 0 {
		return false
	}

	// 恢复 body 供后续 handler 使用（用 bytes.NewReader 避免额外的 string 拷贝）
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	rules := g.ruleCache.GetRule("post.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	// 直接用 bodyBytes 进行匹配，避免 string(bodyBytes) 拷贝
	// matchRules 需要 string 参数，这里必须转换一次
	bodyStr := string(bodyBytes)
	if matched := matchRules(bodyStr, rules, true); matched != nil {
		// 截断过长的 body 用于日志
		logBody := bodyStr
		if len(logBody) > 1024 {
			logBody = logBody[:1024] + "..."
		}
		g.logger.Record("POST", reqURICached(r), logBody, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
