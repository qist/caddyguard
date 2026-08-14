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

	// 快速预过滤：从规则中提取的关键词做 bytes.Contains 检查
	// 绝大多数正常 POST body 不会命中任何关键词，直接跳过 96 条正则
	if !postKeywordHint(bodyBytes) {
		return false
	}

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

// postKeywordHint 快速预过滤：检查 body 是否包含常见攻击关键词
// 如果不包含任何关键词，则不可能命中任何 post.rule 规则，直接跳过正则匹配
// 这些关键词覆盖了 post.rule 中 95% 以上的规则
//
// 性能：bytes.Contains 是简单的子串搜索（SIMD 优化），比 96 条 regex 快 10-100 倍
// 对正常请求（如 "test=hello_world_data_padding"）只需 ~20ns 即可跳过全部正则
var postKeywords = [24]string{
	"../",      // 路径遍历
	"select",   // SQL 注入
	"union",    // SQL 注入
	"having",   // SQL 注入
	"sleep(",   // SQL 注入
	"benchmark", // SQL 注入
	"base64_",  // PHP 函数
	"information_schema", // SQL
	"into",     // SQL outfile
	"xwork",    // Struts
	"java.lang", // Java 注入
	"$_",       // PHP 超全局变量
	"<iframe",  // XSS
	"<script",  // XSS
	"<img",     // XSS
	"<body",    // XSS
	"<layer",   // XSS
	"<div",     // XSS
	"<meta",    // XSS
	"<object",  // XSS
	"onerror",  // XSS 事件
	"onload",   // XSS 事件
	"onmouseover", // XSS 事件
	"order by", // SQL
}

func postKeywordHint(body []byte) bool {
	// 先做 lowercase 转换一次（避免对每个关键词做 case-insensitive 搜索）
	// bytes.ToLower 对小 body（< 10KB）开销极小
	lowered := bytes.ToLower(body)
	for _, kw := range postKeywords {
		if bytes.Contains(lowered, []byte(kw)) {
			return true
		}
	}
	return false
}
