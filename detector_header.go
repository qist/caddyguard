package caddyguard

import (
	"context"
	"net/http"
	"strings"
)

// getHeaderTextCached 构建 "Name: value" 多行请求头文本（per-request 缓存）
// 对应 Lua access.lua 的 get_header_text()：结果缓存在 ngx.ctx._hdr_text，
// 同请求内多个检测项复用，不重复拼接
func getHeaderTextCached(r *http.Request) string {
	if v, ok := r.Context().Value(keyHeaderText).(string); ok {
		return v
	}
	text := buildHeaderText(r)
	// 存入 context（r.WithContext 返回新 *http.Request）
	*r = *r.WithContext(context.WithValue(r.Context(), keyHeaderText, text))
	return text
}

// buildHeaderText 将所有请求头拼成 "Name: value" 多行文本
// 与 Lua 版一致：Host 头在 Go 中不在 r.Header 里，需单独补上；
// 重复头（如多个 Cookie）逐个拼接，与 ngx.req.get_headers(0) 的表遍历一致
func buildHeaderText(r *http.Request) string {
	var b strings.Builder
	if r.Host != "" {
		b.WriteString("Host: ")
		b.WriteString(r.Host)
		b.WriteByte('\n')
	}
	for name, values := range r.Header {
		for _, v := range values {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	// 去掉末尾换行，与 Lua table_concat(parts, "\n") 保持一致
	text := b.String()
	if len(text) > 0 {
		text = text[:len(text)-1]
	}
	return text
}

// headerAttackCheck 请求头检测（header.rule）
// 对应 Lua 的 header_attack_check：
//   - 检测对象是所有请求头拼接成的 "Name: value" 多行文本
//   - 用大小写不敏感 + 多行模式匹配（规则里的 ^ 可锚定任意头名开头）
//   - 命中后记录 Deny_Header 日志并拦截
//
// 典型规则：X-Middleware-Subrequest（Next.js CVE-2025-29927）、
// X-Original-URL / X-Rewrite-URL 绕过头、云元数据 SSRF 代理头、Log4Shell ${jndi:
func (g *Guard) headerAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.HeaderCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("header.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	headerText := getHeaderTextCached(r)
	if headerText == "" {
		return false
	}

	if matched := matchRules(headerText, rules, true); matched != nil {
		g.logger.Record("Header", reqURICached(r), "", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
