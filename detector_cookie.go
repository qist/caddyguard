package caddyguard

import (
	"net/http"
)

// cookieAttackCheck Cookie 检测
// 检查 Cookie 头是否包含攻击特征
// 对应 Lua 的 cookie_attack_check：先匹配原始值，再尝试 fullDecode 后匹配
func (g *Guard) cookieAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.CookieCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("cookie.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	cookieHeader := r.Header.Get("Cookie")
	if cookieHeader == "" {
		return false
	}

	// 1. 匹配整个 Cookie 头
	if matched := matchRules(cookieHeader, rules, true); matched != nil {
		g.logger.Record("Cookie", reqURICached(r), cookieHeader, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}

	// 2. 解码后匹配整个 Cookie 头
	if hasEncodeMarkers(cookieHeader) {
		if decoded, changed := fullDecode(cookieHeader); changed {
			if matched := matchRules(decoded, rules, true); matched != nil {
				g.logger.Record("Cookie", reqURICached(r), cookieHeader, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				g.wafOutput(w, cfg)
				return true
			}
		}
	}

	// 3. 逐个 cookie 值检测
	for _, cookie := range r.Cookies() {
		// 原始值匹配
		if matched := matchRules(cookie.Value, rules, true); matched != nil {
			g.logger.Record("Cookie", reqURICached(r), cookie.Value, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}
		// 解码后匹配
		if hasEncodeMarkers(cookie.Value) {
			if decoded, changed := fullDecode(cookie.Value); changed {
				if matched := matchRules(decoded, rules, true); matched != nil {
					g.logger.Record("Cookie", reqURICached(r), cookie.Value, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					g.wafOutput(w, cfg)
					return true
				}
			}
		}
	}

	return false
}
