package caddyguard

import (
	"net/http"
)

// cookieAttackCheck Cookie 检测
// 检查 Cookie 头是否包含攻击特征
func (g *Guard) cookieAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.CookieCheck != "on" {
		return false
	}

	cookieHeader := r.Header.Get("Cookie")
	if cookieHeader == "" {
		return false
	}

	rules := g.ruleCache.GetRule("cookie.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	if matched := matchRules(cookieHeader, rules, true); matched != nil {
		g.logger.Record("Cookie", reqURICached(r), cookieHeader, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}

	// 逐个 cookie 值检测
	for _, cookie := range r.Cookies() {
		if matched := matchRules(cookie.Value, rules, true); matched != nil {
			g.logger.Record("Cookie", reqURICached(r), cookie.Value, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}
	}
	return false
}
