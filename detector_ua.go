package caddyguard

import (
	"net/http"
)

// isWhiteUA 白名单 UA 检测（仅跳过 UA 黑名单）
func (g *Guard) isWhiteUA(r *http.Request, cfg Config) bool {
	if cfg.WhiteUACheck != "on" {
		return false
	}
	rules := g.ruleCache.GetRule("whiteua.rule", cfg.RuleDir)
	ua := r.UserAgent()
	if ua == "" {
		return false
	}
	if matched := matchRules(ua, rules, true); matched != nil {
		return true
	}
	return false
}

// userAgentAttackCheck User-Agent 检测
// 1. 先检查白名单 UA：命中 → 仅跳过 UA 检测
// 2. 再检查黑名单 UA：命中 → 拦截
func (g *Guard) userAgentAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.UserAgentCheck != "on" {
		return false
	}

	ua := r.UserAgent()
	if ua == "" {
		return false
	}

	// 白名单 UA 检测
	if g.isWhiteUA(r, cfg) {
		return false
	}

	// 黑名单 UA 检测
	blackRules := g.ruleCache.GetRule("useragent.rule", cfg.RuleDir)
	if matched := matchRules(ua, blackRules, true); matched != nil {
		g.logger.Record("UserAgent", r.URL.RequestURI(), "", matched.Raw, g.getClientIP(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
