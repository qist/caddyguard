package caddyguard

import (
	"net/http"
)

// userAgentAttackCheck User-Agent 检测
// 1. 先检查白名单 UA：命中 → 仅跳过 UA 检测，不跳过其他检测
// 2. 再检查黑名单 UA：命中 → 拦截
func (g *Guard) userAgentAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.UABlackEnable != "on" {
		return false
	}

	ua := r.UserAgent()
	if ua == "" {
		return false
	}

	// 白名单 UA 检测
	if cfg.UAWhiteEnable == "on" {
		whiteRules := g.ruleCache.GetRule("whiteua.rule", cfg.RuleDir)
		if matched := matchRules(ua, whiteRules, true); matched != nil {
			return false // 白名单命中，跳过 UA 检测
		}
	}

	// 黑名单 UA 检测
	blackRules := g.ruleCache.GetRule("useragent.rule", cfg.RuleDir)
	if matched := matchRules(ua, blackRules, true); matched != nil {
		g.logger.Record("UserAgent", r.URL.String(), "", matched.Raw, g.getClientIP(r, cfg), r, cfg)
		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}
	return false
}
