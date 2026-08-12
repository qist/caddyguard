package caddyguard

import (
	"net/http"
)

// refererCheck Referer 检测
// 检查 Referer 头是否包含攻击特征
func (g *Guard) refererCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.RefererCheck != "on" {
		return false
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		return false
	}

	rules := g.ruleCache.GetRule("referer.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	if matched := matchRules(referer, rules, true); matched != nil {
		g.logger.Record("Referer", r.URL.RequestURI(), referer, matched.Raw, g.getClientIP(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
