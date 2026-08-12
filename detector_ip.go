package caddyguard

import (
	"net/http"
)

// whiteIPCheck 白名单 IP 检测
// 命中白名单 → 跳过所有检测
func (g *Guard) whiteIPCheck(r *http.Request, cfg Config) bool {
	if cfg.IPWhiteEnable != "on" {
		return false
	}
	clientIP := g.getClientIP(r, cfg)
	rules := g.ruleCache.GetRule("whiteip.rule", cfg.RuleDir)
	if matched := matchRules(clientIP, rules, false); matched != nil {
		return true
	}
	return false
}

// blackIPCheck 黑名单 IP 检测
// 命中 → 拦截
func (g *Guard) blackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.IPBlackEnable != "on" {
		return false
	}
	clientIP := g.getClientIP(r, cfg)
	rules := g.ruleCache.GetRule("blackip.rule", cfg.RuleDir)
	if matched := matchRules(clientIP, rules, false); matched != nil {
		g.logger.Record("BlackIP", r.URL.String(), "", matched.Raw, clientIP, r, cfg)
		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}
	return false
}

// dynamicBlackIPCheck 动态黑名单（CC 自动拉黑）
// 命中 → 拦截
func (g *Guard) dynamicBlackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	clientIP := g.getClientIP(r, cfg)
	if g.ccStore.IsBanned(clientIP) {
		g.logger.Record("DynamicBlackIP", r.URL.String(), "", "CC Ban", clientIP, r, cfg)
		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}
	return false
}
