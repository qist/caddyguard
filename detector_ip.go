package caddyguard

import (
	"net/http"
)

// whiteIPCheck 白名单 IP 检测
// 命中白名单 → 跳过所有检测
func (g *Guard) whiteIPCheck(r *http.Request, cfg Config) bool {
	if cfg.WhiteIPCheck != "on" {
		return false
	}
	clientIP := g.getClientIPCached(r, cfg)
	rules := g.ruleCache.GetRule("whiteip.rule", cfg.RuleDir)
	// IP 规则使用 glob 格式，运行时编译
	for _, rule := range rules {
		if matchRegex(clientIP, globToRegex(rule.Raw), false) {
			return true
		}
	}
	return false
}

// blackIPCheck 黑名单 IP 检测
// 命中 → 拦截
func (g *Guard) blackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.BlackIPCheck != "on" {
		return false
	}
	clientIP := g.getClientIPCached(r, cfg)
	rules := g.ruleCache.GetRule("blackip.rule", cfg.RuleDir)
	for _, rule := range rules {
		if matchRegex(clientIP, globToRegex(rule.Raw), false) {
			g.logger.Record("BlackIP", reqURICached(r), "", rule.Raw, clientIP, r, cfg)
			g.wafOutput(w, cfg)
			return true
		}
	}
	return false
}

// dynamicBlackIPCheck 动态黑名单（CC 自动拉黑）
// 命中 → 拦截
func (g *Guard) dynamicBlackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.CCBlockTTL <= 0 {
		return false
	}
	clientIP := g.getClientIPCached(r, cfg)
	if g.ccStore.IsBanned(clientIP) {
		g.logger.Record("DynamicBlackIP", reqURICached(r), "", "CC Ban", clientIP, r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
