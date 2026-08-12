package caddyguard

import (
	"net/http"
	"net/url"
	"strings"
)

// urlAttackCheck URL 路径检测
// 检查 URI path 是否包含攻击特征
func (g *Guard) urlAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.URLCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("url.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	reqURI := reqURICached(r)
	if matched := matchRules(reqURI, rules, false); matched != nil {
		g.logger.Record("URLAttack", reqURI, "", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}

// urlArgsAttackCheck URL 参数检测
// 检查 Query String 是否包含攻击特征
func (g *Guard) urlArgsAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.URLArgsCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("args.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	query := r.URL.Query()
	for _, vals := range query {
		val := strings.Join(vals, " ")
		decoded, err := url.QueryUnescape(val)
		if err != nil {
			decoded = val
		}
		if matched := matchRules(decoded, rules, false); matched != nil {
			g.logger.Record("URLArgs", reqURICached(r), val, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}
	}
	return false
}

// whiteURLCheck 白名单 URL 检测
// 命中 → 跳过所有检测（IP 白名单除外）
func (g *Guard) whiteURLCheck(r *http.Request, cfg Config) bool {
	if cfg.WhiteURLCheck != "on" {
		return false
	}
	rules := g.ruleCache.GetRule("whiteurl.rule", cfg.RuleDir)
	reqURI := reqURICached(r)
	if matched := matchRules(reqURI, rules, false); matched != nil {
		return true
	}
	return false
}
