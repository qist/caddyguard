package caddyguard

import (
	"net/http"
	"strings"
)

// urlAttackCheck URL 路径检测
// 检查 URI path 是否包含攻击特征
func (g *Guard) urlAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.URLBlackEnable != "on" {
		return false
	}

	// 扩展名检测
	if cfg.Exts != "" && cfg.ExtsCheck != "" {
		exts := strings.Split(cfg.Exts, ",")
		pathLower := strings.ToLower(r.URL.Path)
		for _, ext := range exts {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if strings.HasSuffix(pathLower, strings.ToLower(ext)) {
				if cfg.ExtsCheck == "black" {
					// 黑名单扩展名 → 拦截
					g.logger.Record("URLAttack", r.URL.String(), "", "BlackExt: "+ext, g.getClientIP(r, cfg), r, cfg)
					if cfg.WAFMode == "block" {
						g.wafOutput(w, cfg)
					}
					return true
				}
				// 白名单扩展名 → 跳过后续 URL 检测
				return false
			}
		}
		// 白名单模式且未命中白名单扩展名 → 拦截
		if cfg.ExtsCheck == "white" {
			return false // 不拦截，仅跳过 URL 规则检测
		}
	}

	// URL 路径正则检测
	rules := g.ruleCache.GetRule("url.rule", cfg.RuleDir)
	uri := r.URL.Path
	if matched := matchRules(uri, rules, true); matched != nil {
		g.logger.Record("URLAttack", uri, "", matched.Raw, g.getClientIP(r, cfg), r, cfg)
		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}
	return false
}

// urlArgsAttackCheck URL 参数检测
// 检查 Query String 是否包含攻击特征
func (g *Guard) urlArgsAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.ArgsEnable != "on" {
		return false
	}

	rawQuery := r.URL.RawQuery
	if rawQuery == "" {
		return false
	}

	// URL 解码后的参数检测
	rules := g.ruleCache.GetRule("args.rule", cfg.RuleDir)
	if matched := matchRules(rawQuery, rules, true); matched != nil {
		g.logger.Record("URLArgs", r.URL.String(), "", matched.Raw, g.getClientIP(r, cfg), r, cfg)
		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}

	// 逐个参数值检测
	for _, values := range r.URL.Query() {
		for _, v := range values {
			if matched := matchRules(v, rules, true); matched != nil {
				g.logger.Record("URLArgs", r.URL.String(), v, matched.Raw, g.getClientIP(r, cfg), r, cfg)
				if cfg.WAFMode == "block" {
					g.wafOutput(w, cfg)
				}
				return true
			}
		}
	}
	return false
}

// whiteURLCheck 白名单 URL 检测
// 命中 → 跳过所有检测（IP 白名单除外）
func (g *Guard) whiteURLCheck(r *http.Request, cfg Config) bool {
	if cfg.URLWhiteEnable != "on" {
		return false
	}
	rules := g.ruleCache.GetRule("whiteurl.rule", cfg.RuleDir)
	uri := r.URL.Path
	if matched := matchRules(uri, rules, true); matched != nil {
		return true
	}
	return false
}
