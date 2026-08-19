package caddyguard

import (
	"net/http"
	"net/url"
	"strings"
)

// urlAttackCheck URL 路径检测
// 检查 URI path 是否包含攻击特征
// 对应 Lua 的 url_attack_check：先匹配原始 URI，再尝试解码后匹配
func (g *Guard) urlAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.URLCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("url.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	reqURI := reqURICached(r)

	// 1. 先匹配原始 URI
	if matched := matchRules(reqURI, rules, true); matched != nil {
		g.logger.Record("URLAttack", reqURI, "", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}

	// 2. 尝试 URL 解码后匹配（防编码路径穿越，如 %2e%2e%2f）
	if hasEncodeMarkers(reqURI) {
		decodedURI, err := url.PathUnescape(reqURI)
		if err == nil && decodedURI != reqURI {
			if matched := matchRules(decodedURI, rules, true); matched != nil {
				g.logger.Record("URLAttack", reqURI, "", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				g.wafOutput(w, cfg)
				return true
			}
		}
	}

	return false
}

// urlArgsAttackCheck URL 参数检测
// 检查 Query String 是否包含攻击特征
// 对应 Lua 的 url_args_attack_check：先匹配原始值，再尝试 fullDecode 后匹配
func (g *Guard) urlArgsAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.URLArgsCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("args.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	// 无查询参数时直接返回（对应 Lua 的 next(REQ_ARGS) == nil 短路）
	query := r.URL.Query()
	if len(query) == 0 {
		return false
	}

	// 遍历所有参数（key + value）
	for key, vals := range query {
		// 检查参数名（key）
		if key != "" {
			if matched := matchRules(key, rules, true); matched != nil {
				g.logger.Record("URLArgs", reqURICached(r), "key:"+key, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				g.wafOutput(w, cfg)
				return true
			}
			// 尝试解码后匹配
			if hasEncodeMarkers(key) {
				if decoded, changed := fullDecode(key); changed {
					if matched := matchRules(decoded, rules, true); matched != nil {
						g.logger.Record("URLArgs", reqURICached(r), "key:"+key, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
						g.wafOutput(w, cfg)
						return true
					}
				}
			}
		}

		// 检查参数值
		val := strings.Join(vals, " ")
		if val == "" {
			continue
		}

		if matched := matchRules(val, rules, true); matched != nil {
			g.logger.Record("URLArgs", reqURICached(r), val, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}

		// 尝试解码后匹配
		if hasEncodeMarkers(val) {
			if decoded, changed := fullDecode(val); changed {
				if matched := matchRules(decoded, rules, true); matched != nil {
					g.logger.Record("URLArgs", reqURICached(r), val, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					g.wafOutput(w, cfg)
					return true
				}
			}
		}
	}

	return false
}

// whiteURLCheck 白名单 URL 检测
// 命中 → 跳过所有检测（IP 白名单除外）
//
// 对应 Lua 的 white_url_check：
//   - 先匹配 URI path（r.URL.Path），这是最常见的白名单场景（如 /static/, /api/login）
//   - 再匹配完整 request_uri（含 query string），兼容有意包含查询参数的白名单规则
func (g *Guard) whiteURLCheck(r *http.Request, cfg Config) bool {
	if cfg.WhiteURLCheck != "on" {
		return false
	}
	rules := g.ruleCache.GetRule("whiteurl.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	// 1. 先匹配 URI path（纯路径，不含 query string）
	reqPath := r.URL.Path
	if reqPath != "" {
		if matched := matchRules(reqPath, rules, true); matched != nil {
			return true
		}
	}

	// 2. 再匹配完整 request_uri（含 query string），兼容含查询参数的白名单规则
	fullURI := reqURICached(r)
	if fullURI != "" && fullURI != reqPath {
		if matched := matchRules(fullURI, rules, true); matched != nil {
			return true
		}
	}

	return false
}
