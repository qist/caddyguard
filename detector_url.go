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

	// 参数截断保护（对应 Lua req_get_uri_args(256) 限制）
	// 当参数数量超过 256 时，只遍历前 256 个，然后回退到原始 RawQuery 扫描
	const maxArgsParse = 256
	argsTruncated := len(query) > maxArgsParse

	// 遍历参数（key + value），截断时只扫前 256 个
	count := 0
	for key, vals := range query {
		if argsTruncated && count >= maxArgsParse {
			break
		}
		count++
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

	// 参数截断回退：扫描原始 RawQuery 字符串（对应 Lua 的 var.args 回退）
	// 防止攻击者用 256+ 参数把攻击 payload 藏在截断后的参数中
	if argsTruncated {
		rawArgs := r.URL.RawQuery
		if rawArgs != "" {
			// 1. 匹配原始 RawQuery
			if matched := matchRules(rawArgs, rules, true); matched != nil {
				g.logger.Record("URLArgs", reqURICached(r), "truncated_query", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				g.wafOutput(w, cfg)
				return true
			}
			// 2. + 号替换为空格后匹配（对应 Lua 的 normalized_args）
			var normalizedArgs string
			if strings.Contains(rawArgs, "+") {
				normalizedArgs = strings.ReplaceAll(rawArgs, "+", " ")
				if matched := matchRules(normalizedArgs, rules, true); matched != nil {
					g.logger.Record("URLArgs", reqURICached(r), "truncated_query", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					g.wafOutput(w, cfg)
					return true
				}
			}
			// 3. URL 解码后匹配
			if hasEncodeMarkers(rawArgs) {
				if decoded, changed := fullDecode(rawArgs); changed {
					if matched := matchRules(decoded, rules, true); matched != nil {
						g.logger.Record("URLArgs", reqURICached(r), "truncated_query", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
						g.wafOutput(w, cfg)
						return true
					}
				}
			}
			// 4. normalized + 解码后匹配
			if normalizedArgs != "" && hasEncodeMarkers(normalizedArgs) {
				if decoded, changed := fullDecode(normalizedArgs); changed {
					if matched := matchRules(decoded, rules, true); matched != nil {
						g.logger.Record("URLArgs", reqURICached(r), "truncated_query", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
						g.wafOutput(w, cfg)
						return true
					}
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
