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

// URLSkipChecks 白名单 URL 命中后需要跳过的检测项集合
// 对应 Lua 的 url_skips 表
// 纯路径格式默认只跳过 url_attack；扩展格式可指定跳过哪些检测项
type URLSkipChecks struct {
	UserAgent  bool
	Referer    bool
	URLAttack  bool
	URLArgs    bool
	Cookie     bool
	Post       bool
	FileUpload bool
	CC         bool
}

// defaultURLSkip 纯路径格式默认只跳过 url_attack
var defaultURLSkip = URLSkipChecks{URLAttack: true}

// whiteURLCheck 白名单 URL 检测
// 命中 → 返回需要跳过的检测项集合（URLSkipChecks）
// 未命中 → 返回 nil
//
// 对应 Lua 的 white_url_check：
//   - 纯路径格式 /path/          → 默认只跳过 url_attack
//   - 扩展格式 /path/ ua,referer  → 跳过指定检测项
//   - 纯路径规则用前缀匹配（HasPrefix），修复子串匹配安全漏洞
//   - 正则规则用 MatchString（向后兼容复杂规则）
func (g *Guard) whiteURLCheck(r *http.Request, cfg Config) *URLSkipChecks {
	if cfg.WhiteURLCheck != "on" {
		return nil
	}
	parsed := g.ruleCache.GetWhiteURLRule(cfg.RuleDir)
	if parsed == nil || (len(parsed.Plain) == 0 && len(parsed.Extended) == 0) {
		return nil
	}

	reqPath := r.URL.Path
	fullURI := reqURICached(r)

	// 1. 扩展格式：前缀匹配或正则匹配，最长匹配优先
	if reqPath != "" && len(parsed.Extended) > 0 {
		var bestSkips *URLSkipChecks
		bestLen := 0
		for i := range parsed.Extended {
			rule := &parsed.Extended[i]
			matched := false
			if rule.IsRegex {
				// 正则规则：用预编译的正则匹配
				if rule.RegexCI != nil && rule.RegexCI.MatchString(reqPath) {
					matched = true
				} else if rule.Regex != nil && rule.Regex.MatchString(reqPath) {
					matched = true
				}
			} else {
				// 普通路径：前缀匹配
				if strings.HasPrefix(reqPath, rule.Path) {
					matched = true
				}
			}
			if matched && len(rule.Path) > bestLen {
				bestSkips = &rule.Skips
				bestLen = len(rule.Path)
			}
		}
		if bestSkips != nil {
			return bestSkips
		}
		// 也检查 fullURI（兼容含查询参数的扩展规则）
		if fullURI != "" && fullURI != reqPath {
			for i := range parsed.Extended {
				rule := &parsed.Extended[i]
				matched := false
				if rule.IsRegex {
					if rule.RegexCI != nil && rule.RegexCI.MatchString(fullURI) {
						matched = true
					} else if rule.Regex != nil && rule.Regex.MatchString(fullURI) {
						matched = true
					}
				} else {
					if strings.HasPrefix(fullURI, rule.Path) {
						matched = true
					}
				}
				if matched && len(rule.Path) > bestLen {
					bestSkips = &rule.Skips
					bestLen = len(rule.Path)
				}
			}
			if bestSkips != nil {
				return bestSkips
			}
		}
	}

	// 2. 纯路径格式：前缀匹配（修复子串匹配安全漏洞）
	if reqPath != "" {
		for _, prefix := range parsed.Plain {
			if strings.HasPrefix(reqPath, prefix) {
				return &defaultURLSkip
			}
		}
	}
	// 也检查 fullURI
	if fullURI != "" && fullURI != reqPath {
		for _, prefix := range parsed.Plain {
			if strings.HasPrefix(fullURI, prefix) {
				return &defaultURLSkip
			}
		}
	}

	// 3. 正则规则（向后兼容复杂规则）
	if len(parsed.Regex) > 0 {
		if reqPath != "" {
			if matched := matchRules(reqPath, parsed.Regex, true); matched != nil {
				return &defaultURLSkip
			}
		}
		if fullURI != "" && fullURI != reqPath {
			if matched := matchRules(fullURI, parsed.Regex, true); matched != nil {
				return &defaultURLSkip
			}
		}
	}

	return nil
}
