package caddyguard

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// postAttackCheck POST body 检测
// 对应 Lua 的 post_attack_check：
//   - form-urlencoded: 解析 key/value 逐一匹配，完成后跳过 raw body 二次扫描
//   - JSON/XML/plain-text: 直接走 raw body 扫描
//   - multipart: 跳过（由 fileUploadCheck 处理）
func (g *Guard) postAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.PostCheck != "on" {
		return false
	}

	// 仅检查 POST/PUT/PATCH
	method := r.Method
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}

	if r.Body == nil {
		return false
	}

	// 只检测有 body 的请求
	if r.ContentLength == 0 {
		return false
	}

	// Multipart bodies are handled by fileUploadCheck. Scanning the entire
	// multipart payload with all POST rules would duplicate both the read and
	// the regex work before the upload detector reads it again.
	contentType := r.Header.Get("Content-Type")
	isFormURLEncoded := false
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			if strings.EqualFold(mediaType, "multipart/form-data") {
				return false
			}
			if strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
				isFormURLEncoded = true
			}
		}
	}

	// Load rules before touching the body. An enabled detector with an empty
	// rule file should be a true no-op and must not consume/rebuild the body.
	rules := g.ruleCache.GetRule("post.rule", cfg.RuleDir)
	if len(rules) == 0 {
		return false
	}

	// 限制读取大小（防止超大 body 消耗内存）
	maxSize := int64(10 * 1024 * 1024) // 10MB
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	r.Body.Close()
	if err != nil || len(bodyBytes) == 0 {
		return false
	}

	// 恢复 body 供后续 handler 使用（用 bytes.NewReader 避免额外的 string 拷贝）
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// waf_enabled 缓存一次（对应 Lua 的 local waf_enabled = is_waf_enabled() == "on"）
	wafEnabled := cfg.WAFEnable == "on"

	// 1. form-urlencoded: 解析 key/value 逐一匹配
	//    对应 Lua: should_parse_post_args = is_form_urlencoded
	if isFormURLEncoded {
		formValues, parseErr := url.ParseQuery(string(bodyBytes))
		if parseErr == nil && len(formValues) > 0 {
			for key, vals := range formValues {
				// 检查参数名（key）
				if key != "" {
					if matched := matchRules(key, rules, true); matched != nil {
						g.logger.Record("POST", reqURICached(r), "key:"+key, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
						if wafEnabled {
							g.wafOutput(w, cfg)
						}
						return true
					}
					// 解码后匹配
					if hasEncodeMarkers(key) {
						if decoded, changed := fullDecode(key); changed {
							if matched := matchRules(decoded, rules, true); matched != nil {
								g.logger.Record("POST", reqURICached(r), "key:"+key, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
								if wafEnabled {
									g.wafOutput(w, cfg)
								}
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
					g.logger.Record("POST", reqURICached(r), val, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					if wafEnabled {
						g.wafOutput(w, cfg)
					}
					return true
				}
				// 解码后匹配
				if hasEncodeMarkers(val) {
					if decoded, changed := fullDecode(val); changed {
						if matched := matchRules(decoded, rules, true); matched != nil {
							g.logger.Record("POST", reqURICached(r), val, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
							if wafEnabled {
								g.wafOutput(w, cfg)
							}
							return true
						}
					}
				}
			}
			// form-urlencoded 已经通过 key/value 完整检测，跳过 raw body 二次扫描
			// 对应 Lua: if is_form_urlencoded and POST_ARGS_ERR ~= "truncated" then return false end
			return false
		}
		// ParseQuery 失败或空结果 → 回退到 raw body 扫描
	}

	// 2. raw body 扫描（JSON, XML, plain-text, 或 form 解析失败时回退）
	// matchRulesBytes 内置关键词预过滤：
	// 加载阶段已从每条正则规则中自动提取字面量关键词，
	// 绝大多数正常 POST body 不会命中任何关键词，直接跳过全部正则。
	if matched := matchRulesBytes(bodyBytes, rules, true); matched != nil {
		logBody := bodyBytes
		if len(logBody) > 1024 {
			logBody = logBody[:1024]
		}
		logData := string(logBody)
		if len(bodyBytes) > 1024 {
			logData += "..."
		}
		g.logger.Record("POST", reqURICached(r), logData, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		if wafEnabled {
			g.wafOutput(w, cfg)
		}
		return true
	}

	// 尝试解码后匹配（对应 Lua 的 full_decode 后匹配）
	bodyStr := string(bodyBytes)
	if hasEncodeMarkers(bodyStr) {
		if decoded, changed := fullDecode(bodyStr); changed {
			if matched := matchRules(decoded, rules, true); matched != nil {
				logData := decoded
				if len(logData) > 1024 {
					logData = logData[:1024] + "..."
				}
				g.logger.Record("POST", reqURICached(r), logData, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				if wafEnabled {
					g.wafOutput(w, cfg)
				}
				return true
			}
		}
	}

	return false
}
