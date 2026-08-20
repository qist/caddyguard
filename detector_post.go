package caddyguard

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
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

	// 仅检查带 body 的方法（POST/PUT/PATCH/DELETE）
	// 对应 Lua: is_bodyless_method 排除 GET/HEAD/OPTIONS
	// bodyless="off" 时所有方法都扫描 body（handler.go 层已控制是否进入此函数，
	// 这里做二次防御确保非 bodyless 方法不被跳过）
	method := r.Method
	if cfg.Bodyless != "off" {
		// bodyless="on" (默认): GET/HEAD/OPTIONS 不走 body 检测
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			return false
		}
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
	isMultipartForm := false
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			if strings.EqualFold(mediaType, "multipart/form-data") {
				isMultipartForm = true
				// multipart_streaming_check == "off" 时跳过 raw body 扫描（默认）
				// 对应 Lua: if is_multipart_form and not is_multipart_streaming_enabled() then return false end
				if cfg.MultipartStreamingCheck != "on" {
					return false
				}
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

	// 限制读取大小（对应 Lua 的 post_body_scan_limit）
	// 超过此值的非 multipart body 直接拦截，避免只扫前半段后误放行
	postBodyScanLimit := cfg.PostBodyScanLimit
	if postBodyScanLimit <= 0 {
		postBodyScanLimit = 2097152 // 2MB 默认
	}

	// 非 multipart 的 body：如果 ContentLength 已知且超过限制，直接拦截
	// multipart body 不受此限制（由 fileUploadCheck 的 upload_filename_scan_limit 控制）
	if !isMultipartForm && r.ContentLength > postBodyScanLimit {
		g.logger.Record("POSTOversize", reqURICached(r), "size:"+strconv.FormatInt(r.ContentLength, 10), "max:"+strconv.FormatInt(postBodyScanLimit, 10), g.getClientIPCached(r, cfg), r, cfg)
		if cfg.WAFEnable == "on" {
			g.wafOutput(w, cfg)
		}
		return true
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, postBodyScanLimit+1)) // +1 to detect truncation
	r.Body.Close()
	if err != nil || len(bodyBytes) == 0 {
		return false
	}

	// 截断检测：如果读取到的字节数超过限制，说明 body 大于阈值
	// 对应 Lua: file_size > post_body_scan_limit → 拦截
	// multipart body 不受此限制（由 fileUploadCheck 处理）
	if !isMultipartForm && int64(len(bodyBytes)) > postBodyScanLimit {
		g.logger.Record("POSTOversize", reqURICached(r), "size:>"+strconv.FormatInt(postBodyScanLimit, 10), "max:"+strconv.FormatInt(postBodyScanLimit, 10), g.getClientIPCached(r, cfg), r, cfg)
		if cfg.WAFEnable == "on" {
			g.wafOutput(w, cfg)
		}
		return true
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
