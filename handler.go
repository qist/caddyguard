package caddyguard

import (
	"net/http"
)

// runChecks 执行检测链
// 对应 Lua access.lua 的 waf_main 函数
//
// 检测顺序（与 nginxguard 完全一致）：
//  1. 白名单 IP → 放行
//  2. 动态黑名单（CC 自动拉黑期内）
//  3. 静态黑名单 IP
//  4. 白名单 URL → 返回跳过的检测项集合（不再全局放行）
//  5. User-Agent 检测（白名单 UA 仅跳过此项；白名单 URL 可指定跳过）
//  6. Referer 检测（白名单 URL 可指定跳过）
//  7. CC 攻击检测（白名单 URL 可指定跳过）
//  8. [非 bodyless] 文件上传检测（白名单 URL 可指定跳过）
//  9. URL 路径检测（纯路径白名单默认跳过此项；可指定跳过）
// 10. URL 参数检测（白名单 URL 可指定跳过）
// 11. Cookie 检测（白名单 URL 可指定跳过）
// 12. [非 bodyless] POST 检测（白名单 URL 可指定跳过）
//
// 请求类型分叉（对应 Lua 的 is_bodyless_method 优化）：
//   - bodyless="on" (默认): GET/HEAD/OPTIONS 跳过文件上传和 POST 检测
//   - bodyless="off":        所有方法都执行全部检测
//   - POST/PUT/PATCH/DELETE: 始终执行 body 检测（不受 bodyless 开关影响）
func (g *Guard) runChecks(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	// 1. 白名单 IP → 放行
	if g.whiteIPCheck(r, cfg) {
		return false
	}

	// 2. 动态黑名单（CC 自动拉黑期内）
	if g.dynamicBlackIPCheck(w, r, cfg) {
		return true
	}

	// 3. 静态黑名单 IP
	if g.blackIPCheck(w, r, cfg) {
		return true
	}

	// 4. 白名单 URL → 返回跳过的检测项集合（不再全局放行）
	// 对应 Lua: local url_skips = white_url_check()
	// 纯路径格式默认只跳过 url_attack；扩展格式可指定跳过哪些检测项
	urlSkips := g.whiteURLCheck(r, cfg)

	// 请求类型分叉：GET/HEAD/OPTIONS 跳过 body 相关检测
	method := r.Method
	isBodyless := cfg.Bodyless != "off" && (method == "GET" || method == "HEAD" || method == "OPTIONS")

	// 5. User-Agent 检测（白名单 UA 仅跳过此项；白名单 URL 可指定跳过）
	if !(urlSkips != nil && urlSkips.UserAgent) {
		if g.userAgentAttackCheck(w, r, cfg) {
			return true
		}
	}

	// 6. Referer 检测
	if !(urlSkips != nil && urlSkips.Referer) {
		if g.refererCheck(w, r, cfg) {
			return true
		}
	}

	// 7. CC 攻击检测
	if !(urlSkips != nil && urlSkips.CC) {
		if g.ccAttackCheck(w, r, cfg) {
			return true
		}
	}

	// 8. [非 bodyless] 文件上传检测（需解析 multipart，最昂贵）
	if !isBodyless {
		if !(urlSkips != nil && urlSkips.FileUpload) {
			if g.fileUploadCheck(w, r, cfg) {
				return true
			}
		}
	}

	// 9. URL 路径检测（纯路径白名单默认跳过此项）
	if !(urlSkips != nil && urlSkips.URLAttack) {
		if g.urlAttackCheck(w, r, cfg) {
			return true
		}
	}

	// 10. URL 参数检测
	if !(urlSkips != nil && urlSkips.URLArgs) {
		if g.urlArgsAttackCheck(w, r, cfg) {
			return true
		}
	}

	// 11. Cookie 检测
	if !(urlSkips != nil && urlSkips.Cookie) {
		if g.cookieAttackCheck(w, r, cfg) {
			return true
		}
	}

	// 12. [非 bodyless] POST 检测（需读取 body，最昂贵）
	if !isBodyless {
		if !(urlSkips != nil && urlSkips.Post) {
			if g.postAttackCheck(w, r, cfg) {
				return true
			}
		}
	}

	return false
}

// defaultHTMLBytes 预计算 []byte，避免每次 wafOutput 时重新分配
var defaultHTMLBytes = []byte(defaultHTML)

// wafOutput 输出拦截响应
// waf_output: "html" → 返回拦截页面，"redirect" → 302 跳转
func (g *Guard) wafOutput(w http.ResponseWriter, cfg Config) {
	if cfg.WAFOutput == "redirect" {
		http.Redirect(w, nil, cfg.WAFRedirectURL, http.StatusMovedPermanently)
		return
	}
	// 默认 html
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write(defaultHTMLBytes)
}

const defaultHTML = `<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>WAF防火墙</title></head>
<body style="font:14px/1.5 Microsoft Yahei,sans-serif;color:#555;">
<div style="margin:0 auto;width:600px;padding-top:70px;">
<div style="height:40px;line-height:40px;color:#fff;font-size:16px;background:#6bb3f6;padding-left:20px;">安全拦截</div>
<div style="border:1px dashed #cdcece;border-top:none;background:#f3f7f9;padding:20px;height:220px;">
<p><span style="font-weight:600;color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span></p>
<p>可能原因：您提交的内容包含危险的攻击请求</p>
</div>
</div>
</body>
</html>`
