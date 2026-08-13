package caddyguard

import (
	"net/http"
)

// runChecks 执行检测链
// 优化：按检测成本从低到高排序，昂贵的 body 读取检测放最后
// 1. WAF off? → 在 ServeHTTP 中已检查
// 2. 白名单 IP → 放行（仅 map/regex 匹配，无 IO）
// 3. 白名单 URL → 放行（仅 regex 匹配）
// 4. 动态黑名单（CC 自动拉黑，仅 map 查找）
// 5. 静态黑名单 IP（仅 regex 匹配）
// 6. CC 攻击检测（map 查找 + 计数）
// 7. User-Agent 检测（header 读取 + regex）
// 8. URL 路径检测（regex）
// 9. URL 参数检测（regex，需 parse query）
// 10. Cookie 检测（header 读取 + regex）
// 11. Referer 检测（header 读取 + regex）
// 12. POST 检测（body 读取 + regex，最昂贵）
// 13. 文件上传检测（multipart 解析 + regex，最昂贵）
func (g *Guard) runChecks(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	// 1. 白名单 IP → 放行
	if g.whiteIPCheck(r, cfg) {
		return false
	}
	// 2. 白名单 URL → 放行
	if g.whiteURLCheck(r, cfg) {
		return false
	}
	// 3. 动态黑名单（CC 自动拉黑）
	if g.dynamicBlackIPCheck(w, r, cfg) {
		return true
	}
	// 4. 静态黑名单 IP
	if g.blackIPCheck(w, r, cfg) {
		return true
	}
	// 5. CC 攻击检测
	if g.ccAttackCheck(w, r, cfg) {
		return true
	}
	// 6. User-Agent 检测（白名单 UA 仅跳过此项）
	if g.userAgentAttackCheck(w, r, cfg) {
		return true
	}
	// 7. URL 路径检测
	if g.urlAttackCheck(w, r, cfg) {
		return true
	}
	// 8. URL 参数检测
	if g.urlArgsAttackCheck(w, r, cfg) {
		return true
	}
	// 9. Cookie 检测
	if g.cookieAttackCheck(w, r, cfg) {
		return true
	}
	// 10. Referer 检测
	if g.refererCheck(w, r, cfg) {
		return true
	}
	// 11. POST 检测（需读取 body，最昂贵）
	if g.postAttackCheck(w, r, cfg) {
		return true
	}
	// 12. 文件上传检测（需解析 multipart，最昂贵）
	if g.fileUploadCheck(w, r, cfg) {
		return true
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
