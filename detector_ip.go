package caddyguard

import (
	"net"
	"net/http"
	"strings"
)

// ipMatch 检查 clientIP 是否匹配规则
// 支持三种格式：
//  1. CIDR 表示法（IPv4/IPv6）：192.168.1.0/24, 2001:db8::/32
//  2. glob 通配符：192.168.*.*, 2001:db8:*
//  3. 精确匹配：192.168.1.1, ::1
func ipMatch(clientIP, rule string) bool {
	if clientIP == "" || rule == "" {
		return false
	}

	// 1. CIDR 匹配（含 IPv4 和 IPv6）
	if strings.Contains(rule, "/") {
		_, ipNet, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}
		return ipNet.Contains(ip)
	}

	// 2. glob 通配符匹配
	if strings.Contains(rule, "*") {
		return matchRegex(clientIP, globToRegex(rule), false)
	}

	// 3. 精确匹配（IPv4 和 IPv6 均支持）
	return clientIP == rule
}

// whiteIPCheck 白名单 IP 检测
// 命中白名单 → 跳过所有检测
func (g *Guard) whiteIPCheck(r *http.Request, cfg Config) bool {
	if cfg.WhiteIPCheck != "on" {
		return false
	}
	clientIP := g.getClientIPCached(r, cfg)
	rules := g.ruleCache.GetRule("whiteip.rule", cfg.RuleDir)
	for _, rule := range rules {
		if ipMatch(clientIP, rule.Raw) {
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
		if ipMatch(clientIP, rule.Raw) {
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
