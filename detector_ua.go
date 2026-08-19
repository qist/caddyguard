package caddyguard

import (
	"net/http"
	"strings"
)

// botMarkers 常见搜索引擎蜘蛛标记
// 对应 Lua 的 BOT_MARKERS 预检：UA 不含任何标记时直接跳过白名单遍历
var botMarkers = []string{"bot", "spider", "crawl", "slurp", "archiver", "feed", "index"}

// isWhiteUA 白名单 UA 检测（仅跳过 UA 黑名单）
// 对应 Lua 的 is_white_ua()：先做 bloom-filter 预检
func (g *Guard) isWhiteUA(r *http.Request, cfg Config) bool {
	if cfg.WhiteUACheck != "on" {
		return false
	}
	ua := r.UserAgent()
	if ua == "" {
		return false
	}

	// Bloom-filter 预检：UA 不含任何 bot 标记时直接跳过
	// 99% 的正常流量不含 bot 标记，避免遍历白名单规则
	uaLower := strings.ToLower(ua)
	hasBotMarker := false
	for _, marker := range botMarkers {
		if strings.Contains(uaLower, marker) {
			hasBotMarker = true
			break
		}
	}
	if !hasBotMarker {
		return false
	}

	rules := g.ruleCache.GetRule("whiteua.rule", cfg.RuleDir)
	if matched := matchRules(ua, rules, true); matched != nil {
		return true
	}
	return false
}

// userAgentAttackCheck User-Agent 检测
// 1. 先检查白名单 UA：命中 → 仅跳过 UA 检测
// 2. 再检查黑名单 UA：命中 → 拦截
func (g *Guard) userAgentAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.UserAgentCheck != "on" {
		return false
	}

	ua := r.UserAgent()
	if ua == "" {
		return false
	}

	// 白名单 UA 检测
	if g.isWhiteUA(r, cfg) {
		return false
	}

	// 黑名单 UA 检测
	blackRules := g.ruleCache.GetRule("useragent.rule", cfg.RuleDir)
	if len(blackRules) == 0 {
		return false
	}
	if matched := matchRules(ua, blackRules, true); matched != nil {
		g.logger.Record("UserAgent", reqURICached(r), "", matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
		g.wafOutput(w, cfg)
		return true
	}
	return false
}
