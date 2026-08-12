package caddyguard

import (
	"fmt"
	"net/http"
	"time"
)

// ccAttackCheck CC 攻击检测
// 基于滑动窗口的速率限制，超阈值自动拉黑
func (g *Guard) ccAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.CCEnable != "on" {
		return false
	}

	clientIP := g.getClientIP(r, cfg)

	// 构造 CC 计数 key：IP + URI（对应 Lua 版 cc_key）
	ccKey := clientIP + r.URL.Path

	// 递增计数
	window := time.Duration(cfg.CCWindow) * time.Second
	count := g.ccStore.Incr(ccKey, window)

	// 超阈值 → 自动拉黑
	if count > cfg.CCRate {
		banTime := time.Duration(cfg.CCBanTime) * time.Second
		g.ccStore.Ban(clientIP, banTime)

		logData := fmt.Sprintf("count=%d threshold=%d window=%ds", count, cfg.CCRate, cfg.CCWindow)
		g.logger.Record("CCAttack", r.URL.String(), logData, "CC Rate Limit", clientIP, r, cfg)

		if cfg.WAFMode == "block" {
			g.wafOutput(w, cfg)
		}
		return true
	}

	return false
}
