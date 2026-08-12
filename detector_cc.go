package caddyguard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ccAttackCheck CC 攻击检测
// 基于滑动窗口的速率限制，超阈值自动拉黑
func (g *Guard) ccAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.CCCheck != "on" {
		return false
	}

	// 解析 cc_rate: "60/60" → count=60, seconds=60
	ccCount, ccSeconds := parseCCRate(cfg.CCRate)
	if ccCount == 0 || ccSeconds == 0 {
		return false
	}

	clientIP := g.getClientIPCached(r, cfg)
	uri := r.URL.Path
	ccKey := clientIP + uri

	// 通过存储接口计数（内存或 Redis）
	count := g.ccStore.Incr(ccKey, time.Duration(ccSeconds)*time.Second)

	if count > ccCount {
		logData := fmt.Sprintf("count=%d threshold=%d window=%ds", count, ccCount, ccSeconds)
		g.logger.Record("CCAttack", reqURICached(r), logData, "CC Rate Limit", clientIP, r, cfg)

		// 自动拉黑
		if cfg.CCBlockTTL > 0 {
			if !g.ccStore.IsBanned(clientIP) {
				g.ccStore.Ban(clientIP, time.Duration(cfg.CCBlockTTL)*time.Second)
			}
		}

		g.wafOutput(w, cfg)
		return true
	}

	return false
}

// parseCCRate 解析 "60/60" → (60, 60)
// 返回 (0, 0) 表示格式错误
func parseCCRate(rate string) (count, seconds int) {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	c, _ := strconv.Atoi(parts[0])
	s, _ := strconv.Atoi(parts[1])
	return c, s
}
