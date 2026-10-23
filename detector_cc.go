package caddyguard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// ccAttackCheck CC 攻击检测
// 基于滑动窗口的速率限制，超阈值自动拉黑
// 计数粒度由 cc_mode 决定（对应 nginxguard 的 config_cc_mode）：
//   - "ip"（默认）：按整 IP 计数，跨 URI/域名共享额度
//   - "ip_uri"：按 IP+URI 计数，仅防单路径刷
//   - "ip_host"：按域名+IP 计数，各域名独立额度，自动拉黑也只作用于该域名
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
	ccMode := cfg.CCMode

	// 通过存储接口计数（内存或 Redis）
	// ip_uri 模式取纯路径（对应 Lua var.uri，不含 query）
	count := g.ccStore.Incr(ccCountKey(ccMode, getDomain(r), clientIP, r.URL.Path), time.Duration(ccSeconds)*time.Second)

	if count > ccCount {
		logData := fmt.Sprintf("count=%d threshold=%d window=%ds mode=%s", count, ccCount, ccSeconds, ccModeString(ccMode))
		g.logger.Record("CCAttack", reqURICached(r), logData, "CC Rate Limit", clientIP, r, cfg)

		// 自动拉黑：封禁粒度跟随 cc_mode
		// "ip"/"ip_uri" 封禁整个 IP（全局，所有域名）；"ip_host" 仅封禁 域名+IP，
		// 一个域名触发 CC 不会影响该 IP 访问其他域名
		if cfg.CCBlockTTL > 0 {
			banKey := ccBanKey(ccMode, getDomain(r), clientIP)
			if !g.ccStore.IsBanned(banKey) {
				g.ccStore.Ban(banKey, time.Duration(cfg.CCBlockTTL)*time.Second)
				g.logger.Record("CCAutoBan", reqURICached(r), "_",
					fmt.Sprintf("ban_%ds", cfg.CCBlockTTL), clientIP, r, cfg)
			}
		}

		g.wafOutput(w, cfg)
		return true
	}

	return false
}

// ccModeString 归一化 cc_mode，未知/空值按默认 "ip" 处理（与 Lua 默认分支一致）
func ccModeString(ccMode string) string {
	switch ccMode {
	case "ip_uri", "ip_host":
		return ccMode
	default:
		return "ip"
	}
}

// ccCountKey 构造 CC 计数 key（对应 Lua 的 CC_TOKEN）
func ccCountKey(ccMode, host, clientIP, uri string) string {
	switch ccMode {
	case "ip_uri":
		// per IP+URI: 只拦截单路径刷量
		return "cc:" + clientIP + "|" + uri
	case "ip_host":
		// per 域名+IP: 各域名独立额度
		return "cc:h|" + host + "|" + clientIP
	default:
		// 默认: per IP，跨 URI/域名共享额度
		return "cc:" + clientIP
	}
}

// ccBanKey 构造 CC 自动拉黑 key（封禁粒度跟随 cc_mode）
// "ip"/"ip_uri" → 整 IP 全局封禁；"ip_host" → 仅封禁 域名+IP
func ccBanKey(ccMode, host, clientIP string) string {
	if ccMode == "ip_host" {
		return "h|" + host + "|" + clientIP
	}
	return clientIP
}

// parseCCRate 解析 "60/60" → (60, 60)
// 返回 (0, 0) 表示格式错误
// 对应 Lua: 无效 cc_rate 时记录 ngx.ERR 日志，避免 CC 静默 fail-open
func parseCCRate(rate string) (count, seconds int) {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 {
		caddy.Log().Error("[CaddyGuard] invalid cc_rate config",
			zap.String("rate", rate),
			zap.String("expected", "<count>/<seconds>"),
			zap.String("action", "CC check disabled"))
		return 0, 0
	}
	c, err1 := strconv.Atoi(parts[0])
	s, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || c <= 0 || s <= 0 {
		caddy.Log().Error("[CaddyGuard] invalid cc_rate config",
			zap.String("rate", rate),
			zap.String("expected", "<count>/<seconds>"),
			zap.String("action", "CC check disabled"))
		return 0, 0
	}
	return c, s
}
