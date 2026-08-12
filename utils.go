package caddyguard

import (
	"net"
	"net/http"
	"strings"
)

// getDomain 从请求中提取域名（去掉端口，转小写）
func getDomain(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return "default"
	}
	// 去掉端口
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return strings.ToLower(host)
}

// resolveRuleDir 解析规则目录路径
// 绝对路径原样返回，相对路径拼接 ruleDir
func resolveRuleDir(dir, baseRuleDir string) string {
	if dir == "" {
		return baseRuleDir
	}
	if strings.HasPrefix(dir, "/") {
		return dir // 绝对路径
	}
	return baseRuleDir + "/" + dir // 相对路径
}

// getClientIP 获取客户端真实 IP（对应 Lua get_client_ip）
func (g *Guard) getClientIP(r *http.Request, cfg Config) string {
	if cfg.TrustProxyHeaders != "off" {
		// 1. CF-Connecting-IP
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
		// 2. X-Real-IP
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
		// 3. X-Forwarded-For (取第一个)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	// 4. RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "" {
		return host
	}
	return "unknown"
}
