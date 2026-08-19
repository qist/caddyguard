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

// isCDNIP 检查 remoteAddr 是否在 cdnip.rule 列表中
// 对应 Lua 的 is_cdn_ip 函数
// 返回 true = remoteAddr 在 CDN 列表中（信任 XFF）
// 返回 false = remoteAddr 不在 CDN 列表中（不信任 XFF）
// 当 cdnip.rule 不存在或为空时返回 true（向后兼容，信任所有 XFF）
func (g *Guard) isCDNIP(remoteAddr string) bool {
	if remoteAddr == "" {
		return true // 无法判断，默认信任
	}

	// 内网 IP 快速短路（对应 Lua 的内网 IP O(1) 快速判定）
	// 127.x / 10.x / 172.16-31.x / 192.168.x 是常见的内部代理/负载均衡器
	host, _, _ := net.SplitHostPort(remoteAddr)
	if host == "" {
		host = remoteAddr
	}

	// 去掉 IPv6 前缀 ::ffff:
	host = strings.TrimPrefix(host, "::ffff:")

	if host == "127.0.0.1" || host == "::1" {
		return true
	}

	// 检查是否为私有 IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() {
			return true
		}
	}

	// 加载预编译的 cdnip.rule 并检查
	compiled := g.getCompiledIPRules("cdnip.rule", "")
	if compiled == nil || !compiled.hasRules {
		return true // cdnip.rule 不存在或为空 → 信任所有 XFF（向后兼容）
	}

	return compiled.match(host)
}

// getClientIP 获取客户端真实 IP
// 当 trust_proxy_headers=on 时，优先读 header（CDN/反代场景）
//   - cdnip.rule 存在时：仅当 remote_addr 在 CDN IP 列表中才信任 XFF（安全，推荐）
//   - cdnip.rule 不存在时：信任所有 XFF（原始行为，向后兼容）
// 当 trust_proxy_headers=off 时，只用 RemoteAddr（防 IP 伪造）
// 注意：当 layer4 使用 PROXY protocol 时，r.RemoteAddr 已是真实 IP
func (g *Guard) getClientIP(r *http.Request, cfg Config) string {
	if cfg.TrustProxyHeaders != "off" {
		// 检查 remote_addr 是否来自可信 CDN/代理
		// 只有来自 CDN IP 的请求才信任 XFF，防止直连伪造
		if g.isCDNIP(r.RemoteAddr) {
			// 1. CF-Connecting-IP (Cloudflare 专用，最可靠)
			if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
				ip = strings.TrimSpace(ip)
				if isValidIP(ip) {
					return ip
				}
			}
			// 2. X-Real-IP
			if ip := r.Header.Get("X-Real-IP"); ip != "" {
				ip = strings.TrimSpace(ip)
				if isValidIP(ip) {
					return ip
				}
			}
			// 3. X-Forwarded-For (取第一个有效 IP)
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				for _, entry := range strings.Split(xff, ",") {
					candidate := strings.TrimSpace(entry)
					if candidate != "" && isValidIP(candidate) {
						return candidate
					}
				}
			}
		}
	}
	// 4. RemoteAddr (PROXY protocol 会改写此值)
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "" {
		return strings.TrimPrefix(host, "::ffff:")
	}
	return "unknown"
}

// isValidIP 检查字符串是否为有效的 IPv4 或 IPv6 地址
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}
