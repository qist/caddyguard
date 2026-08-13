package caddyguard

import (
	"net/http"
	"strings"
)

// GetEffectiveConfig 获取当前请求的有效配置
// 优化：域名配置在加载阶段已预合并为 Config 结构体
// 请求阶段只需一次 map 查找（精确域名），无需每请求做 map merge + 类型断言
func (g *Guard) GetEffectiveConfig(r *http.Request) Config {
	// 1. 从 config.json 获取全局基线配置
	cfg := g.ruleCache.GetGlobalConfig()

	// 2. 获取域名级配置（预合并后的缓存）
	domainEntry := g.ruleCache.GetDomainConfig()
	if domainEntry == nil {
		return cfg
	}

	// 3. 获取请求域名
	domain := getDomain(r)

	// 4. 精确匹配（O(1) map lookup）
	if merged, ok := domainEntry.configs[domain]; ok {
		return merged
	}

	// 5. 通配符匹配（加载时已预解析为列表，遍历很短）
	for _, wc := range domainEntry.wildcards {
		if strings.HasSuffix(domain, wc.suffix) {
			return wc.config
		}
	}

	return cfg
}

// matchDomain 检查请求域名是否匹配指定域名模式（保留用于工具函数）
func matchDomain(pattern, domain string) bool {
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix)
	}
	return false
}
