package caddyguard

import (
	"net/http"
	"strings"
)

// GetEffectiveConfig 获取当前请求的有效配置
// 优先级：domain.json 域名级覆盖 > config.json 全局基线
func (g *Guard) GetEffectiveConfig(r *http.Request) Config {
	// 1. 从 config.json 获取全局基线配置
	cfg := g.ruleCache.GetGlobalConfig()

	// 2. 获取域名
	domain := getDomain(r)

	// 3. 从 domain.json 获取域名级配置
	domainConfigs := g.ruleCache.GetDomainConfig(domain)
	if domainConfigs == nil {
		return cfg
	}

	// 4. 通配符匹配（精确优先，后通配符）
	domainCfg := matchDomainConfig(domainConfigs, domain)
	if domainCfg == nil {
		return cfg
	}

	// 5. 用域名级配置覆盖全局配置
	if v, ok := domainCfg["waf_enable"].(string); ok && v != "" {
		cfg.WAFEnable = v
	}
	if v, ok := domainCfg["trust_proxy_headers"].(string); ok && v != "" {
		cfg.TrustProxyHeaders = v
	}
	if v, ok := domainCfg["log_dir"].(string); ok && v != "" {
		cfg.LogDir = v
	}
	if v, ok := domainCfg["rule_dir"].(string); ok && v != "" {
		cfg.RuleDir = v
	}
	if v, ok := domainCfg["white_url_check"].(string); ok && v != "" {
		cfg.WhiteURLCheck = v
	}
	if v, ok := domainCfg["white_ip_check"].(string); ok && v != "" {
		cfg.WhiteIPCheck = v
	}
	if v, ok := domainCfg["white_ua_check"].(string); ok && v != "" {
		cfg.WhiteUACheck = v
	}
	if v, ok := domainCfg["black_ip_check"].(string); ok && v != "" {
		cfg.BlackIPCheck = v
	}
	if v, ok := domainCfg["url_check"].(string); ok && v != "" {
		cfg.URLCheck = v
	}
	if v, ok := domainCfg["url_args_check"].(string); ok && v != "" {
		cfg.URLArgsCheck = v
	}
	if v, ok := domainCfg["user_agent_check"].(string); ok && v != "" {
		cfg.UserAgentCheck = v
	}
	if v, ok := domainCfg["cookie_check"].(string); ok && v != "" {
		cfg.CookieCheck = v
	}
	if v, ok := domainCfg["cc_check"].(string); ok && v != "" {
		cfg.CCCheck = v
	}
	if v, ok := domainCfg["cc_rate"].(string); ok && v != "" {
		cfg.CCRate = v
	}
	if v, ok := domainCfg["cc_block_ttl"].(float64); ok && v > 0 {
		cfg.CCBlockTTL = int(v)
	}
	if v, ok := domainCfg["post_check"].(string); ok && v != "" {
		cfg.PostCheck = v
	}
	if v, ok := domainCfg["referer_check"].(string); ok && v != "" {
		cfg.RefererCheck = v
	}
	if v, ok := domainCfg["file_upload_check"].(string); ok && v != "" {
		cfg.FileUploadCheck = v
	}
	if v, ok := domainCfg["waf_output"].(string); ok && v != "" {
		cfg.WAFOutput = v
	}
	if v, ok := domainCfg["waf_redirect_url"].(string); ok && v != "" {
		cfg.WAFRedirectURL = v
	}

	return cfg
}

// matchDomainConfig 先精确匹配，再通配符匹配
// *.example.com → 匹配 a.example.com, b.example.com
func matchDomainConfig(domainConfigs map[string]map[string]interface{}, domain string) map[string]interface{} {
	// 1. 精确匹配
	if cfg, ok := domainConfigs[domain]; ok {
		return cfg
	}
	// 2. 通配符匹配
	for pattern, cfg := range domainConfigs {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .example.com
			if strings.HasSuffix(domain, suffix) {
				return cfg
			}
		}
	}
	return nil
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
