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

	// 3. 从 domain.json 获取域名级覆盖
	domainConfigs := g.ruleCache.GetDomainConfig(domain)
	if domainConfigs == nil {
		return cfg
	}

	domainCfg, ok := domainConfigs[domain]
	if !ok {
		return cfg
	}

	// 4. 用域名级配置覆盖全局配置
	if v, ok := domainCfg["waf_enable"].(string); ok && v != "" {
		cfg.WAFEnable = v
	}
	if v, ok := domainCfg["waf_mode"].(string); ok && v != "" {
		cfg.WAFMode = v
	}
	if v, ok := domainCfg["waf_output"].(string); ok && v != "" {
		cfg.WAFOutput = v
	}
	if v, ok := domainCfg["waf_redirect_url"].(string); ok && v != "" {
		cfg.WAFRedirectURL = v
	}
	if v, ok := domainCfg["cc_enable"].(string); ok && v != "" {
		cfg.CCEnable = v
	}
	if v, ok := domainCfg["cc_rate"].(float64); ok && v > 0 {
		cfg.CCRate = int(v)
	}
	if v, ok := domainCfg["cc_window"].(float64); ok && v > 0 {
		cfg.CCWindow = int(v)
	}
	if v, ok := domainCfg["cc_ban_time"].(float64); ok && v > 0 {
		cfg.CCBanTime = int(v)
	}
	if v, ok := domainCfg["ip_black_enable"].(string); ok && v != "" {
		cfg.IPBlackEnable = v
	}
	if v, ok := domainCfg["ip_white_enable"].(string); ok && v != "" {
		cfg.IPWhiteEnable = v
	}
	if v, ok := domainCfg["url_black_enable"].(string); ok && v != "" {
		cfg.URLBlackEnable = v
	}
	if v, ok := domainCfg["url_white_enable"].(string); ok && v != "" {
		cfg.URLWhiteEnable = v
	}
	if v, ok := domainCfg["ua_black_enable"].(string); ok && v != "" {
		cfg.UABlackEnable = v
	}
	if v, ok := domainCfg["ua_white_enable"].(string); ok && v != "" {
		cfg.UAWhiteEnable = v
	}
	if v, ok := domainCfg["cookie_enable"].(string); ok && v != "" {
		cfg.CookieEnable = v
	}
	if v, ok := domainCfg["post_enable"].(string); ok && v != "" {
		cfg.PostEnable = v
	}
	if v, ok := domainCfg["referer_enable"].(string); ok && v != "" {
		cfg.RefererEnable = v
	}
	if v, ok := domainCfg["file_upload_enable"].(string); ok && v != "" {
		cfg.FileUploadEnable = v
	}
	if v, ok := domainCfg["args_enable"].(string); ok && v != "" {
		cfg.ArgsEnable = v
	}
	if v, ok := domainCfg["rule_dir"].(string); ok && v != "" {
		cfg.RuleDir = v
	}
	if v, ok := domainCfg["log_dir"].(string); ok && v != "" {
		cfg.LogDir = v
	}

	return cfg
}

// matchDomain 检查请求域名是否匹配指定域名模式
// 支持通配符：*.example.com 匹配 www.example.com
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
