package caddyguard

import (
	"net/http"
	"strings"
)

// GetEffectiveConfig 合并全局配置和域名级配置
// 全局基线从 config.json 热加载，域名级配置从 domain.json 热加载
// 域名级配置优先，未设置的项回退到全局
func (g *Guard) GetEffectiveConfig(r *http.Request) Config {
	// 全局基线：从 config.json 热加载
	cfg := g.ruleCache.GetGlobalConfig()

	domain := getDomain(r)
	domainCfg := g.ruleCache.GetDomainConfig(domain)
	if domainCfg == nil {
		return cfg
	}

	// 逐项覆盖
	if v, ok := domainCfg["waf_enable"]; ok {
		cfg.WAFEnable = v.(string)
	}
	if v, ok := domainCfg["trust_proxy_headers"]; ok {
		cfg.TrustProxyHeaders = v.(string)
	}
	if v, ok := domainCfg["log_dir"]; ok {
		cfg.LogDir = v.(string)
	}
	if v, ok := domainCfg["white_url_check"]; ok {
		cfg.WhiteURLCheck = v.(string)
	}
	if v, ok := domainCfg["white_ip_check"]; ok {
		cfg.WhiteIPCheck = v.(string)
	}
	if v, ok := domainCfg["white_ua_check"]; ok {
		cfg.WhiteUACheck = v.(string)
	}
	if v, ok := domainCfg["black_ip_check"]; ok {
		cfg.BlackIPCheck = v.(string)
	}
	if v, ok := domainCfg["url_check"]; ok {
		cfg.URLCheck = v.(string)
	}
	if v, ok := domainCfg["url_args_check"]; ok {
		cfg.URLArgsCheck = v.(string)
	}
	if v, ok := domainCfg["user_agent_check"]; ok {
		cfg.UserAgentCheck = v.(string)
	}
	if v, ok := domainCfg["cookie_check"]; ok {
		cfg.CookieCheck = v.(string)
	}
	if v, ok := domainCfg["cc_check"]; ok {
		cfg.CCCheck = v.(string)
	}
	if v, ok := domainCfg["cc_rate"]; ok {
		cfg.CCRate = v.(string)
	}
	if v, ok := domainCfg["cc_block_ttl"]; ok {
		cfg.CCBlockTTL = int(v.(float64))
	}
	if v, ok := domainCfg["post_check"]; ok {
		cfg.PostCheck = v.(string)
	}
	if v, ok := domainCfg["referer_check"]; ok {
		cfg.RefererCheck = v.(string)
	}
	if v, ok := domainCfg["file_upload_check"]; ok {
		cfg.FileUploadCheck = v.(string)
	}
	if v, ok := domainCfg["waf_output"]; ok {
		cfg.WAFOutput = v.(string)
	}
	if v, ok := domainCfg["waf_redirect_url"]; ok {
		cfg.WAFRedirectURL = v.(string)
	}
	if v, ok := domainCfg["rule_dir"]; ok {
		cfg.RuleDir = v.(string)
	}

	return cfg
}

// matchDomain 先精确匹配，再通配符匹配
// *.example.com → 匹配 a.example.com, b.example.com
func matchDomain(domainConfigs map[string]map[string]interface{}, domain string) map[string]interface{} {
	// 1. 精确匹配
	if cfg, ok := domainConfigs[domain]; ok {
		return cfg
	}
	// 2. 通配符匹配
	for pattern, cfg := range domainConfigs {
		if pattern == "_comment" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) {
				return cfg
			}
		}
	}
	return nil
}
