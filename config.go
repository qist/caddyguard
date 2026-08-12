package caddyguard

// Config 全局安全配置结构体
// 对应 config.lua，通过 config.json 热加载
type Config struct {
	WAFEnable         string `json:"waf_enable"`          // "on" / "off"
	TrustProxyHeaders string `json:"trust_proxy_headers"` // "on" / "off"
	LogDir            string `json:"log_dir"`
	RuleDir           string `json:"rule_dir"`

	WhiteURLCheck   string `json:"white_url_check"`
	WhiteIPCheck    string `json:"white_ip_check"`
	WhiteUACheck    string `json:"white_ua_check"`
	BlackIPCheck    string `json:"black_ip_check"`
	URLCheck        string `json:"url_check"`
	URLArgsCheck    string `json:"url_args_check"`
	UserAgentCheck  string `json:"user_agent_check"`
	CookieCheck     string `json:"cookie_check"`
	CCCheck         string `json:"cc_check"`
	CCRate          string `json:"cc_rate"`          // "60/60"
	CCBlockTTL      int    `json:"cc_block_ttl"`     // 600
	PostCheck       string `json:"post_check"`
	RefererCheck    string `json:"referer_check"`
	FileUploadCheck string `json:"file_upload_check"`

	WAFOutput      string `json:"waf_output"`        // "html" / "redirect"
	WAFRedirectURL string `json:"waf_redirect_url"`
}

// DefaultConfig 返回默认配置（对应 config.lua 的默认值）
// 当 config.json 不存在或某字段缺失时，使用这些默认值
func DefaultConfig() Config {
	return Config{
		WAFEnable:         "on",
		TrustProxyHeaders: "on",
		LogDir:            "/var/log/caddy",
		RuleDir:           "/etc/caddyguard/rule-config",
		WhiteURLCheck:     "on",
		WhiteIPCheck:      "on",
		WhiteUACheck:      "on",
		BlackIPCheck:      "on",
		URLCheck:          "on",
		URLArgsCheck:      "on",
		UserAgentCheck:    "on",
		CookieCheck:       "on",
		CCCheck:           "on",
		CCRate:            "60/60",
		CCBlockTTL:        600,
		PostCheck:         "on",
		RefererCheck:      "off",
		FileUploadCheck:   "on",
		WAFOutput:         "html",
		WAFRedirectURL:    "https://www.waf.com",
	}
}
