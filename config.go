package caddyguard

// Config 全局配置结构体
// 对应 Lua 版 config.lua，所有字段均可通过 config.json 热加载
type Config struct {
	WAFEnable         string `json:"waf_enable"`          // 安全总开关 "on" / "off"
	TrustProxyHeaders string `json:"trust_proxy_headers"` // 信任代理头 "on" / "off"
	LogDir            string `json:"log_dir"`             // 日志目录
	RuleDir           string `json:"rule_dir"`            // 规则目录（域名级覆盖）

	WhiteURLCheck   string `json:"white_url_check"`   // URL 白名单开关
	WhiteIPCheck    string `json:"white_ip_check"`    // IP 白名单开关
	WhiteUACheck    string `json:"white_ua_check"`    // UA 白名单开关
	BlackIPCheck    string `json:"black_ip_check"`    // IP 黑名单开关
	URLCheck        string `json:"url_check"`         // URL 路径检测开关
	URLArgsCheck    string `json:"url_args_check"`    // URL 参数检测开关
	UserAgentCheck  string `json:"user_agent_check"`  // UA 攻击检测开关
	CookieCheck     string `json:"cookie_check"`      // Cookie 检测开关
	CCCheck         string `json:"cc_check"`          // CC 攻击检测开关
	CCRate          string `json:"cc_rate"`           // CC 速率 "60/60"（次数/秒数）
	CCBlockTTL      int    `json:"cc_block_ttl"`      // CC 触发后封禁时长（秒）
	PostCheck       string `json:"post_check"`        // POST 检测开关
	RefererCheck    string `json:"referer_check"`     // Referer 检测开关
	FileUploadCheck string `json:"file_upload_check"` // 文件上传检测开关

	WAFOutput      string `json:"waf_output"`       // 拦截输出 "html" / "redirect"
	WAFRedirectURL string `json:"waf_redirect_url"` // 重定向 URL
}

// DefaultConfig 返回默认配置
// 对应 Lua 版 config.lua 中的默认值
func DefaultConfig() Config {
	return Config{
		WAFEnable:         "on",
		TrustProxyHeaders: "on",
		LogDir:            "/var/log/caddy",
		RuleDir:           "",
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
