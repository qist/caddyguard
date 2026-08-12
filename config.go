package caddyguard

// Config 全局配置结构体
// 对应 Lua 版 config.lua，所有字段均可通过 config.json 热加载
type Config struct {
	WAFEnable         string `json:"waf_enable"`          // 安全总开关 "on" / "off"
	WAFMode           string `json:"waf_mode"`            // 运行模式 "block" / "log"
	WAFOutput         string `json:"waf_output"`          // 拦截输出 "block" / "redirect"
	WAFRedirectURL    string `json:"waf_redirect_url"`    // 重定向 URL
	CCEnable          string `json:"cc_enable"`           // CC 攻击检测开关
	CCRate            int    `json:"cc_rate"`             // CC 速率：每 RateWindow 秒内最多多少次
	CCWindow          int    `json:"cc_window"`           // CC 时间窗口（秒）
	CCBanTime         int    `json:"cc_ban_time"`         // CC 触发后封禁时长（秒）
	IPBlackEnable     string `json:"ip_black_enable"`     // IP 黑名单开关
	IPWhiteEnable     string `json:"ip_white_enable"`     // IP 白名单开关
	URLBlackEnable    string `json:"url_black_enable"`    // URL 黑名单开关
	URLWhiteEnable    string `json:"url_white_enable"`    // URL 白名单开关
	UABlackEnable     string `json:"ua_black_enable"`     // User-Agent 黑名单开关
	UAWhiteEnable     string `json:"ua_white_enable"`     // User-Agent 白名单开关
	CookieEnable      string `json:"cookie_enable"`       // Cookie 检测开关
	PostEnable        string `json:"post_enable"`         // POST 检测开关
	RefererEnable     string `json:"referer_enable"`      // Referer 检测开关
	FileUploadEnable  string `json:"file_upload_enable"`  // 文件上传检测开关
	MinPHPID          int    `json:"min_php_id"`          // PHP 反序列化检测：最小 ID
	MinSessID         int    `json:"min_sess_id"`         // Session ID 最小值
	MaxSessID         int    `json:"max_sess_id"`         // Session ID 最大值
	ArgsEnable        string `json:"args_enable"`         // URL 参数检测开关
	Exts              string `json:"exts"`                // 需检测的扩展名（逗号分隔）
	ExtsCheck         string `json:"exts_check"`          // 扩展名检测模式 "black" / "white"
	RegexEnable       string `json:"regex_enable"`        // 正则规则开关
	TrustProxyHeaders string `json:"trust_proxy_headers"` // 信任代理头 "on" / "off"
	LogDir            string `json:"log_dir"`             // 日志目录
	RuleDir           string `json:"rule_dir"`            // 规则目录（域名级覆盖）
}

// DefaultConfig 返回默认配置
// 对应 Lua 版 config.lua 中的默认值
func DefaultConfig() Config {
	return Config{
		WAFEnable:         "on",
		WAFMode:           "block",
		WAFOutput:         "block",
		WAFRedirectURL:    "https://github.com/qist/caddyguard",
		CCEnable:          "on",
		CCRate:            120,
		CCWindow:          60,
		CCBanTime:         1800,
		IPBlackEnable:     "on",
		IPWhiteEnable:     "on",
		URLBlackEnable:    "on",
		URLWhiteEnable:    "on",
		UABlackEnable:     "on",
		UAWhiteEnable:     "on",
		CookieEnable:      "on",
		PostEnable:        "on",
		RefererEnable:     "on",
		FileUploadEnable:  "on",
		MinPHPID:          2000,
		MinSessID:         10000000,
		MaxSessID:         99999999,
		ArgsEnable:        "on",
		Exts:              ".php,.jsp,.asp,.aspx,.do,.cgi,.pl,.py,.sh,.sql",
		ExtsCheck:         "black",
		RegexEnable:       "on",
		TrustProxyHeaders: "on",
		LogDir:            "/var/log/caddyguard",
		RuleDir:           "",
	}
}
