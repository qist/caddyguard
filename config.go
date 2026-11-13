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
	HeaderCheck     string `json:"header_check"`      // 请求头检测开关（header.rule）
	CookieCheck     string `json:"cookie_check"`      // Cookie 检测开关
	CCCheck         string `json:"cc_check"`          // CC 攻击检测开关
	CCRate          string `json:"cc_rate"`           // CC 速率 "60/60"（次数/秒数）
	CCMode          string `json:"cc_mode"`           // CC 计数粒度 "ip"（默认）/ "ip_uri" / "ip_host"
	CCBlockTTL      int    `json:"cc_block_ttl"`      // CC 触发后封禁时长（秒）
	PostCheck       string `json:"post_check"`        // POST 检测开关
	RefererCheck    string `json:"referer_check"`     // Referer 检测开关
	FileUploadCheck string `json:"file_upload_check"` // 文件上传检测开关

	// Bodyless 方法跳过开关（对应 Lua config_bodyless）
	// "on" (默认) = GET/HEAD/OPTIONS 跳过 body/post/file_upload 检测
	// "off"         = 所有方法都扫描 body（更严格，延迟更高）
	Bodyless string `json:"bodyless"` // bodyless 方法跳过开关

	WAFOutput      string `json:"waf_output"`       // 拦截输出 "html" / "redirect"
	WAFRedirectURL string `json:"waf_redirect_url"` // 重定向 URL

	// Body 扫描控制（对应 Lua config_upload_filename_scan_limit / config_post_body_scan_limit）
	MultipartStreamingCheck string `json:"multipart_streaming_check"`  // multipart body 流式扫描开关 "on"/"off"
	UploadFilenameScanLimit int64  `json:"upload_filename_scan_limit"` // multipart 文件名扫描上限（字节），0=全扫
	PostBodyScanLimit       int64  `json:"post_body_scan_limit"`       // 非 multipart body 扫描上限（字节），超过直接拦截

	// 匹配缓存开关（对应 Lua config_match_cache）
	// "on" (默认) = 缓存小输入(≤512B)匹配结果加速重复检测，绝不改变检测结果
	// "off"       = 每次完整检测（A/B 一致性测试用）
	// 注意：缓存为进程级共享（key 不含域名），此开关仅由 config.json 全局配置生效，
	//       不支持 domain.json 域名级覆盖
	MatchCache string `json:"match_cache"`
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
		HeaderCheck:       "on",
		CookieCheck:       "on",
		CCCheck:           "on",
		CCRate:            "60/60",
		CCMode:            "ip", // 默认按整 IP 计数，跨 URI/域名共享额度
		CCBlockTTL:        600,
		PostCheck:         "on",
		RefererCheck:      "off",
		FileUploadCheck:   "on",
		Bodyless:          "on", // 默认开启：GET/HEAD/OPTIONS 跳过 body 检测
		WAFOutput:         "html",
		WAFRedirectURL:    "https://www.waf.com",

		// Body 扫描控制默认值（对应 Lua config.lua 默认值）
		MultipartStreamingCheck: "off",   // 默认关闭：multipart 只做 filename 检查，跳过 raw body 流式扫描
		UploadFilenameScanLimit: 0,       // 0 = 扫描整个上传临时文件
		PostBodyScanLimit:       2097152, // 2MB：超过此值直接拦截

		MatchCache: "on", // 分段匹配缓存默认开启（config_match_cache）
	}
}
