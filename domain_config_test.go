package caddyguard

import "testing"

// 站点级配置（domain.json）需与 NginxGuard 完全一致：键名相同、取值口径相同。
// NginxGuard 侧用 tonumber() 解析数值，因此 JSON 数字和数字字符串都要生效。

func TestMergeDomainConfigNumericStrings(t *testing.T) {
	base := DefaultConfig()
	base.CCBlockTTL = 600
	base.PostBodyScanLimit = 2097152
	base.UploadFilenameScanLimit = 0
	base.ScoreBlockThreshold = 0

	got := mergeDomainConfig(base, map[string]interface{}{
		"cc_block_ttl":               "120",
		"post_body_scan_limit":       "1048576",
		"upload_filename_scan_limit": "1024",
		"score_block_threshold":      "20",
	})

	if got.CCBlockTTL != 120 {
		t.Fatalf("cc_block_ttl string: got %d, want 120", got.CCBlockTTL)
	}
	if got.PostBodyScanLimit != 1048576 {
		t.Fatalf("post_body_scan_limit string: got %d, want 1048576", got.PostBodyScanLimit)
	}
	if got.UploadFilenameScanLimit != 1024 {
		t.Fatalf("upload_filename_scan_limit string: got %d, want 1024", got.UploadFilenameScanLimit)
	}
	if got.ScoreBlockThreshold != 20 {
		t.Fatalf("score_block_threshold string: got %d, want 20", got.ScoreBlockThreshold)
	}
}

func TestMergeDomainConfigNumericFloats(t *testing.T) {
	base := DefaultConfig()
	got := mergeDomainConfig(base, map[string]interface{}{
		"cc_block_ttl":               float64(300),
		"post_body_scan_limit":       float64(5242880),
		"upload_filename_scan_limit": float64(2048),
		"score_block_threshold":      float64(10),
	})

	if got.CCBlockTTL != 300 || got.PostBodyScanLimit != 5242880 ||
		got.UploadFilenameScanLimit != 2048 || got.ScoreBlockThreshold != 10 {
		t.Fatalf("numeric values not applied: %+v", got)
	}
}

func TestMergeDomainConfigZeroBlockTTL(t *testing.T) {
	base := DefaultConfig()
	base.CCBlockTTL = 600

	// 0 = 该站点只限速、不自动拉黑，NginxGuard 语义
	if got := mergeDomainConfig(base, map[string]interface{}{"cc_block_ttl": float64(0)}); got.CCBlockTTL != 0 {
		t.Fatalf("cc_block_ttl=0 number: got %d, want 0", got.CCBlockTTL)
	}
	if got := mergeDomainConfig(base, map[string]interface{}{"cc_block_ttl": "0"}); got.CCBlockTTL != 0 {
		t.Fatalf("cc_block_ttl=\"0\" string: got %d, want 0", got.CCBlockTTL)
	}
	// 负数非法，保留全局
	if got := mergeDomainConfig(base, map[string]interface{}{"cc_block_ttl": float64(-1)}); got.CCBlockTTL != 600 {
		t.Fatalf("cc_block_ttl=-1 should keep global 600, got %d", got.CCBlockTTL)
	}
}

// TestMergeDomainConfigCorefusionSiteKeys 覆盖 corefusion 实际下发的站点级键，
// 保证同一份 domain.json 在 NginxGuard / CaddyGuard 上语义一致。
func TestMergeDomainConfigCorefusionSiteKeys(t *testing.T) {
	base := DefaultConfig()
	base.WAFEnable = "on"
	base.URLCheck = "on"
	base.CCRate = "150/60"
	base.CCMode = "ip"
	base.Bodyless = "on"
	base.MultipartStreamingCheck = "off"
	base.PostBodyScanLimit = 2097152
	base.UploadFilenameScanLimit = 0
	base.ScoreBlockThreshold = 0
	base.WAFOutput = "html"
	base.WAFRedirectURL = "https://www.caddyguard.com"

	got := mergeDomainConfig(base, map[string]interface{}{
		"waf_enable":                 "off",
		"trust_proxy_headers":        "off",
		"rule_dir":                   "domains/example.com",
		"white_url_check":            "off",
		"white_ip_check":             "off",
		"white_ua_check":             "off",
		"black_ip_check":             "off",
		"url_check":                  "off",
		"url_args_check":             "off",
		"user_agent_check":           "off",
		"header_check":               "off",
		"cookie_check":               "off",
		"cc_check":                   "off",
		"cc_rate":                    "100/60",
		"cc_mode":                    "ip_host",
		"cc_block_ttl":               "0",
		"post_check":                 "off",
		"referer_check":              "on",
		"file_upload_check":          "off",
		"bodyless":                   "off",
		"waf_output":                 "redirect",
		"waf_redirect_url":           "https://example.com/blocked",
		"multipart_streaming_check":  "on",
		"upload_filename_scan_limit": "1024",
		"post_body_scan_limit":       "1048576",
		"score_block_threshold":      1,
	})

	checks := map[string]bool{
		"waf_enable":                 got.WAFEnable == "off",
		"trust_proxy_headers":        got.TrustProxyHeaders == "off",
		"rule_dir":                   got.RuleDir == "domains/example.com",
		"white_url_check":            got.WhiteURLCheck == "off",
		"white_ip_check":             got.WhiteIPCheck == "off",
		"white_ua_check":             got.WhiteUACheck == "off",
		"black_ip_check":             got.BlackIPCheck == "off",
		"url_check":                  got.URLCheck == "off",
		"url_args_check":             got.URLArgsCheck == "off",
		"user_agent_check":           got.UserAgentCheck == "off",
		"header_check":               got.HeaderCheck == "off",
		"cookie_check":               got.CookieCheck == "off",
		"cc_check":                   got.CCCheck == "off",
		"cc_rate":                    got.CCRate == "100/60",
		"cc_mode":                    got.CCMode == "ip_host",
		"cc_block_ttl":               got.CCBlockTTL == 0,
		"post_check":                 got.PostCheck == "off",
		"referer_check":              got.RefererCheck == "on",
		"file_upload_check":          got.FileUploadCheck == "off",
		"bodyless":                   got.Bodyless == "off",
		"waf_output":                 got.WAFOutput == "redirect",
		"waf_redirect_url":           got.WAFRedirectURL == "https://example.com/blocked",
		"multipart_streaming_check":  got.MultipartStreamingCheck == "on",
		"upload_filename_scan_limit": got.UploadFilenameScanLimit == 1024,
		"post_body_scan_limit":       got.PostBodyScanLimit == 1048576,
		"score_block_threshold":      got.ScoreBlockThreshold == 1,
	}
	for key, ok := range checks {
		if !ok {
			t.Errorf("site-level key %q not applied", key)
		}
	}
}

// TestMergeDomainConfigGlobalOnlyKeys 验证进程级配置不会被站点级覆盖，
// 与 NginxGuard 行为一致（log_dir / match_cache 只读全局）。
func TestMergeDomainConfigGlobalOnlyKeys(t *testing.T) {
	base := DefaultConfig()
	base.LogDir = "/var/log/caddyguard"
	base.MatchCache = "on"

	got := mergeDomainConfig(base, map[string]interface{}{
		"log_dir":     "/tmp/other",
		"match_cache": "off",
	})

	if got.LogDir != base.LogDir {
		t.Fatalf("log_dir must stay global: got %q", got.LogDir)
	}
	if got.MatchCache != base.MatchCache {
		t.Fatalf("match_cache must stay global: got %q", got.MatchCache)
	}
}
