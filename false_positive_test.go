package caddyguard

import (
	"net/http"
	"testing"
)

// 本文件用例全部来自生产 WAF 日志（192.168.3.99）里真实发生过的"误杀/误报"事件，
// 用于锁死修复效果，避免规则调整时回退：
//
//	2026-09-17 11:53~12:08  17 次 UA 误杀：老规则里的裸 "hey" 命中 OPPO/一加系统浏览器 HeyTapBrowser
//	2026-08-27 09:03~09:12   3 次 POST 误杀：日志上报报文含 "type java.lang.String cannot be converted"
//	2026-09-01 14:22~14:28  23 次 POST 误杀：SDK 日志报文被 PHP 函数通用规则(include/define/eval 等)命中
//	2026-09-17（当天修复）  日志文本里的 alert(1) 不再当作 XSS

// TestFalsePositiveUserAgentFromProductionLog 手机浏览器正常 UA 不应被拦截
func TestFalsePositiveUserAgentFromProductionLog(t *testing.T) {
	g := newUATestGuard(t)
	cases := []struct {
		name string
		ua   string
	}{
		// 9/17 生产日志里被误杀 14 次的真实 UA（PLW110/PKR110 为 OPPO/一加机型）
		{"OPPO HeyTapBrowser",
			"Mozilla/5.0 (Linux; U; Android 16; zh-cn; PLW110 Build/AP3A.240617.008) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/115.0.5790.168 Mobile Safari/537.36 HeyTapBrowser/40.10.21.1"},
		{"OnePlus HeyTapBrowser",
			"Mozilla/5.0 (Linux; U; Android 15; zh-cn; PKR110 Build/AP3A.240617.008) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/115.0.5790.168 Mobile Safari/537.36 HeyTapBrowser/40.10.21.1"},
		// 其它常见国产手机浏览器（同类短词误杀风险）
		{"vivo VivoBrowser",
			"Mozilla/5.0 (Linux; U; Android 14; zh-CN; V2312A Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.0.0 Mobile Safari/537.36 VivoBrowser/19.6.0.0"},
		{"Xiaomi MiuiBrowser",
			"Mozilla/5.0 (Linux; U; Android 13; zh-cn; 2211133C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/105.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/17.3.6"},
		{"UC UCBrowser",
			"Mozilla/5.0 (Linux; U; Android 12; zh-CN; SM-A5160 Build/SP1A.210812.016) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 UCBrowser/15.5.8.1226 Mobile Safari/537.36"},
		{"QQ MQQBrowser",
			"Mozilla/5.0 (Linux; U; Android 12; zh-cn; M2012K11AC Build/SKQ1.211006.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/105.0.5195.79 MQQBrowser/12.5 Mobile Safari/537.36"},
		{"Quark Browser",
			"Mozilla/5.0 (Linux; U; Android 13; zh-CN; 22021211RC Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/111.0.0.0 Quark/6.5.5.230 Mobile Safari/537.36"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code := doWAFRequest(t, g, "GET", "/", "example.com",
				map[string]string{"User-Agent": tt.ua}, "")
			if code != http.StatusOK {
				t.Fatalf("正常浏览器 UA 被拦截（误杀）：%s → %d", tt.name, code)
			}
		})
	}
}

// TestFalsePositivePostFromProductionLog 业务日志上报报文里的普通文本不应被拦截
func TestFalsePositivePostFromProductionLog(t *testing.T) {
	g := newUATestGuard(t)
	cases := []struct {
		name string
		body string
	}{
		// 8/27 openapi.boshungame.com /openplatformdatareport/api/Log/report/batch
		{"java.lang.String 报错日志",
			`{"method":"log.report","data":[{"msg":"ue of type java.lang.String cannot be converted to JSONObject"}]}`},
		// 9/1 uxapi.boshungame.com /sdk/sdk/gateway（PHP 函数通用规则命中纯文本）
		{"含 include/define 文本的日志",
			`{"method":"sdk.log.report","data":[{"msg":"include/upload.php not found, define(DEBUG) is false, require(config.php) failed"}]}`},
		// 9/17 起 alert() 文本不再当 XSS
		{"含 alert(1) 文本的日志",
			`{"method":"log.report","data":[{"msg":"player triggered alert(1) at level 3, hp=100"}]}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code := doWAFRequest(t, g, "POST", "/sdk/sdk/gateway", "uxapi.example.com",
				map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}, tt.body)
			if code != http.StatusOK {
				t.Fatalf("正常业务日志被拦截（误报）：%s → %d", tt.name, code)
			}
		})
	}
}

// TestPostRuleEvalSystemNarrowing eval( / system( 收紧为"函数名 + 变量/字符串实参"后的双向验证
// 背景：业务日志正文里出现 eval()/system(x) 这类纯文本会被误报，
// 现在是 \beval\s*\(\s*[$"'] 或 [$"']|\w+\( 形式 —— 即必须有实参上下文
func TestPostRuleEvalSystemNarrowing(t *testing.T) {
	g := newUATestGuard(t)
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}

	t.Run("日志纯文本不再误报", func(t *testing.T) {
		for _, body := range []string{
			`{"msg":"script eval() failed at line 12"}`,
			`{"msg":"eval(1+1) 计算完成"}`,
			`{"msg":"the system(Windows) 版本不兼容"}`,
			`{"msg":"retrieval($data) 调用完成"}`,
		} {
			if code := doWAFRequest(t, g, "POST", "/sdk/sdk/gateway", "uxapi.example.com", headers, body); code != http.StatusOK {
				t.Fatalf("日志文本被拦截（误报）：%s → %d", body, code)
			}
		}
	})

	t.Run("真实 eval/system 调用仍拦截", func(t *testing.T) {
		for _, body := range []string{
			`{"x":"eval($_POST[1])"}`,
			`{"x":"eval(base64_decode('cGhwaW5mbygpOw=='))"}`,
			`{"x":"system($_GET['cmd'])"}`,
			`{"x":"system(\"ls -la\")"}`,   // JSON 转义引号形式，收紧规则必须兼容
			`{"x":"eval(\"phpinfo();\")"}`, // 同上
		} {
			if code := doWAFRequest(t, g, "POST", "/sdk/sdk/gateway", "uxapi.example.com", headers, body); code != http.StatusForbidden {
				t.Fatalf("真实调用未被拦截：%s → %d", body, code)
			}
		}
	})
}

// TestTruePositiveStillBlockedAfterFixes 上述误报修复不能削弱真实攻击拦截能力
func TestTruePositiveStillBlockedAfterFixes(t *testing.T) {
	g := newUATestGuard(t)

	t.Run("UA 扫描器", func(t *testing.T) {
		for _, ua := range []string{"sqlmap/1.0", "Mozilla/5.0 (compatible; Burp Suite Professional)"} {
			if code := doWAFRequest(t, g, "GET", "/", "example.com", map[string]string{"User-Agent": ua}, ""); code != http.StatusForbidden {
				t.Fatalf("攻击 UA 未被拦截：%q → %d", ua, code)
			}
		}
	})

	t.Run("POST 真实攻击", func(t *testing.T) {
		cases := []struct{ name, body string }{
			{"java.lang.Runtime 反序列化", `{"x":"java.lang.Runtime.getRuntime().exec(\"id\")"}`},
			{"file_get_contents 读文件", `{"x":"file_get_contents(/etc/passwd)"}`},
			{"phpinfo 探测", `{"x":"phpinfo()"}`},
			{"XSS script 标签", `{"q":"<script>alert(1)</script>"}`},
		}
		for _, tt := range cases {
			code := doWAFRequest(t, g, "POST", "/sdk/sdk/gateway", "uxapi.example.com",
				map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}, tt.body)
			if code != http.StatusForbidden {
				t.Fatalf("真实攻击未被拦截：%s → %d", tt.name, code)
			}
		}
	})
}
