package caddyguard

import (
	"regexp"
	"strings"
	"sync"
)

// RuleEntry 规则条目：加载阶段预编译正则，请求阶段零编译开销
type RuleEntry struct {
	Raw   string         // 原始规则文本
	Regex *regexp.Regexp // 预编译后的正则
}

// matchRules 将输入与预编译规则列表逐一匹配
// 返回命中的规则（用于日志记录）
func matchRules(input string, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
	if input == "" || len(rules) == 0 {
		return nil
	}

	for i := range rules {
		re := rules[i].Regex
		if caseInsensitive {
			// 预编译时已编译为大小写敏感
			// 此处通过 ToLower 优化，避免运行时重新编译
			if re.MatchString(strings.ToLower(input)) {
				return &rules[i]
			}
		} else {
			if re.MatchString(input) {
				return &rules[i]
			}
		}
	}
	return nil
}

// regexCache 用于运行时动态编译的正则缓存（IP glob 等）
var regexCache sync.Map // key: pattern → value: *regexp.Regexp

// matchRegex 单条正则匹配（用于 IP glob 等动态规则）
func matchRegex(text, pattern string, caseInsensitive bool) bool {
	if pattern == "" || text == "" {
		return false
	}

	fullPattern := pattern
	if caseInsensitive {
		fullPattern = "(?i)" + pattern
	}

	var re *regexp.Regexp
	if v, ok := regexCache.Load(fullPattern); ok {
		re = v.(*regexp.Regexp)
	} else {
		var err error
		re, err = regexp.Compile(fullPattern)
		if err != nil {
			return false
		}
		regexCache.Store(fullPattern, re)
	}

	return re.MatchString(text)
}

// globToRegex 将 glob 通配符转为正则
// 192.168.0.* → ^192\.168\.0\.\d+$
// 192.168.*.1 → ^192\.168\.\d+\.1$
// 无 * 则原样返回
func globToRegex(pattern string) string {
	if !strings.Contains(pattern, "*") {
		return pattern // 已是正则
	}
	// 转义特殊字符（除 *）
	regex := regexp.MustCompile(`([.+?[\](){}$^])`).ReplaceAllStringFunc(pattern, func(s string) string {
		return "\\" + s
	})
	// * → \d+
	regex = strings.ReplaceAll(regex, "*", `\d+`)
	return "^" + regex + "$"
}
