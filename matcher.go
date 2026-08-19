package caddyguard

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// RuleEntry 规则条目：加载阶段预编译正则，请求阶段零编译开销
type RuleEntry struct {
	Raw      string         // 原始规则文本
	Regex    *regexp.Regexp // 预编译后的正则（大小写敏感）
	RegexCI  *regexp.Regexp // 预编译后的正则（大小写不敏感，(?i) 前缀）
	Keywords [][]byte        // 从正则中提取的字面量关键词，用于快速预过滤

	// 纯字符串规则标记：不含正则元字符的规则
	// 用 strings.Contains 做子串匹配，比 regexp 快 10 倍+
	IsPlain bool
}

// matchRules 将输入与预编译规则列表逐一匹配
// 返回命中的规则（用于日志记录）
//
// 双引擎优化（对应 Lua 的 dual-engine）：
//   - 纯字符串规则（IsPlain=true）：用 strings.Contains 做子串匹配，比 regexp 快 10x+
//   - 正则规则：用预编译的 *regexp.Regexp 匹配
//
// caseInsensitive=true 时使用 RegexCI（(?i) 前缀预编译），
// 无需运行时 ToLower，真正的大小写不敏感匹配
//
// worker 级匹配缓存（对应 Lua 的 worker_match_cache）：
//   - 对小体积输入（≤512字节）的匹配结果做全局缓存
//   - key = 规则指针 + caseInsensitive + input
//   - 命中缓存时直接返回，跳过全部正则/子串匹配
//   - 缓存上限 4096 条，满时清空重建（简单 LRU 策略）
func matchRules(input string, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
	if input == "" || len(rules) == 0 {
		return nil
	}

	// 输入最小长度预检（对应 Lua 的 MIN_RULE_LEN = 2）
	if len(input) < 2 {
		return nil
	}

	// worker 级匹配缓存：小输入复用匹配结果
	if len(input) <= matchCacheInputMax {
		cacheKey := matchCacheKey(rules, caseInsensitive, input)
		if v, ok := matchCache.Load(cacheKey); ok {
			if v == nil {
				return nil // 缓存的未命中
			}
			return v.(*RuleEntry)
		}
	}

	result := matchRulesInternal(input, rules, caseInsensitive)

	// 缓存匹配结果
	if len(input) <= matchCacheInputMax {
		cacheKey := matchCacheKey(rules, caseInsensitive, input)
		setMatchCache(cacheKey, result)
	}

	return result
}

// matchRulesInternal 不带缓存的内部匹配逻辑
func matchRulesInternal(input string, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
	// 大小写不敏感时用 ToLower 一次，纯字符串规则直接匹配 lowercase
	lowerInput := ""
	if caseInsensitive {
		lowerInput = strings.ToLower(input)
	}

	for i := range rules {
		// 纯字符串规则：用 strings.Contains 做子串匹配
		if rules[i].IsPlain {
			if caseInsensitive {
				if strings.Contains(lowerInput, strings.ToLower(rules[i].Raw)) {
					return &rules[i]
				}
			} else {
				if strings.Contains(input, rules[i].Raw) {
					return &rules[i]
				}
			}
			continue
		}
		// 正则规则：用预编译的 *regexp.Regexp 匹配
		if caseInsensitive {
			if rules[i].RegexCI != nil && rules[i].RegexCI.MatchString(input) {
				return &rules[i]
			}
		} else {
			if rules[i].Regex.MatchString(input) {
				return &rules[i]
			}
		}
	}
	return nil
}

// matchRulesBytes is the allocation-free equivalent of matchRules for request
// bodies. regexp.Regexp can match []byte directly, so callers do not need to
// convert a potentially large body to string before scanning it.
//
// 关键词预过滤：当规则有 Keywords 时，先对 body 做一次 bytes.ToLower，
// 然后用 bytes.Contains 检查是否包含任何关键词（关键词也存小写）。
// 不包含任何关键词 → 跳过该规则的正则匹配。
// 正则匹配：caseInsensitive 时用 RegexCI（(?i) 前缀）匹配原始 input，
// 保证大小写混合的规则（如 CONCAT\(）能正确匹配。
func matchRulesBytes(input []byte, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
	if len(input) == 0 || len(rules) == 0 {
		return nil
	}

	// 延迟初始化 lowered body：只在有规则需要关键词预过滤时才分配
	var lowered []byte
	needLower := false
	for i := range rules {
		if len(rules[i].Keywords) > 0 {
			needLower = true
			break
		}
	}
	if needLower {
		lowered = bytes.ToLower(input)
	}

	for i := range rules {
		// 关键词预过滤：如果 body 不包含任何关键词，跳过正则匹配
		if len(rules[i].Keywords) > 0 {
			hit := false
			for _, kw := range rules[i].Keywords {
				if bytes.Contains(lowered, kw) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}

		// 正则匹配：caseInsensitive 用 RegexCI 匹配原始 input
		re := rules[i].Regex
		if caseInsensitive {
			re = rules[i].RegexCI
		}
		if re != nil && re.Match(input) {
			return &rules[i]
		}
	}
	return nil
}

// regexCache 用于运行时动态编译的正则缓存（IP glob 等）
var regexCache sync.Map // key: pattern → value: *regexp.Regexp

// worker 级匹配缓存（对应 Lua 的 worker_match_cache）
// 缓存小体积输入的匹配结果，避免重复正则/子串匹配
var (
	matchCache          sync.Map // key: string → value: *RuleEntry (nil = 未命中缓存)
	matchCacheCount     int64    // atomic，当前缓存条目数
	matchCacheMax       int64    = 4096
	matchCacheInputMax         = 512 // 仅缓存输入 ≤512 字节的匹配结果
)

// matchCacheKey 生成缓存 key：规则集标识 + caseInsensitive + input
func matchCacheKey(rules []RuleEntry, caseInsensitive bool, input string) string {
	// 用 rules 切片的长度 + 第一条/最后一条规则的 Raw 作为规则集标识
	// 不同文件/mtime 的 rules 内容不同，足以区分
	sig := "0:0"
	if len(rules) > 0 {
		sig = fmt.Sprintf("%d:%s:%s", len(rules), rules[0].Raw, rules[len(rules)-1].Raw)
	}
	ci := "0"
	if caseInsensitive {
		ci = "1"
	}
	return sig + "|" + ci + "|" + input
}

// setMatchCache 写入匹配缓存，超过上限时清空重建
func setMatchCache(key string, value *RuleEntry) {
	if key == "" {
		return
	}
	// 只在 key 不存在时递增计数
	if _, loaded := matchCache.LoadOrStore(key, value); !loaded {
		count := atomic.AddInt64(&matchCacheCount, 1)
		if count > matchCacheMax {
			// 清空缓存（简单策略，对应 Lua 的 worker_match_cache = {}）
			matchCache = sync.Map{}
			atomic.StoreInt64(&matchCacheCount, 0)
		}
	}
}

// matchRegex 单条正则匹配（用于 IP glob 等）
// caseInsensitive 参数保留用于接口兼容，当前 IP 匹配场景固定 false
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

// globEscapeRe 预编译的正则，用于 globToRegex 中转义特殊字符
// 避免每次调用 globToRegex 都重新编译这个正则
var globEscapeRe = regexp.MustCompile(`([.+?[\](){}$^])`)

// globToRegex 将 glob 通配符转为正则
// 支持 IPv4 和 IPv6 通配符：
//
//	192.168.0.*  → ^192\.168\.0\.[0-9a-fA-F:]+$   (IPv4)
//	2001:db8::*  → ^2001:db8::[0-9a-fA-F:]+$       (IPv6)
//	192.168.*.* → ^192\.168\.[0-9a-fA-F:]+\.[0-9a-fA-F:]+$
//
// 无 * 则原样返回（视为正则）
func globToRegex(pattern string) string {
	if !strings.Contains(pattern, "*") {
		return pattern // 已是正则
	}
	// 转义特殊字符（除 *），使用预编译正则避免每次 MustCompile
	regex := globEscapeRe.ReplaceAllStringFunc(pattern, func(s string) string {
		return "\\" + s
	})
	// * → [0-9a-fA-F:]+  （匹配 IPv4 数字、IPv6 十六进制和冒号）
	regex = strings.ReplaceAll(regex, "*", `[0-9a-fA-F:]+`)
	return "^" + regex + "$"
}
