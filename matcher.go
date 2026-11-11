package caddyguard

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
// worker 级分段匹配缓存（与 NginxGuard Lua 版同一结构与淘汰策略）：
//   - 对小体积输入（≤512字节）的匹配结果做缓存，只优化检测速度、绝不改变检测结果
//   - key = 规则集内容 FNV-1a 签名 + caseInsensitive + 完整 input，
//     规则热加载（改任意一条规则）都会产生新签名，旧缓存 key 不可达
//   - 新结果进暂存区（1024, FIFO），二次命中晋升热点区（3072, FIFO 批量淘汰）
//   - 高基数洪水（大量一次性输入）只冲刷暂存区，热点区条目完整保留
//   - 容量压力只做部分淘汰，绝不清空缓存、绝不跳过检测
func matchRules(input string, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
	if input == "" || len(rules) == 0 {
		return nil
	}

	// 输入最小长度预检（对应 Lua 的 MIN_RULE_LEN = 2）
	if len(input) < 2 {
		return nil
	}

	// worker 级匹配缓存：小输入复用匹配结果（热点区 → 暂存区 → 晋升）
	var cacheKey string
	if len(input) <= matchCacheInputMax {
		cacheKey = matchCacheKey(rules, caseInsensitive, input)
		if re, ok := matchHotZone.lookup(cacheKey); ok {
			if re == nil {
				return nil // 缓存的未命中
			}
			return re
		}
		if re, ok := matchProbationZone.lookup(cacheKey); ok {
			// 暂存区二次命中 → 晋升热点区
			matchProbationZone.promote(cacheKey)
			matchHotZone.insert(cacheKey, re)
			if re == nil {
				return nil
			}
			return re
		}
	}

	result := matchRulesInternal(input, rules, caseInsensitive)

	// 缓存匹配结果（负缓存 nil 也写入，与命中路径语义一致）
	if cacheKey != "" {
		matchProbationZone.insert(cacheKey, result)
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

// worker 级分段匹配缓存（对应 NginxGuard Lua 版的分段缓存结构，并发安全）
// store 用 sync.Map（命中路径无锁读），FIFO 队列/淘汰用 mutex 串行化（低频路径）。
// owner 时间戳实现晋升后的残留槽位懒删除，重复晋升产生的重复槽位无害。
type matchZone struct {
	mu     sync.Mutex       // 保护 q/owner/head/seq（淘汰与入队）
	store  sync.Map         // key → *RuleEntry (nil = 负缓存/未命中)
	q      []string         // FIFO 环形队列, slot = seq % ring
	owner  map[string]int64 // key → 入队 seq
	head   int64
	seq    int64
	cap    int  // 容量
	ring   int  // 环形队列长度 (2x cap)
	evictN int  // 满时批量淘汰条数
}

func newMatchZone(cap, evictN int) *matchZone {
	return &matchZone{
		q:      make([]string, cap*2),
		owner:  make(map[string]int64),
		cap:    cap,
		ring:   cap * 2,
		evictN: evictN,
	}
}

var (
	matchProbationZone = newMatchZone(1024, 1)   // 暂存区: 新结果先进这里, 满时逐条 FIFO 淘汰
	matchHotZone       = newMatchZone(3072, 384) // 热点区: 二次命中晋升, 满时批量淘汰 384 条
	matchCacheInputMax = 512                     // 仅缓存输入 ≤512 字节的匹配结果
)

// lookup 读取缓存条目 (ok=true 表示 key 存在, 条目可能是 nil 负缓存)
func (z *matchZone) lookup(key string) (*RuleEntry, bool) {
	v, ok := z.store.Load(key)
	if !ok {
		return nil, false
	}
	re, _ := v.(*RuleEntry)
	return re, true
}

// insert 写入新结果; 容量满时按 evictN 批量 FIFO 淘汰最旧条目 (只淘汰, 不清空)
func (z *matchZone) insert(key string, value *RuleEntry) {
	z.mu.Lock()
	if z.seq-z.head >= int64(z.cap) {
		n := int64(z.evictN)
		if n > z.seq-z.head {
			n = z.seq - z.head
		}
		for i := int64(0); i < n; i++ {
			slot := z.head % int64(z.ring)
			k := z.q[slot]
			z.q[slot] = ""
			z.head++
			if k == "" {
				continue
			}
			// owner 时间戳: 槽位对应 key 的当前入队才淘汰, 晋升残留的旧槽位跳过
			if seq, ok := z.owner[k]; ok && seq == z.head-1 {
				delete(z.owner, k)
				z.store.Delete(k)
			}
		}
	}
	slot := z.seq % int64(z.ring)
	z.q[slot] = key
	z.owner[key] = z.seq
	z.seq++
	z.mu.Unlock()
	z.store.Store(key, value)
}

// promote 从本区移除条目 (晋升到热点区前调用); 队列残留槽位由淘汰时懒删除
func (z *matchZone) promote(key string) {
	z.mu.Lock()
	delete(z.owner, key)
	z.mu.Unlock()
	z.store.Delete(key)
}

// matchCacheStats 缓存占用诊断 (对应 Lua 版 get_match_cache_stats)
func matchCacheStats() (hot int, probation int) {
	matchHotZone.mu.Lock()
	hot = int(matchHotZone.seq - matchHotZone.head)
	matchHotZone.mu.Unlock()
	matchProbationZone.mu.Lock()
	probation = int(matchProbationZone.seq - matchProbationZone.head)
	matchProbationZone.mu.Unlock()
	return
}

// matchCacheKey 生成缓存 key：规则集内容 FNV-1a 签名 + caseInsensitive + 完整 input
// 对规则 Raw 逐条哈希 —— 规则集任何变化（热加载改任意一条规则）都会产生不同签名,
// 旧缓存 key 随之不可达（对应 Lua 版的 规则文件|mtime 标识）
func matchCacheKey(rules []RuleEntry, caseInsensitive bool, input string) string {
	const (
		fnvOffset = 2166136261
		fnvPrime  = 16777619
	)
	h := uint32(fnvOffset)
	for i := range rules {
		for j := 0; j < len(rules[i].Raw); j++ {
			h ^= uint32(rules[i].Raw[j])
			h *= fnvPrime
		}
		h ^= '\n'
		h *= fnvPrime
	}
	if caseInsensitive {
		h ^= 'i'
		h *= fnvPrime
	}
	b := make([]byte, 0, len(input)+11)
	b = strconv.AppendUint(b, uint64(h), 10)
	b = append(b, '|')
	b = append(b, input...)
	return string(b)
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
