package caddyguard

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hotReloadInterval 热加载检查间隔
// 在此间隔内复用缓存结果，避免每个请求都 os.Stat
const hotReloadInterval = 2 * time.Second

// RuleCache 规则缓存：管理所有规则文件、config.json、domain.json 的 mtime 缓存
type RuleCache struct {
	mu           sync.RWMutex
	ruleDir      string
	files        map[string]*ruleFileEntry // key: filepath
	domainJSON   *domainConfigEntry
	globalConfig *globalConfigEntry // config.json 缓存

	// 热加载节流：上次检查 mtime 的时间
	lastCheckNano int64 // atomic，上次 os.Stat 的时间戳（纳秒）
}

// ruleFileEntry 存储预编译后的规则
type ruleFileEntry struct {
	modTime int64       // Unix mtime (秒)
	rules   []RuleEntry // 预编译后的规则列表
	exists  bool        // 文件是否存在
	// 热加载节流：上次检查此文件 mtime 的时间
	lastCheckNano int64 // atomic
}

// domainConfigEntry domain.json 缓存条目
type domainConfigEntry struct {
	modTime       int64
	configs       map[string]Config     // 精确域名 → 预合并后的 Config
	wildcards     []domainWildcardEntry // 通配符域名列表（加载时预解析）
	lastCheckNano int64                 // atomic
}

// domainWildcardEntry 通配符域名配置
type domainWildcardEntry struct {
	suffix string // .example.com
	config Config
}

// globalConfigEntry config.json 缓存条目
type globalConfigEntry struct {
	modTime       int64
	config        Config
	lastCheckNano int64 // atomic
}

// NewRuleCache 创建规则缓存
func NewRuleCache(ruleDir string) *RuleCache {
	return &RuleCache{
		ruleDir: ruleDir,
		files:   make(map[string]*ruleFileEntry),
	}
}

// getFileMtime 获取文件修改时间（对应 Lua FFI stat）
func getFileMtime(filepath string) (int64, bool) {
	info, err := os.Stat(filepath)
	if err != nil {
		return 0, false
	}
	return info.ModTime().Unix(), true
}

// shouldCheck 判断是否需要重新检查 mtime（节流）
// 在 hotReloadInterval 内不重复检查
func shouldCheck(lastCheckNano int64) bool {
	now := time.Now().UnixNano()
	return now-lastCheckNano > int64(hotReloadInterval)
}

// GetRule 获取预编译规则列表（带缓存）
//  1. 先查域名 rule_dir，文件不存在再回退全局
//  2. 文件存在但为空 → 返回空列表（不回退）
//     空文件代表「此域名关闭该规则」，而非「使用全局规则」
//  3. 文件不存在 → 回退全局目录
func (rc *RuleCache) GetRule(filename string, domainRuleDir string) []RuleEntry {
	// 1. 检查域名目录
	if domainRuleDir != "" {
		domainPath := resolveRuleDir(domainRuleDir, rc.ruleDir) + "/" + filename
		rules, exists := rc.loadCached(domainPath)
		if exists {
			return rules // 文件存在（即使为空也返回）
		}
	}
	// 2. 回退全局目录
	globalPath := rc.ruleDir + "/" + filename
	rules, _ := rc.loadCached(globalPath)
	return rules
}

// loadCached 带缓存的文件读取
// 缓存策略：比较 mtime，mtime 未变则用缓存
// 热加载节流：在 hotReloadInterval 内跳过 os.Stat，直接用缓存
func (rc *RuleCache) loadCached(filepath string) ([]RuleEntry, bool) {
	// 快速路径：先读锁检查缓存是否可用（跳过 os.Stat）
	rc.mu.RLock()
	entry, ok := rc.files[filepath]
	rc.mu.RUnlock()

	if ok {
		// 检查是否在节流窗口内
		if !shouldCheck(atomic.LoadInt64(&entry.lastCheckNano)) {
			// 节流窗口内，直接用缓存
			return entry.rules, entry.exists
		}
	}

	// 需要检查 mtime
	mtime, exists := getFileMtime(filepath)
	if !exists {
		return nil, false
	}

	// 缓存命中（mtime 未变）
	if ok && entry.modTime == mtime {
		// 更新最后检查时间
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.rules, true
	}

	// 缓存未命中，读取文件
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// double check
	if entry, ok := rc.files[filepath]; ok && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.rules, true
	}

	// 读取并解析 + 预编译
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, false
	}

	rules := parseAndCompileRules(string(content))
	nowNano := time.Now().UnixNano()
	rc.files[filepath] = &ruleFileEntry{
		modTime:       mtime,
		rules:         rules,
		exists:        true,
		lastCheckNano: nowNano,
	}
	return rules, true
}

// parseAndCompileRules 按行解析规则文件，空行跳过
// 每条规则在加载阶段预编译为 *regexp.Regexp，并提取字面量关键词用于预过滤
// 编译失败的规则跳过
// hasRegexMetachar 检查规则是否包含正则元字符
// 不含元字符的纯字符串规则可以用 strings.Contains 做子串匹配，快 10 倍+
// 对应 Lua 的 dual-engine 分离逻辑
func hasRegexMetachar(s string) bool {
	return strings.ContainsAny(s, `()%.[]{}*+?^$|\`)
}

func parseAndCompileRules(content string) []RuleEntry {
	var rules []RuleEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 判断是否是纯字符串规则（不含正则元字符）
		isPlain := !hasRegexMetachar(line)

		// 预编译正则（大小写敏感模式）
		re, err := compileRegex(line)
		if err != nil {
			continue
		}
		// 预编译大小写不敏感版本（(?i) 前缀）
		reCI, _ := compileRegex("(?i)" + line)
		// 提取字面量关键词用于快速预过滤
		keywords := extractKeywords(line)
		rules = append(rules, RuleEntry{
			Raw:      line,
			Regex:    re,
			RegexCI:  reCI,
			Keywords: keywords,
			IsPlain:  isPlain,
		})
	}

	return rules
}

// extractKeywords 从正则表达式中提取字面量关键词
// 用于 bytes.Contains 预过滤：如果输入不包含任何关键词，
// 则不可能命中该正则，可直接跳过。
//
// 算法：逐字符扫描正则，跳过元字符和量词，
// 收集连续的字面量子串。对于交替组 (a|b|c)，
// 递归提取每个分支作为独立关键词。
// 过滤掉长度 < 2 的关键词（太短会误判）。
func extractKeywords(pattern string) [][]byte {
	// 去掉前缀 (?i) 等
	cleaned := stripRegexFlags(pattern)
	keywords := extractKeywordsRecursive(cleaned)

	// 过滤：长度 < 2 的关键词没有预过滤价值
	// 同时去重
	seen := make(map[string]bool)
	var result [][]byte
	for _, kw := range keywords {
		if len(kw) < 2 {
			continue
		}
		// 转小写用于去重（因为 matchRulesBytes 会先 lowercase body）
		lower := bytes.ToLower(kw)
		if seen[string(lower)] {
			continue
		}
		seen[string(lower)] = true
		result = append(result, lower)
	}
	return result
}

// stripRegexFlags 去掉正则前缀标记如 (?i), (?m), (?s) 等
func stripRegexFlags(pattern string) string {
	for strings.HasPrefix(pattern, "(?i)") || strings.HasPrefix(pattern, "(?m)") ||
		strings.HasPrefix(pattern, "(?s)") || strings.HasPrefix(pattern, "(?x)") {
		pattern = pattern[4:]
	}
	return pattern
}

// extractKeywordsRecursive 递归提取关键词
func extractKeywordsRecursive(pattern string) [][]byte {
	var result [][]byte
	var buf strings.Builder

	i := 0
	for i < len(pattern) {
		c := pattern[i]

		switch c {
		case '\\':
			// 转义字符：取下一个字符作为字面量
			if i+1 < len(pattern) {
				next := pattern[i+1]
				// 特殊转义序列：\d, \s, \w, \W, \S, \D, \b, \B, \A, \z, \Z 等是正则元语义
				if isRegexEscapeClass(next) {
					// 刷新当前 buffer
					flushBuilder(&buf, &result)
					i += 2
					continue
				}
				// 普通转义字符（如 \., \$, \/, \( 等）作为字面量
				buf.WriteByte(next)
				i += 2
				continue
			}
			flushBuilder(&buf, &result)
			i++

		case '(', '[':
			// 组或字符类开始：刷新当前 buffer
			flushBuilder(&buf, &result)
			// 找到匹配的闭括号
			end := findMatchingBracket(pattern, i)
			if end > i+1 {
				inner := pattern[i+1 : end]
				// 处理非捕获组前缀 (?:
				inner = strings.TrimPrefix(inner, "?:")
				// 处理内联标志 (?i:...)
				for len(inner) > 2 && inner[0] == '?' && (inner[1] == 'i' || inner[1] == 'm' || inner[1] == 's' || inner[1] == 'x') {
					if inner[2] == ':' {
						inner = inner[3:]
					} else {
						break
					}
				}
				// 如果是字符类 [...]，提取其中的字面量字符
				if c == '[' {
					extractCharClassKeywords(inner, &result)
				} else {
					// 交替组 (a|b|c)：递归提取每个分支
					for _, branch := range strings.Split(inner, "|") {
						result = append(result, extractKeywordsRecursive(branch)...)
					}
				}
			}
			i = end + 1

		case '.', '*', '+', '?', '^', '$', '|', '{', '}':
			// 正则元字符：刷新当前 buffer
			flushBuilder(&buf, &result)
			i++

		default:
			// 普通字面量字符
			buf.WriteByte(c)
			i++
		}
	}
	flushBuilder(&buf, &result)
	return result
}

// isRegexEscapeClass 判断转义字符是否是正则元语义类
func isRegexEscapeClass(c byte) bool {
	switch c {
	case 'd', 'D', 's', 'S', 'w', 'W', 'b', 'B', 'A', 'z', 'Z', 'n', 'r', 't', 'v', 'f', '0':
		return true
	}
	return false
}

// extractCharClassKeywords 从字符类 [...] 内部提取字面量字符
// 例如 [a-z0-9_] 不提取（是范围），[abc] 提取 a, b, c
// 对于我们的场景，字符类通常太宽泛，跳过
func extractCharClassKeywords(inner string, result *[][]byte) {
	// 字符类内部通常包含范围如 a-z0-9_，
	// 这些作为关键词太短或太宽泛，跳过
	// 但如果包含较长的字面量子串，可以提取
	var buf strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '-' && i > 0 && i+1 < len(inner) {
			// 范围：跳过
			flushBuilder(&buf, result)
			i++ // 跳过范围结束字符
			continue
		}
		if c == '\\' && i+1 < len(inner) {
			buf.WriteByte(inner[i+1])
			i++
			continue
		}
		buf.WriteByte(c)
	}
	flushBuilder(&buf, result)
}

// findMatchingBracket 找到匹配的闭括号位置
func findMatchingBracket(pattern string, start int) int {
	depth := 0
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
			if depth == 0 {
				return i
			}
		case '\\':
			i++ // 跳过转义
		}
	}
	return len(pattern) - 1 // 兜底
}

// flushBuilder 将 builder 中的内容作为关键词加入 result
func flushBuilder(buf *strings.Builder, result *[][]byte) {
	if buf.Len() > 0 {
		*result = append(*result, []byte(buf.String()))
		buf.Reset()
	}
}

// compileRegex 编译正则（统一入口，便于后续切换 regexp2）
func compileRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

// GetGlobalConfig 获取全局配置（带 mtime 热加载缓存）
// 等价于 Lua 版读取 config.lua 的逻辑
func (rc *RuleCache) GetGlobalConfig() Config {
	path := rc.ruleDir + "/config.json"

	// 快速路径：节流窗口内直接用缓存
	rc.mu.RLock()
	entry := rc.globalConfig
	rc.mu.RUnlock()

	if entry != nil && !shouldCheck(atomic.LoadInt64(&entry.lastCheckNano)) {
		return entry.config
	}

	// 需要检查 mtime
	mtime, exists := getFileMtime(path)
	if !exists {
		return DefaultConfig() // 文件不存在，用默认值
	}

	if entry != nil && entry.modTime == mtime {
		// mtime 未变，更新检查时间
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.config // 缓存命中
	}

	// 重新加载
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// double check
	if entry := rc.globalConfig; entry != nil && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.config
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig()
	}

	cfg := DefaultConfig() // 先填默认值
	if err := json.Unmarshal(content, &cfg); err != nil {
		return DefaultConfig() // 解析失败，用默认值
	}

	rc.globalConfig = &globalConfigEntry{
		modTime:       mtime,
		config:        cfg,
		lastCheckNano: time.Now().UnixNano(),
	}
	return cfg
}

// GetDomainConfig 获取域名级预合并配置（带 mtime 热加载缓存）
// 返回预合并后的结构：精确域名 map + 通配符列表，请求时只需一次 map 查找
func (rc *RuleCache) GetDomainConfig() *domainConfigEntry {
	path := rc.ruleDir + "/domain.json"

	// 快速路径：节流窗口内直接用缓存
	rc.mu.RLock()
	entry := rc.domainJSON
	rc.mu.RUnlock()

	if entry != nil && !shouldCheck(atomic.LoadInt64(&entry.lastCheckNano)) {
		return entry
	}

	// 需要检查 mtime
	mtime, exists := getFileMtime(path)
	if !exists {
		return nil
	}

	if entry != nil && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry
	}

	// ⚠️ 文件读取和 GetGlobalConfig 必须在写锁外执行
	// 否则 GetGlobalConfig 的 RLock 会与 GetDomainConfig 的 Lock 自死锁
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var rawConfigs map[string]json.RawMessage
	if err := json.Unmarshal(content, &rawConfigs); err != nil {
		return nil
	}

	// 获取全局基线配置用于合并（在写锁外调用，避免自死锁）
	globalCfg := rc.GetGlobalConfig()

	configs := make(map[string]Config)
	var wildcards []domainWildcardEntry

	for key, rawVal := range rawConfigs {
		var m map[string]interface{}
		if err := json.Unmarshal(rawVal, &m); err != nil {
			continue // 跳过 _comment 等非对象字段
		}
		merged := mergeDomainConfig(globalCfg, m)
		if strings.HasPrefix(key, "*.") {
			wildcards = append(wildcards, domainWildcardEntry{
				suffix: key[1:],
				config: merged,
			})
		} else {
			configs[key] = merged
		}
	}

	// 写入缓存：只需写锁
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// double check：可能在等待锁期间已被其他 goroutine 加载
	if entry := rc.domainJSON; entry != nil && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry
	}

	newEntry := &domainConfigEntry{
		modTime:       mtime,
		configs:       configs,
		wildcards:     wildcards,
		lastCheckNano: time.Now().UnixNano(),
	}
	rc.domainJSON = newEntry
	return newEntry
}

// mergeDomainConfig 将域名级 map 配置合并到全局 Config 基线上
// 在加载阶段执行一次，请求阶段零开销
func mergeDomainConfig(base Config, domainCfg map[string]interface{}) Config {
	cfg := base // 以全局基线为起点
	if v, ok := domainCfg["waf_enable"].(string); ok && v != "" {
		cfg.WAFEnable = v
	}
	if v, ok := domainCfg["trust_proxy_headers"].(string); ok && v != "" {
		cfg.TrustProxyHeaders = v
	}
	if v, ok := domainCfg["log_dir"].(string); ok && v != "" {
		cfg.LogDir = v
	}
	if v, ok := domainCfg["rule_dir"].(string); ok && v != "" {
		cfg.RuleDir = v
	}
	if v, ok := domainCfg["white_url_check"].(string); ok && v != "" {
		cfg.WhiteURLCheck = v
	}
	if v, ok := domainCfg["white_ip_check"].(string); ok && v != "" {
		cfg.WhiteIPCheck = v
	}
	if v, ok := domainCfg["white_ua_check"].(string); ok && v != "" {
		cfg.WhiteUACheck = v
	}
	if v, ok := domainCfg["black_ip_check"].(string); ok && v != "" {
		cfg.BlackIPCheck = v
	}
	if v, ok := domainCfg["url_check"].(string); ok && v != "" {
		cfg.URLCheck = v
	}
	if v, ok := domainCfg["url_args_check"].(string); ok && v != "" {
		cfg.URLArgsCheck = v
	}
	if v, ok := domainCfg["user_agent_check"].(string); ok && v != "" {
		cfg.UserAgentCheck = v
	}
	if v, ok := domainCfg["cookie_check"].(string); ok && v != "" {
		cfg.CookieCheck = v
	}
	if v, ok := domainCfg["cc_check"].(string); ok && v != "" {
		cfg.CCCheck = v
	}
	if v, ok := domainCfg["cc_rate"].(string); ok && v != "" {
		cfg.CCRate = v
	}
	if v, ok := domainCfg["cc_block_ttl"].(float64); ok && v > 0 {
		cfg.CCBlockTTL = int(v)
	}
	if v, ok := domainCfg["post_check"].(string); ok && v != "" {
		cfg.PostCheck = v
	}
	if v, ok := domainCfg["referer_check"].(string); ok && v != "" {
		cfg.RefererCheck = v
	}
	if v, ok := domainCfg["file_upload_check"].(string); ok && v != "" {
		cfg.FileUploadCheck = v
	}
	if v, ok := domainCfg["waf_output"].(string); ok && v != "" {
		cfg.WAFOutput = v
	}
	if v, ok := domainCfg["waf_redirect_url"].(string); ok && v != "" {
		cfg.WAFRedirectURL = v
	}
	return cfg
}
