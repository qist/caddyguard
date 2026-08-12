package caddyguard

import (
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
	config        map[string]map[string]interface{}
	raw           []byte
	lastCheckNano int64 // atomic
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
// 1. 先查域名 rule_dir，文件不存在再回退全局
// 2. 文件存在但为空 → 返回空列表（不回退）
//    空文件代表「此域名关闭该规则」，而非「使用全局规则」
// 3. 文件不存在 → 回退全局目录
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
// 每条规则在加载阶段预编译为 *regexp.Regexp
// 编译失败的规则跳过
func parseAndCompileRules(content string) []RuleEntry {
	var rules []RuleEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 预编译正则（大小写敏感模式）
		re, err := compileRegex(line)
		if err != nil {
			continue
		}
		rules = append(rules, RuleEntry{
			Raw:   line,
			Regex: re,
		})
	}
	return rules
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

// GetDomainConfig 获取域名级配置（带 mtime 热加载缓存）
func (rc *RuleCache) GetDomainConfig(domain string) map[string]map[string]interface{} {
	path := rc.ruleDir + "/domain.json"

	// 快速路径：节流窗口内直接用缓存
	rc.mu.RLock()
	entry := rc.domainJSON
	rc.mu.RUnlock()

	if entry != nil && !shouldCheck(atomic.LoadInt64(&entry.lastCheckNano)) {
		return entry.config
	}

	// 需要检查 mtime
	mtime, exists := getFileMtime(path)
	if !exists {
		return nil
	}

	if entry != nil && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.config
	}

	// 重新加载
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if entry != nil && entry.modTime == mtime {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.config
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// 先解析为 RawMessage，跳过非对象值（如 _comment 字符串）
	var rawConfigs map[string]json.RawMessage
	if err := json.Unmarshal(content, &rawConfigs); err != nil {
		return nil
	}

	configs := make(map[string]map[string]interface{})
	for key, rawVal := range rawConfigs {
		// 尝试解析为 map[string]interface{}，非对象值（如字符串）跳过
		var m map[string]interface{}
		if err := json.Unmarshal(rawVal, &m); err != nil {
			continue // 跳过 _comment 等非对象字段
		}
		configs[key] = m
	}

	rc.domainJSON = &domainConfigEntry{
		modTime:       mtime,
		config:        configs,
		raw:           content,
		lastCheckNano: time.Now().UnixNano(),
	}
	return configs
}
