# CaddyGuard 开发文档

> CaddyGuard — A lightweight WAF and security middleware for Caddy v2
>
> 基于 Lua WAF 逻辑，用 Go 实现的 Caddy v2 安全中间件。

---

## 1. 项目概述

### 1.1 定位

CaddyGuard 不仅是 WAF，而是一个完整的安全中间件：

- **WAF 攻击检测**：URL / URL参数 / POST / UA / Cookie / Referer / 文件上传
- **IP 管理**：黑白名单 / 动态拉黑
- **CC 防护**：滑动窗口限速 + 自动拉黑
- **域名策略**：域名级配置覆盖 + 规则隔离
- **日志审计**：JSON 格式攻击日志 + 自动轮转

### 1.2 目标

将现有 Nginx+Lua WAF 的全部能力迁移到 Caddy 生态，并在此基础上扩展：

- 12 种安全检测（在 Lua 版 11 种基础上改进文件上传）
- 域名级配置覆盖（`domain.json`）
- 规则文件热加载（mtime 缓存）
- CC 滑动窗口限速 + 自动拉黑（可扩展分布式存储）
- JSON 格式攻击日志 + 自动轮转（worker 模式异步写入）
- 信任代理头开关（防 IP 伪造）

### 1.3 设计原则

- **规则文件 100% 复用**：直接拷贝现有 `.rule` 文件，零迁移成本
- **config.json 格式对应 config.lua**：全局 WAF 配置热加载，与 Lua 版理念一致
- **domain.json 格式不变**：配置文件与 Lua 版完全一致
- **Caddyfile 极简**：全局块只配 `rule_dir`，站点块零安全配置，等价于 Lua 版 `access_by_lua_file` 只写一次
- **规则预编译**：加载阶段编译正则，请求阶段零编译开销
- **存储可插拔**：CC 计数 / IP 封禁通过 interface 抽象，单机内存 → Redis 可切换

---

## 2. 项目结构

```
caddyguard/
├── go.mod
├── module.go                # Caddy 模块注册 + Caddyfile 解析 + 全局选项注入
├── handler.go               # HTTP 中间件 + 检测链调度
├── config/
│   ├── config.go            # Config 结构体 + DefaultConfig + config.json 热加载
│   └── domain.go            # 域名级配置合并 + 通配符匹配
├── engine/
│   ├── rules.go             # 规则加载 + mtime 缓存 + 回退机制
│   ├── matcher.go           # 正则预编译 + Glob 转 Regex + 匹配引擎
│   └── cache.go             # RuleCache 结构体 + 缓存管理
├── detector/
│   ├── ip.go                # IP 白名单 / 黑名单 / 动态拉黑
│   ├── url.go               # URL 路径 / URL 参数检测
│   ├── ua.go                # UA 攻击检测 / UA 白名单
│   ├── post.go              # POST 表单 / JSON body 检测
│   ├── cookie.go            # Cookie 检测
│   ├── referer.go           # Referer 检测
│   ├── fileupload.go        # 文件上传检测（multipart header 级别）
│   └── cc.go                # CC 限速 + 滑动窗口
├── storage/
│   ├── memory.go            # 内存存储实现（CC 计数 + IP 封禁）
│   └── redis.go             # Redis 存储实现（预留，多节点部署用）
├── logger/
│   └── logger.go            # JSON 日志 + channel worker + 轮转
├── utils/
│   └── utils.go             # 工具函数（IP获取、域名匹配等）
├── rule-config/             # 规则文件（与 Lua 版完全一致）
│   ├── config.json          # 全局安全配置（等价于 config.lua，热加载）
│   ├── domain.json          # 域名级配置覆盖（热加载）
│   ├── args.rule
│   ├── blackip.rule
│   ├── cookie.rule
│   ├── fileext.rule
│   ├── post.rule
│   ├── referer.rule
│   ├── url.rule
│   ├── useragent.rule
│   ├── whiteip.rule
│   ├── whiteua.rule
│   ├── whiteurl.rule
│   └── domains/
│       └── www.example.com/
│           └── ...
└── README.md
```

---

## 3. Caddy 插件注册

### 3.1 模块注册

```go
package caddyguard

import (
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyhttp"
    "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
    caddy.RegisterModule(Guard{})
    // 注册为全局选项指令，在 Caddyfile 全局 {} 块中使用
    httpcaddyfile.RegisterGlobalOption("caddyguard", parseGlobalOption)
}

// Guard 实现 caddyhttp.MiddlewareHandler 接口
// 同时实现 caddy.Provisioner 和 caddy.CleanerUpper
type Guard struct {
    // 唯一从 Caddyfile 全局块解析的配置项
    RuleDir string `json:"rule_dir,omitempty"`

    // 运行时状态（不序列化）
    ruleCache *engine.RuleCache
    ccStore   storage.CCStore
    logger    *logger.WAFLogger

    cleanupCtx    context.Context
    cleanupCancel context.CancelFunc
}

// CaddyModule 返回模块信息
func (Guard) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "http.handlers.caddyguard",
        New: func() caddy.Module { return new(Guard) },
    }
}
```

### 3.2 Caddyfile 语法设计

**设计原则**：与 Lua WAF 在 nginx `http {}` 里写一次 `access_by_lua_file` 一样，
`caddyguard` 配置在 Caddyfile **全局 `{}` 块**中，只写一次，所有站点自动生效。
站点块里不需要任何安全配置。

```caddyfile
# 全局配置（只写一次）
{
    order caddyguard before reverse_proxy
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
}

# 站点 1：无需安全配置
example.com {
    reverse_proxy 127.0.0.1:8080
}

# 站点 2：无需安全配置
foo.com {
    reverse_proxy 127.0.0.1:9090
}

# 站点 3：无需安全配置
bar.com {
    reverse_proxy 127.0.0.1:7070
}
```

**Caddyfile 中支持的指令**：

| 指令 | 位置 | 说明 | 默认值 |
|------|------|------|--------|
| `rule_dir` | 全局块 | 规则文件目录（包含 `config.json`、`domain.json`、`*.rule`） | `/etc/caddyguard/rule-config` |

> 其他所有安全配置项（`waf_enable`、`url_check`、`cc_rate`、`bot_check` 等）均通过
> `{rule_dir}/config.json` 管理，支持 mtime 热加载，修改后无需 `caddy reload`。

### 3.3 Caddyfile 解析器 + Handler 注入

> **关键问题**：`RegisterGlobalOption` 返回的值不会自动插入 HTTP handler。
> `order caddyguard before reverse_proxy` 只是排序，不会凭空生成 handler。
>
> **解决方案**：通过 `caddyhttp.AdminRouter` 或在 `Provision()` 中使用
> `caddyhttp.NewNullResponseRecorder` + 全局 subroute 注入。
> 更稳定的方式是注册为全局 App，在 App 的 `Provision()` 中
> 通过 `ctx.App("http")` 获取 `caddyhttp.App`，
> 在 `Servers` 的每个 server 的 routes 前面插入 middleware。

```go
// parseGlobalOption 解析全局 caddyguard 块
// 在 Caddyfile 的全局 {} 块中：caddyguard { rule_dir ... }
func parseGlobalOption(d *httpcaddyfile.Dispenser) (interface{}, error) {
    var ruleDir string
    for d.Next() {
        for nesting := d.Nesting(); d.NextBlock(nesting); {
            switch d.Val() {
            case "rule_dir":
                if !d.NextArg() {
                    return nil, d.ArgErr()
                }
                ruleDir = d.Val()
            }
        }
    }
    return GlobalConfig{RuleDir: ruleDir}, nil
}

// GlobalConfig 是全局选项的解析结果
// 在 Provision 阶段会将其注入到所有 HTTP server 的路由中
type GlobalConfig struct {
    RuleDir string
}
```

### 3.4 Handler 注入实现

```go
// Guard 实现 caddy.Provisioner
func (g *Guard) Provision(ctx caddy.Context) error {
    // Caddyfile 中只配了 rule_dir，其余从 config.json 热加载
    if g.RuleDir == "" {
        g.RuleDir = "/etc/caddyguard/rule-config"
    }

    // 初始化运行时组件
    g.ruleCache = engine.NewRuleCache(g.RuleDir)

    // CC 存储使用内存实现（后续可切换 Redis）
    g.ccStore = storage.NewMemoryStore()

    // 从 config.json 读取全局配置初始化 logger
    cfg := g.ruleCache.GetGlobalConfig()
    g.logger = logger.NewWAFLogger(cfg.LogDir)

    // 启动后台清理 goroutine
    g.cleanupCtx, g.cleanupCancel = context.WithCancel(ctx.Context)
    go g.cleanupLoop()

    return nil
}

// Guard 实现 caddy.CleanerUpper
func (g *Guard) Cleanup() error {
    if g.cleanupCancel != nil {
        g.cleanupCancel()
    }
    if g.logger != nil {
        g.logger.Close()
    }
    return nil
}
```

### 3.5 中间件接口

```go
// Guard 实现 caddyhttp.MiddlewareHandler
func (g Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    // recover 容错（对应 Lua 版 pcall）
    defer func() {
        if rv := recover(); rv != nil {
            // 不因 WAF 内部 panic 影响请求
        }
    }()

    // 1. 获取域名级配置（config.json 全局基线 + domain.json 域名覆盖）
    cfg := g.GetEffectiveConfig(r)

    // 2. 安全总开关
    if cfg.WAFEnable == "off" {
        return next.ServeHTTP(w, r)
    }

    // 3. 执行检测链
    blocked := g.runChecks(w, r, cfg)
    if blocked {
        return nil  // 已输出拦截响应，不再继续
    }

    // 4. 放行
    return next.ServeHTTP(w, r)
}
```

---

## 4. 配置系统

### 4.1 全局配置文件 config.json（等价于 config.lua）

全局安全配置存放在 `{rule_dir}/config.json`，热加载，格式与 `Config` 结构体一致：

```json
{
    "waf_enable": "on",
    "trust_proxy_headers": "on",
    "log_dir": "/var/log/caddy",
    "url_check": "on",
    "url_args_check": "on",
    "post_check": "on",
    "user_agent_check": "on",
    "cookie_check": "on",
    "cc_check": "on",
    "cc_rate": "60/60",
    "cc_block_ttl": 600,
    "white_ip_check": "on",
    "white_ua_check": "on",
    "white_url_check": "on",
    "black_ip_check": "on",
    "referer_check": "off",
    "file_upload_check": "on",
    "waf_output": "html",
    "waf_redirect_url": "https://www.waf.com"
}
```

**加载策略**：
- 启动时从 `{rule_dir}/config.json` 读取，字段缺失则用 `DefaultConfig()` 默认值
- 运行时通过 mtime 检测热加载，修改 `config.json` 后立即生效，无需 `caddy reload`
- `rule_dir` 字段以 Caddyfile 全局块中设置的为准（config.json 中的 `rule_dir` 仅作记录，不覆盖）

#### 配置结构体

```go
type Config struct {
    WAFEnable         string `json:"waf_enable"`          // "on" / "off"
    TrustProxyHeaders string `json:"trust_proxy_headers"` // "on" / "off"
    LogDir            string `json:"log_dir"`
    RuleDir           string `json:"rule_dir"`

    WhiteURLCheck   string `json:"white_url_check"`
    WhiteIPCheck    string `json:"white_ip_check"`
    WhiteUACheck    string `json:"white_ua_check"`
    BlackIPCheck    string `json:"black_ip_check"`
    URLCheck        string `json:"url_check"`
    URLArgsCheck    string `json:"url_args_check"`
    UserAgentCheck  string `json:"user_agent_check"`
    CookieCheck     string `json:"cookie_check"`
    CCCheck         string `json:"cc_check"`
    CCRate          string `json:"cc_rate"`          // "60/60"
    CCBlockTTL      int    `json:"cc_block_ttl"`     // 600
    PostCheck       string `json:"post_check"`
    RefererCheck    string `json:"referer_check"`
    FileUploadCheck string `json:"file_upload_check"`

    WAFOutput      string `json:"waf_output"`        // "html" / "redirect"
    WAFRedirectURL string `json:"waf_redirect_url"`
}

// 默认配置（对应 config.lua 的默认值）
// 当 config.json 不存在或某字段缺失时，使用这些默认值
func DefaultConfig() Config {
    return Config{
        WAFEnable:         "on",
        TrustProxyHeaders: "on",
        LogDir:            "/var/log/caddy",
        RuleDir:           "/etc/caddyguard/rule-config",
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
```

#### config.json 热加载实现

```go
// GetGlobalConfig 获取全局配置（带 mtime 热加载缓存）
// 等价于 Lua 版读取 config.lua 的逻辑
func (rc *RuleCache) GetGlobalConfig() Config {
    path := rc.ruleDir + "/config.json"
    mtime, exists := getFileMtime(path)
    if !exists {
        return DefaultConfig()  // 文件不存在，用默认值
    }

    rc.mu.RLock()
    entry := rc.globalConfig
    rc.mu.RUnlock()

    if entry != nil && entry.modTime == mtime {
        return entry.config  // 缓存命中
    }

    // 重新加载
    rc.mu.Lock()
    defer rc.mu.Unlock()

    // double check
    if entry := rc.globalConfig; entry != nil && entry.modTime == mtime {
        return entry.config
    }

    content, err := os.ReadFile(path)
    if err != nil {
        return DefaultConfig()
    }

    cfg := DefaultConfig()  // 先填默认值
    if err := json.Unmarshal(content, &cfg); err != nil {
        return DefaultConfig()  // 解析失败，用默认值
    }

    rc.globalConfig = &globalConfigEntry{
        modTime: mtime,
        config:  cfg,
    }
    return cfg
}
```

### 4.2 域名级配置

domain.json 格式与 Lua 版完全一致：

```json
{
    "www.example.com": {
        "url_check": "off",
        "cc_rate": "100/60",
        "cc_block_ttl": 300,
        "rule_dir": "domains/www.example.com"
    }
}
```

### 4.3 配置合并逻辑

```go
// GetEffectiveConfig 合并全局配置和域名级配置
// 全局基线从 config.json 热加载，域名级配置从 domain.json 热加载
// 域名级配置优先，未设置的项回退到全局
func (g *Guard) GetEffectiveConfig(r *http.Request) Config {
    // 全局基线：从 config.json 热加载
    cfg := g.ruleCache.GetGlobalConfig()

    domain := getDomain(r)
    domainCfg := g.ruleCache.GetDomainConfig(domain)
    if domainCfg == nil {
        return cfg
    }

    // 逐项覆盖
    if v, ok := domainCfg["waf_enable"]; ok { cfg.WAFEnable = v.(string) }
    if v, ok := domainCfg["trust_proxy_headers"]; ok { cfg.TrustProxyHeaders = v.(string) }
    if v, ok := domainCfg["url_check"]; ok { cfg.URLCheck = v.(string) }
    if v, ok := domainCfg["cc_rate"]; ok { cfg.CCRate = v.(string) }
    if v, ok := domainCfg["cc_block_ttl"]; ok { cfg.CCBlockTTL = int(v.(float64)) }
    if v, ok := domainCfg["rule_dir"]; ok { cfg.RuleDir = v.(string) }
    // ... 所有配置项

    return cfg
}
```

### 4.4 域名匹配（精确 + 通配符）

```go
// matchDomain 先精确匹配，再通配符匹配
// *.example.com → 匹配 a.example.com, b.example.com
func matchDomain(domainConfigs map[string]map[string]interface{}, domain string) map[string]interface{} {
    // 1. 精确匹配
    if cfg, ok := domainConfigs[domain]; ok {
        return cfg
    }
    // 2. 通配符匹配
    for pattern, cfg := range domainConfigs {
        if pattern == "_comment" {
            continue
        }
        if strings.HasPrefix(pattern, "*.") {
            suffix := pattern[1:] // ".example.com"
            if strings.HasSuffix(domain, suffix) {
                return cfg
            }
        }
    }
    return nil
}
```

---

## 5. 规则加载与缓存

### 5.1 缓存结构

```go
type RuleCache struct {
    mu           sync.RWMutex
    ruleDir      string
    files        map[string]*ruleFileEntry    // key: filepath
    domainJSON   *domainConfigEntry
    globalConfig *globalConfigEntry            // config.json 缓存
}

// ruleFileEntry 存储预编译后的规则
type ruleFileEntry struct {
    mtime  time.Time     // 文件修改时间
    modTime int64        // Unix mtime (秒)
    rules  []RuleEntry   // 预编译后的规则列表
    exists bool          // 文件是否存在
}

// RuleEntry 规则条目：加载阶段预编译正则，请求阶段零编译开销
type RuleEntry struct {
    Raw    string         // 原始规则文本
    Regex  *regexp.Regexp // 预编译后的正则
    Tag    string         // 规则标签（用于日志标识）
}

type domainConfigEntry struct {
    mtime   int64
    modTime time.Time
    config  map[string]map[string]interface{}
    raw     []byte
}

type globalConfigEntry struct {
    modTime int64
    config  Config
}
```

### 5.2 mtime 检测（对应 Lua FFI stat）

Go 原生支持，无需 FFI：

```go
func getFileMtime(filepath string) (int64, bool) {
    info, err := os.Stat(filepath)
    if err != nil {
        return 0, false
    }
    return info.ModTime().Unix(), true
}
```

### 5.3 规则文件读取

```go
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
            return rules  // 文件存在（即使为空也返回）
        }
    }
    // 2. 回退全局目录
    globalPath := rc.ruleDir + "/" + filename
    rules, _ := rc.loadCached(globalPath)
    return rules
}

// loadCached 带缓存的文件读取
// 缓存策略：比较 mtime，mtime 未变则用缓存
func (rc *RuleCache) loadCached(filepath string) ([]RuleEntry, bool) {
    mtime, exists := getFileMtime(filepath)
    if !exists {
        return nil, false
    }

    rc.mu.RLock()
    entry, ok := rc.files[filepath]
    rc.mu.RUnlock()

    // 缓存命中
    if ok && entry.modTime == mtime {
        return entry.rules, true
    }

    // 缓存未命中，读取文件
    rc.mu.Lock()
    defer rc.mu.Unlock()

    // double check
    if entry, ok := rc.files[filepath]; ok && entry.modTime == mtime {
        return entry.rules, true
    }

    // 读取并解析 + 预编译
    content, err := os.ReadFile(filepath)
    if err != nil {
        return nil, false
    }

    rules := parseAndCompileRules(string(content))
    rc.files[filepath] = &ruleFileEntry{
        modTime: mtime,
        rules:   rules,
        exists:  true,
    }
    return rules, true
}

// parseAndCompileRules 按行解析规则文件，空行跳过
// 每条规则在加载阶段预编译为 *regexp.Regexp
// 编译失败的规则跳过并记录日志
func parseAndCompileRules(content string) []RuleEntry {
    var rules []RuleEntry
    for _, line := range strings.Split(content, "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        // 预编译正则
        re, err := regexp.Compile(line)
        if err != nil {
            // 正则编译失败，跳过此规则
            // TODO: 记录到错误日志
            continue
        }
        rules = append(rules, RuleEntry{
            Raw:   line,
            Regex: re,
        })
    }
    return rules
}
```

### 5.4 domain.json 缓存

```go
func (rc *RuleCache) GetDomainConfig(domain string) map[string]map[string]interface{} {
    path := rc.ruleDir + "/domain.json"
    mtime, exists := getFileMtime(path)
    if !exists {
        return nil
    }

    rc.mu.RLock()
    entry := rc.domainJSON
    rc.mu.RUnlock()

    if entry != nil && entry.modTime == mtime {
        return entry.config
    }

    // 重新加载
    rc.mu.Lock()
    defer rc.mu.Unlock()

    if entry != nil && entry.modTime == mtime {
        return entry.config
    }

    content, err := os.ReadFile(path)
    if err != nil {
        return nil
    }

    var configs map[string]map[string]interface{}
    if err := json.Unmarshal(content, &configs); err != nil {
        return nil
    }

    // 删除 _comment
    delete(configs, "_comment")

    rc.domainJSON = &domainConfigEntry{
        modTime: mtime,
        config:  configs,
        raw:     content,
    }
    return configs
}
```

---

## 6. 正则匹配

### 6.1 问题：PCRE vs RE2

Go 标准库 `regexp` 使用 RE2 引擎，不支持以下 PCRE 特性：

| PCRE 特性 | RE2 是否支持 | 现有规则是否使用 |
|-----------|:-----------:|:---------------:|
| `(?P<name>...)` 命名组 | ❌ | ❌ |
| 反向引用 `\1` | ❌ | ❌ |
| 零宽断言 `(?<=...)` `(?<!...)` | ❌ | ❌ |
| `(?:...)` 非捕获组 | ✅ | ✅ |
| `(a\|b)` 选择 | ✅ | ✅ |
| `.*?` 惰性匹配 | ✅ | ✅ |
| `\d` `\w` `\s` | ✅ | ✅ |

**结论**：现有规则文件全部兼容 RE2，可直接使用 Go 标准库 `regexp`。
如果后续需要 PCRE 完整兼容，可引入 `github.com/dlclark/regexp2`。

### 6.2 预编译匹配（零编译开销）

> **设计变更**：规则在加载阶段预编译为 `*regexp.Regexp`，
> 请求阶段直接调用 `re.MatchString()`，无 `sync.Map` 查找开销。

```go
// matchRules 将输入与预编译规则列表逐一匹配
// 返回命中的规则（用于日志记录）
func matchRules(input string, rules []RuleEntry, caseInsensitive bool) *RuleEntry {
    if input == "" || len(rules) == 0 {
        return nil
    }

    for i := range rules {
        re := rules[i].Regex
        if caseInsensitive {
            // 大小写不敏感：重新编译带 (?i) 前缀
            // 注意：预编译时已编译为大小写敏感
            // 此处通过 MatchString + strings.ToLower 优化
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

// matchRegex 单条正则匹配（用于 IP glob 等动态规则）
// 保留 sync.Map 缓存用于运行时动态编译的场景
var regexCache sync.Map  // key: pattern → value: *regexp.Regexp

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
```

### 6.3 Glob 转 Regex（IP 匹配用）

```go
// globToRegex 将 glob 通配符转为正则
// 192.168.0.* → ^192\.168\.0\.\d+$
// 192.168.*.1 → ^192\.168\.\d+\.1$
// 无 * 则原样返回
func globToRegex(pattern string) string {
    if !strings.Contains(pattern, "*") {
        return pattern  // 已是正则
    }
    // 转义特殊字符（除 *）
    regex := regexp.MustCompile(`([.+?[\](){}$^])`).ReplaceAllStringFunc(pattern, func(s string) string {
        return "\\" + s
    })
    // * → \d+
    regex = strings.ReplaceAll(regex, "*", `\d+`)
    return "^" + regex + "$"
}
```

---

## 7. 核心检测函数

### 7.1 检测链执行顺序

与 Lua 版 `waf_main()` 一致：

```go
func (g *Guard) runChecks(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    // 1. 白名单 IP → 放行
    if g.whiteIPCheck(r, cfg) { return false }
    // 2. 白名单 URL → 放行
    if g.whiteURLCheck(r, cfg) { return false }
    // 3. 动态黑名单（CC 自动拉黑）
    if g.dynamicBlackIPCheck(w, r, cfg) { return true }
    // 4. 静态黑名单 IP
    if g.blackIPCheck(w, r, cfg) { return true }
    // 5. User-Agent 检测（白名单 UA 仅跳过此项）
    if g.userAgentAttackCheck(w, r, cfg) { return true }
    // 6. Referer 检测
    if g.refererCheck(w, r, cfg) { return true }
    // 7. CC 攻击检测
    if g.ccAttackCheck(w, r, cfg) { return true }
    // 8. Cookie 检测
    if g.cookieAttackCheck(w, r, cfg) { return true }
    // 9. 文件上传检测
    if g.fileUploadCheck(w, r, cfg) { return true }
    // 10. URL 路径检测
    if g.urlAttackCheck(w, r, cfg) { return true }
    // 11. URL 参数检测
    if g.urlArgsAttackCheck(w, r, cfg) { return true }
    // 12. POST 检测
    if g.postAttackCheck(w, r, cfg) { return true }
    return false
}
```

### 7.2 IP 获取（对应 Lua get_client_ip）

```go
func (g *Guard) getClientIP(r *http.Request, cfg Config) string {
    if cfg.TrustProxyHeaders != "off" {
        // 1. CF-Connecting-IP
        if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
            return strings.TrimSpace(ip)
        }
        // 2. X-Real-IP
        if ip := r.Header.Get("X-Real-IP"); ip != "" {
            return strings.TrimSpace(ip)
        }
        // 3. X-Forwarded-For (取第一个)
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            if idx := strings.Index(xff, ","); idx > 0 {
                return strings.TrimSpace(xff[:idx])
            }
            return strings.TrimSpace(xff)
        }
    }
    // 4. RemoteAddr
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    if host != "" {
        return host
    }
    return "unknown"
}
```

### 7.3 白名单 IP 检测

```go
func (g *Guard) whiteIPCheck(r *http.Request, cfg Config) bool {
    if cfg.WhiteIPCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("whiteip.rule", cfg.RuleDir)
    clientIP := g.getClientIP(r, cfg)
    // IP 规则使用 glob 格式，运行时编译
    for _, rule := range rules {
        if matchRegex(clientIP, globToRegex(rule.Raw), false) {
            return true
        }
    }
    return false
}
```

### 7.4 黑名单 IP 检测

```go
func (g *Guard) blackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.BlackIPCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("blackip.rule", cfg.RuleDir)
    clientIP := g.getClientIP(r, cfg)
    for _, rule := range rules {
        if matchRegex(clientIP, globToRegex(rule.Raw), false) {
            g.logger.Record("BlackList_IP", r.URL.RequestURI(), "_", "_", clientIP, r, cfg)
            g.wafOutput(w, cfg)
            return true
        }
    }
    return false
}
```

### 7.5 白名单 URL 检测

```go
func (g *Guard) whiteURLCheck(r *http.Request, cfg Config) bool {
    if cfg.WhiteURLCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("whiteurl.rule", cfg.RuleDir)
    reqURI := r.URL.RequestURI()
    if hit := matchRules(reqURI, rules, false); hit != nil {
        return true
    }
    return false
}
```

### 7.6 白名单 UA 检测（仅跳过 UA 黑名单）

```go
func (g *Guard) isWhiteUA(r *http.Request, cfg Config) bool {
    if cfg.WhiteUACheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("whiteua.rule", cfg.RuleDir)
    ua := r.UserAgent()
    if ua == "" {
        return false
    }
    if hit := matchRules(ua, rules, true); hit != nil { // caseInsensitive=true
        return true
    }
    return false
}
```

### 7.7 UA 攻击检测

```go
func (g *Guard) userAgentAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.UserAgentCheck != "on" {
        return false
    }
    // 白名单 UA 仅跳过 UA 黑名单检测
    if g.isWhiteUA(r, cfg) {
        return false
    }
    rules := g.ruleCache.GetRule("useragent.rule", cfg.RuleDir)
    ua := r.UserAgent()
    if ua == "" {
        return false
    }
    if hit := matchRules(ua, rules, true); hit != nil {
        g.logger.Record("Deny_USER_AGENT", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

### 7.8 URL 路径攻击检测

```go
func (g *Guard) urlAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.URLCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("url.rule", cfg.RuleDir)
    if rules == nil {
        return false
    }
    reqURI := r.URL.RequestURI()
    if hit := matchRules(reqURI, rules, false); hit != nil {
        g.logger.Record("Deny_URL", reqURI, "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

### 7.9 URL 参数攻击检测

```go
func (g *Guard) urlArgsAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.URLArgsCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("args.rule", cfg.RuleDir)
    if rules == nil {
        return false
    }
    query := r.URL.Query()
    for key, vals := range query {
        val := strings.Join(vals, " ")
        decoded, err := url.QueryUnescape(val)
        if err != nil {
            decoded = val
        }
        if hit := matchRules(decoded, rules, false); hit != nil {
            g.logger.Record("Deny_URL_Args", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
            g.wafOutput(w, cfg)
            return true
        }
    }
    return false
}
```

### 7.10 POST 攻击检测（表单 + JSON body）

```go
func (g *Guard) postAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.PostCheck != "on" {
        return false
    }
    // 仅检查 POST/PUT/PATCH
    method := r.Method
    if method != "POST" && method != "PUT" && method != "PATCH" {
        return false
    }
    rules := g.ruleCache.GetRule("post.rule", cfg.RuleDir)
    if rules == nil {
        return false
    }

    // 限制 body 读取大小（防止内存耗尽攻击）
    r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024) // 10MB
    body, err := io.ReadAll(r.Body)
    if err != nil || len(body) == 0 {
        return false
    }
    // 恢复 body 供后续 handler 使用
    r.Body = io.NopCloser(bytes.NewReader(body))

    contentType := r.Header.Get("Content-Type")

    // 1. 表单解析
    if strings.Contains(contentType, "application/x-www-form-urlencoded") {
        form, err := url.ParseQuery(string(body))
        if err == nil {
            for key, vals := range form {
                val := strings.Join(vals, " ")
                if hit := matchRules(val, rules, false); hit != nil {
                    g.logger.Record("Deny_URL_POST", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
                    g.wafOutput(w, cfg)
                    return true
                }
            }
        }
    }

    // 2. Raw body 检测（JSON、XML 等）
    decoded, err := url.QueryUnescape(string(body))
    if err != nil {
        decoded = string(body)
    }
    if hit := matchRules(decoded, rules, false); hit != nil {
        g.logger.Record("Deny_URL_POST", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

> **注意**：POST body 读取后需要 `r.Body = io.NopCloser(bytes.NewReader(body))` 恢复。
> 使用 `http.MaxBytesReader` 限制读取大小，防止内存耗尽攻击。

### 7.11 Cookie 检测

```go
func (g *Guard) cookieAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.CookieCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("cookie.rule", cfg.RuleDir)
    cookie := r.Header.Get("Cookie")
    if cookie == "" || rules == nil {
        return false
    }
    if hit := matchRules(cookie, rules, false); hit != nil {
        g.logger.Record("Deny_Cookie", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

### 7.12 Referer 检测

```go
func (g *Guard) refererCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.RefererCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("referer.rule", cfg.RuleDir)
    referer := r.Header.Get("Referer")
    if referer == "" || rules == nil {
        return false
    }
    if hit := matchRules(referer, rules, false); hit != nil {
        g.logger.Record("Deny_Referer", r.URL.RequestURI(), "-", hit.Raw, g.getClientIP(r, cfg), r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

### 7.13 文件上传检测（multipart header 级别）

> **设计变更**：不完整读取 body，仅解析 multipart header 中的 filename，
> 对 filename 执行扩展名正则匹配。避免大文件耗内存。

```go
func (g *Guard) fileUploadCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.FileUploadCheck != "on" {
        return false
    }
    rules := g.ruleCache.GetRule("fileext.rule", cfg.RuleDir)
    if rules == nil {
        return false
    }
    contentType := r.Header.Get("Content-Type")
    if !strings.Contains(contentType, "multipart/form-data") {
        return false
    }

    // 使用 multipart.Reader 流式解析，只读 header 不读文件内容
    reader, err := r.MultipartReader()
    if err != nil {
        return false
    }

    for {
        part, err := reader.NextPart()
        if err == io.EOF {
            break
        }
        if err != nil {
            break
        }

        // 只检查 filename，不读取文件内容
        filename := part.FileName()
        if filename == "" {
            part.Close()
            continue
        }

        // 对 filename 进行规则匹配
        if hit := matchRules(filename, rules, false); hit != nil {
            part.Close()
            g.logger.Record("Deny_File_Upload", r.URL.RequestURI(), filename, hit.Raw, g.getClientIP(r, cfg), r, cfg)
            g.wafOutput(w, cfg)
            return true
        }

        // 不需要读取文件内容，直接关闭
        part.Close()
    }

    return false
}
```

> **优势**：
> - 不读取文件内容，内存占用恒定（仅 header 大小）
> - 1000 个 50MB 上传请求不会耗尽内存
> - 通过 filename 正则匹配扩展名（如 `\.php$`、`\.asp$`、`\.exe$`）

---

## 8. CC 限速 + 动态拉黑

### 8.1 存储抽象接口

> **设计变更**：CC 计数和 IP 封禁通过 interface 抽象，
> 单机使用 `MemoryStore`，多节点部署可切换 `RedisStore`。

```go
// CCStore 定义 CC 限速和 IP 封禁的存储接口
type CCStore interface {
    // CC 计数
    Incr(key string, ttl time.Duration) int
    CleanupCounters()

    // IP 封禁
    Ban(ip string, ttl time.Duration)
    IsBanned(ip string) bool
    CleanupBans()
}
```

### 8.2 内存存储实现（默认）

```go
type MemoryStore struct {
    mu       sync.Mutex
    counters map[string]*ccEntry  // key: IP + URI
    banMu    sync.RWMutex
    bans     map[string]time.Time // key: IP → value: 解封时间
}

type ccEntry struct {
    count    int
    expireAt time.Time
}

func NewMemoryStore() *MemoryStore {
    return &MemoryStore{
        counters: make(map[string]*ccEntry),
        bans:     make(map[string]time.Time),
    }
}

// Incr 原子递增 + 滑动窗口
func (m *MemoryStore) Incr(key string, ttl time.Duration) int {
    m.mu.Lock()
    defer m.mu.Unlock()

    now := time.Now()
    entry, ok := m.counters[key]

    if !ok || now.After(entry.expireAt) {
        // 新窗口
        m.counters[key] = &ccEntry{
            count:    1,
            expireAt: now.Add(ttl),
        }
        return 1
    }

    entry.count++
    entry.expireAt = now.Add(ttl) // 滑动窗口
    return entry.count
}

// Ban 封禁 IP
func (m *MemoryStore) Ban(ip string, ttl time.Duration) {
    m.banMu.Lock()
    defer m.banMu.Unlock()
    m.bans[ip] = time.Now().Add(ttl)
}

// IsBanned 检查 IP 是否在封禁中
func (m *MemoryStore) IsBanned(ip string) bool {
    m.banMu.RLock()
    defer m.banMu.RUnlock()
    expireAt, ok := m.bans[ip]
    if !ok {
        return false
    }
    if time.Now().After(expireAt) {
        return false // 已过期
    }
    return true
}

// CleanupCounters 清理过期计数器
func (m *MemoryStore) CleanupCounters() {
    m.mu.Lock()
    defer m.mu.Unlock()
    now := time.Now()
    for key, entry := range m.counters {
        if now.After(entry.expireAt) {
            delete(m.counters, key)
        }
    }
}

// CleanupBans 清理过期封禁
func (m *MemoryStore) CleanupBans() {
    m.banMu.Lock()
    defer m.banMu.Unlock()
    now := time.Now()
    for ip, expireAt := range m.bans {
        if now.After(expireAt) {
            delete(m.bans, ip)
        }
    }
}
```

### 8.3 Redis 存储实现（预留）

```go
// RedisStore 实现 CCStore 接口，用于多节点部署
// 使用 Redis INCR + EXPIRE 实现滑动窗口
// 使用 Redis SET + TTL 实现 IP 封禁
type RedisStore struct {
    client *redis.Client
}

func NewRedisStore(addr string) *RedisStore {
    return &RedisStore{
        client: redis.NewClient(&redis.Options{Addr: addr}),
    }
}

// TODO: 实现 CCStore 接口
```

### 8.4 CC 检测

```go
func (g *Guard) ccAttackCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.CCCheck != "on" {
        return false
    }

    // 解析 cc_rate: "60/60" → count=60, seconds=60
    parts := strings.Split(cfg.CCRate, "/")
    if len(parts) != 2 {
        return false
    }
    ccCount, _ := strconv.Atoi(parts[0])
    ccSeconds, _ := strconv.Atoi(parts[1])
    if ccCount == 0 || ccSeconds == 0 {
        return false
    }

    clientIP := g.getClientIP(r, cfg)
    uri := r.URL.Path
    token := clientIP + uri

    // 通过存储接口计数（内存或 Redis）
    count := g.ccStore.Incr(token, time.Duration(ccSeconds)*time.Second)

    if count > ccCount {
        g.logger.Record("CC_Attack", r.URL.RequestURI(), "-", "-", clientIP, r, cfg)

        // 自动拉黑
        if cfg.CCBlockTTL > 0 {
            if !g.ccStore.IsBanned(clientIP) {
                g.ccStore.Ban(clientIP, time.Duration(cfg.CCBlockTTL)*time.Second)
                g.logger.Record("CC_AutoBan", r.URL.RequestURI(), "_",
                    fmt.Sprintf("ban_%ds", cfg.CCBlockTTL), clientIP, r, cfg)
            }
        }

        g.wafOutput(w, cfg)
        return true
    }

    return false
}
```

### 8.5 动态黑名单

```go
// dynamicBlackIPCheck 检查是否被 CC 自动拉黑
func (g *Guard) dynamicBlackIPCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
    if cfg.CCBlockTTL <= 0 {
        return false
    }
    clientIP := g.getClientIP(r, cfg)
    if g.ccStore.IsBanned(clientIP) {
        g.logger.Record("Dynamic_Block_IP", r.URL.RequestURI(), "_", "_", clientIP, r, cfg)
        g.wafOutput(w, cfg)
        return true
    }
    return false
}
```

### 8.6 后台清理 goroutine

```go
// cleanupLoop 定期清理过期条目
func (g *Guard) cleanupLoop() {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            g.ccStore.CleanupCounters()
            g.ccStore.CleanupBans()
        case <-g.cleanupCtx.Done():
            return
        }
    }
}
```

---

## 9. 日志系统

### 9.1 日志结构

```go
type WAFLogger struct {
    logDir string
    queue  chan LogEntry  // 日志队列（有缓冲 channel）
    done   chan struct{}  // 关闭信号
}

type LogEntry struct {
    Timestamp    string `json:"@timestamp"`
    ClientIP     string `json:"client_ip"`
    LocalTime    string `json:"local_time"`
    ServerName   string `json:"server_name"`
    UserAgent    string `json:"user_agent"`
    AttackMethod string `json:"attack_method"`
    ReqURL       string `json:"req_url"`
    ReqData      string `json:"req_data"`
    RuleTag      string `json:"rule_tag"`
}
```

### 9.2 日志记录（channel + worker 模式）

> **设计变更**：不再每条日志启动一个 goroutine（高攻击下会导致 goroutine 爆炸）。
> 改为 channel + 单 worker goroutine 模式，类似生产 WAF 的异步日志管线。

```go
// NewWAFLogger 创建日志器并启动 worker goroutine
func NewWAFLogger(logDir string) *WAFLogger {
    l := &WAFLogger{
        logDir: logDir,
        queue:  make(chan LogEntry, 4096),  // 有缓冲队列，高峰期可暂存
        done:   make(chan struct{}),
    }
    go l.worker()
    return l
}

// Record 投递日志到队列（非阻塞）
func (l *WAFLogger) Record(method, reqURL, reqData, ruleTag, clientIP string, r *http.Request, cfg Config) {
    entry := LogEntry{
        Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
        ClientIP:     clientIP,
        LocalTime:    time.Now().Format("2006-01-02 15:04:05"),
        ServerName:   getDomain(r),
        UserAgent:    r.UserAgent(),
        AttackMethod: method,
        ReqURL:       reqURL,
        ReqData:      reqData,
        RuleTag:      ruleTag,
    }

    // 非阻塞投递：队列满时丢弃（保护服务不因日志阻塞）
    select {
    case l.queue <- entry:
    default:
        // 队列满，丢弃日志（可加计数器统计丢弃数量）
    }
}

// worker 单 goroutine 消费队列，串行写入文件
func (l *WAFLogger) worker() {
    for {
        select {
        case entry := <-l.queue:
            l.write(entry)
        case <-l.done:
            // 关闭前消费完队列中剩余日志
            for {
                select {
                case entry := <-l.queue:
                    l.write(entry)
                default:
                    return
                }
            }
        }
    }
}

// write 写入单条日志
func (l *WAFLogger) write(entry LogEntry) {
    logFile := fmt.Sprintf("%s/%s_waf.log", l.logDir, time.Now().Format("2006-01-02"))

    // 日志轮转：超过 100MB 则重命名
    if info, err := os.Stat(logFile); err == nil {
        if info.Size() > 100*1024*1024 {
            os.Rename(logFile, logFile+".old")
        }
    }

    // 追加写入
    f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    jsonBytes, _ := json.Marshal(entry)
    f.Write(jsonBytes)
    f.WriteString("\n")
}

// Close 关闭日志器（优雅退出）
func (l *WAFLogger) Close() {
    close(l.done)
}
```

> **优势**：
> - 无论多少攻击请求，始终只有 1 个 worker goroutine
> - channel 缓冲 4096 条，高峰期可暂存
> - 队列满时丢弃日志（保护服务不因日志阻塞），可加计数器统计丢弃数量

---

## 10. WAF 输出

```go
const defaultHTML = `<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>WAF防火墙</title></head>
<body style="font:14px/1.5 Microsoft Yahei,sans-serif;color:#555;">
<div style="margin:0 auto;width:600px;padding-top:70px;">
<div style="height:40px;line-height:40px;color:#fff;font-size:16px;background:#6bb3f6;padding-left:20px;">安全拦截</div>
<div style="border:1px dashed #cdcece;border-top:none;background:#f3f7f9;padding:20px;height:220px;">
<p><span style="font-weight:600;color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span></p>
<p>可能原因：您提交的内容包含危险的攻击请求</p>
</div>
</div>
</body>
</html>`

func (g *Guard) wafOutput(w http.ResponseWriter, cfg Config) {
    if cfg.WAFOutput == "redirect" {
        http.Redirect(w, nil, cfg.WAFRedirectURL, http.StatusMovedPermanently)
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(http.StatusForbidden)
    w.Write([]byte(defaultHTML))
}
```

---

## 11. 工具函数

```go
// getDomain 从请求中提取域名（去掉端口，转小写）
func getDomain(r *http.Request) string {
    host := r.Host
    if host == "" {
        host = r.URL.Host
    }
    if host == "" {
        return "default"
    }
    // 去掉端口
    if idx := strings.Index(host, ":"); idx > 0 {
        host = host[:idx]
    }
    return strings.ToLower(host)
}

// resolveRuleDir 解析规则目录路径
// 绝对路径原样返回，相对路径拼接 ruleDir
func resolveRuleDir(dir, baseRuleDir string) string {
    if dir == "" {
        return baseRuleDir
    }
    if strings.HasPrefix(dir, "/") {
        return dir  // 绝对路径
    }
    return baseRuleDir + "/" + dir  // 相对路径
}
```

---

## 12. Provision 生命周期

```go
func (g *Guard) Provision(ctx caddy.Context) error {
    // Caddyfile 中只配了 rule_dir，其余从 config.json 热加载
    if g.RuleDir == "" {
        g.RuleDir = "/etc/caddyguard/rule-config"
    }

    // 初始化运行时组件
    g.ruleCache = engine.NewRuleCache(g.RuleDir)

    // CC 存储使用内存实现（后续可切换 Redis）
    g.ccStore = storage.NewMemoryStore()

    // 从 config.json 读取全局配置初始化 logger
    cfg := g.ruleCache.GetGlobalConfig()
    g.logger = logger.NewWAFLogger(cfg.LogDir)

    // 启动后台清理 goroutine
    g.cleanupCtx, g.cleanupCancel = context.WithCancel(ctx.Context)
    go g.cleanupLoop()

    return nil
}

func (g *Guard) Cleanup() error {
    if g.cleanupCancel != nil {
        g.cleanupCancel()
    }
    if g.logger != nil {
        g.logger.Close()
    }
    return nil
}
```

---

## 13. 构建与安装

### 13.1 使用 xcaddy 构建（推荐）

```bash
# 安装 xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 构建带 caddyguard 的 Caddy
xcaddy build \
    --with github.com/qist/caddyguard \
    --output /usr/local/bin/caddy

# 验证
caddy list-modules | grep caddyguard
```

### 13.2 开发模式

```bash
cd /opt/caddyguard
go mod tidy
go build -o caddyguard.so -buildmode=plugin .
# 或直接用 xcaddy 本地构建
xcaddy build --with github.com/qist/caddyguard=. --output ./caddy
```

### 13.3 Caddyfile 示例

```caddyfile
# 全局配置（只写一次，所有站点自动生效）
{
    order caddyguard before reverse_proxy
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
}

# 站点无需安全配置
example.com {
    reverse_proxy 127.0.0.1:8080
}

foo.com {
    reverse_proxy 127.0.0.1:9090
}
```

> 安全开关、阈值等配置在 `{rule_dir}/config.json` 中管理，修改后自动热加载，无需 `caddy reload`。

---

## 14. 开发计划

| 阶段 | 模块 | 文件 | 预估代码量 | 预估耗时 |
|------|------|------|-----------|---------|
| 1 | 项目骨架 + go.mod | go.mod, .gitignore | 30 行 | 0.5h |
| 2 | Caddy 插件注册 + Handler 注入 | module.go, handler.go | 250 行 | 3h |
| 3 | 配置系统 + config.json 热加载 | config/config.go, config/domain.go | 200 行 | 2h |
| 4 | 规则加载 + 预编译 + 缓存 | engine/rules.go, engine/matcher.go, engine/cache.go | 300 行 | 3h |
| 5 | 检测函数（12 个） | detector/*.go | 450 行 | 4.5h |
| 6 | CC + 存储抽象 | detector/cc.go, storage/memory.go, storage/redis.go | 250 行 | 3h |
| 7 | 日志 worker | logger/logger.go | 120 行 | 1.5h |
| 8 | 工具函数 | utils/utils.go | 80 行 | 1h |
| 9 | 规则文件同步 | rule-config/* | — | 0.5h |
| 10 | README + 测试 | README.md | — | 2h |
| **合计** | | | **~1680 行** | **~21h** |

---

## 15. 与 Lua WAF 功能对照表

| 功能 | Lua WAF | CaddyGuard | 状态 |
|------|---------|------------|------|
| 安全总开关 | ✅ config.lua | ✅ config.json（热加载） | 待开发 |
| 域名级配置 | ✅ domain.json | ✅ domain.json（复用） | 待开发 |
| 通配符域名 | ✅ *.example.com | ✅ 后缀匹配 | 待开发 |
| 信任代理头 | ✅ trust_proxy_headers | ✅ 同名配置 | 待开发 |
| 规则文件热加载 | ✅ FFI stat mtime | ✅ os.Stat mtime | 待开发 |
| 规则预编译 | ❌ 运行时编译 | ✅ 加载阶段预编译 | 待开发 |
| 规则回退机制 | ✅ 域名→全局 | ✅ 同逻辑 | 待开发 |
| IP 白名单 | ✅ whiteip.rule | ✅ 同文件 | 待开发 |
| IP 黑名单 | ✅ blackip.rule | ✅ 同文件 | 待开发 |
| URL 白名单 | ✅ whiteurl.rule | ✅ 同文件 | 待开发 |
| UA 白名单 | ✅ whiteua.rule | ✅ 同文件 | 待开发 |
| URL 攻击检测 | ✅ url.rule | ✅ 同文件 | 待开发 |
| URL 参数检测 | ✅ args.rule | ✅ 同文件 | 待开发 |
| POST 检测 | ✅ post.rule | ✅ 同文件 + MaxBytesReader | 待开发 |
| UA 攻击检测 | ✅ useragent.rule | ✅ 同文件 | 待开发 |
| Cookie 检测 | ✅ cookie.rule | ✅ 同文件 | 待开发 |
| Referer 检测 | ✅ referer.rule | ✅ 同文件 | 待开发 |
| 文件上传检测 | ✅ fileext.rule（读 body） | ✅ 同文件（multipart header） | 待开发 |
| CC 限速 | ✅ 滑动窗口 | ✅ 滑动窗口 | 待开发 |
| CC 自动拉黑 | ✅ badGuys dict | ✅ CCStore（内存/Redis） | 待开发 |
| 分布式存储 | ❌ 单机 | ✅ RedisStore（预留） | 待开发 |
| JSON 日志 | ✅ async timer | ✅ channel + worker | 待开发 |
| 日志轮转 | ✅ 100MB rename | ✅ 同逻辑 | 待开发 |
| 拦截输出 | ✅ html/redirect | ✅ html/redirect | 待开发 |
| pcall 容错 | ✅ pcall | ✅ recover | 待开发 |
```
