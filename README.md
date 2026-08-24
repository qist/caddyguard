# CaddyGuard

Caddy v2 WAF (Web Application Firewall) 插件 — 用 Go 原生编写，为 Caddy 提供 enterprise 级 Web 安全防护。

## 特性

- **全局自动生效**：全局配置一次 `rule_dir`，所有站点自动启用 WAF，无需每个站点单独写 `caddyguard` 指令（通过 `caddyguardfile` 适配器实现）
- **12 项检测链**：白名单 IP/URL/UA、黑名单 IP、CC 攻击防护、URL 路径/参数检测（含 256+ 参数截断兜底）、User-Agent/Cookie/Referer 检测、POST body 检测（含大 body 超限拦截）、文件上传扩展名检测
- **IPv4/IPv6 双栈**：IP 黑白名单同时支持 IPv4 和 IPv6，支持 CIDR 表示法（`192.168.1.0/24`、`2001:db8::/32`）、glob 通配符（`192.168.*.*`、`2001:db8::*`）和精确匹配
- **高性能**：正则预编译（含 `(?i)` 大小写不敏感版本）+ POST body 关键词自动提取预过滤 + 64 分片 CC 存储 + Config 预合并缓存，WAF 全规则开启仅 ~1.7% 性能开销
- **热加载**：规则和配置文件修改后 2 秒内自动生效，无需重启 Caddy
- **域名级配置**：支持全局配置 + 按域名覆盖（精确匹配 + 通配符）+ 域名级独立规则目录 + 域名级扫描阈值覆盖
- **路径级配置**：支持基于 Caddy 原生 `path` matcher 的 WAF 开关，可对特定 URL 路径关闭 WAF（如 webhook、上传接口等）
- **Body 扫描控制**：`post_body_scan_limit` 超限直接拦截防部分扫描误放行；`multipart_streaming_check` 开关控制 multipart body 是否走流式扫描；`upload_filename_scan_limit` 控制文件名扫描范围
- **bodyless 方法控制**：`bodyless` 配置项控制 GET/HEAD/OPTIONS 是否跳过 body 检测，支持域名级覆盖（如对特定域名强制全方法扫描）
- **同步日志**：与 Lua 版一致，攻击日志同步落盘，不丢失。`sync.Mutex` 保护并发写入。日志字段自动截断到 4096 字节，防止单条日志过大
- **cc_rate 配置校验**：无效的 `cc_rate` 配置自动记录错误日志，避免 CC 防护静默失效
- **零 reflect/unsafe**：使用 Caddy 标准中间件链，不依赖私有字段反射
- **ReDoS 安全**：基于 Go RE2 正则引擎，无回溯爆炸风险

## 编译

### 前置要求

- Go 1.23+（go.mod 最低依赖 go 1.25.1，建议使用 Go 1.23+）
- [xcaddy](https://github.com/caddyserver/xcaddy) 构建工具
- Caddy v2.10.1+（go.mod 最低依赖 v2.10.1，兼容 v2.10.1 ~ v2.11.4）

```bash
# 安装 xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 方式 1：直接从 GitHub 仓库编译（推荐）
xcaddy build --with github.com/qist/caddyguard --output ./caddy

# 方式 2：本地开发编译
cd /opt/caddyguard
xcaddy build --with github.com/qist/caddyguard=. --output ./caddy

# 验证
./caddy version
./caddy list-modules | grep caddyguard
# 输出:
#   caddy.adapters.caddyguardfile   # 适配器（全局自动注入）
#   caddyguard                       # App 模块（全局配置存储）
#   http.handlers.caddyguard         # WAF handler
```

### 交叉编译

```bash
# Linux AMD64
CGO_ENABLED=0 xcaddy build --with github.com/qist/caddyguard --output ./caddy-linux-amd64
```

## 配置

CaddyGuard 提供三种配置方式：

### 方式 1：全局配置 + `caddyguardfile` 适配器（推荐）

全局配置一次 `rule_dir`，所有站点自动启用 WAF，**站点块不需要写 `caddyguard`**。
`caddyguardfile` 适配器在解析 Caddyfile 后自动向每个 HTTP server 注入 Guard handler。

```caddyfile
{
    auto_https off

    # 全局 WAF 配置 — 只写一次
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
}

# 站点不需要写 caddyguard，自动生效
example.com {
    reverse_proxy 127.0.0.1:8080
}

another.com {
    reverse_proxy 127.0.0.1:9090
}
```

启动时使用 `--adapter caddyguardfile`：

```bash
caddy run --config /etc/caddy/Caddyfile --adapter caddyguardfile
```

### 方式 2：站点级配置 + 标准 `caddyfile` 适配器

每个站点单独写 `caddyguard` 指令，适合需要精细控制的场景。

```caddyfile
{
    auto_https off
}

example.com {
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
    reverse_proxy 127.0.0.1:8080
}
```

启动时使用标准 `caddyfile` 适配器（默认）：

```bash
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
```

### 方式 3：JSON 配置（适合自动化部署 / Docker / K8s）

直接使用 Caddy 原生 JSON 配置，无需 adapter。WAF handler 需手动写在每个 route 的 `handle` 列表最前面。

```json
{
    "apps": {
        "caddyguard": {
            "rule_dir": "/etc/caddyguard/rule-config"
        },
        "http": {
            "servers": {
                "srv0": {
                    "automatic_https": { "disable": true },
                    "listen": [":80"],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "caddyguard"
                                },
                                {
                                    "handler": "reverse_proxy",
                                    "upstreams": [{ "dial": "127.0.0.1:8080" }]
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }
}
```

启动时**不需要** `--adapter` 参数（默认即为 JSON）：

```bash
caddy run --config /etc/caddy/caddy.json
```

**关键点**：
- `apps.caddyguard.rule_dir` 指定规则目录，与 Caddyfile 方式等效
- 每个 route 的 `handle` 列表中，`{"handler": "caddyguard"}` 必须写在其他 handler（如 `reverse_proxy`）**前面**，确保 WAF 检测在反代之前执行
- 路径级 WAF 开关：在特定 route 的 `handle` 中写 `{"handler": "caddyguard", "waf_enable": "off"}` 即可跳过该路径的 WAF
- WAF 检测开关（`url_check`、`post_check` 等）仍由 `rule_dir/config.json` 控制，与 Caddyfile 方式完全一致

### 三种方式对比

| | 方式 1：caddyguardfile | 方式 2：caddyfile | 方式 3：JSON |
|---|---|---|---|
| 全局配置 | ✅ 一次配置，所有站点自动生效 | ❌ 每个站点需单独写 | ❌ 每个 route 需手动写 |
| 站点块 | 只写业务指令 | 需写 `caddyguard` 指令 | 需写 `caddyguard` handler |
| 启动参数 | `--adapter caddyguardfile` | `--adapter caddyfile`（默认） | 不需要 adapter |
| 站点级覆盖 | 支持（站点写 `caddyguard { rule_dir ... }`） | 支持 | 支持（route 级 `waf_enable`） |
| 路径级开关 | ✅ Caddy 原生 path matcher | ✅ Caddy 原生 path matcher | ✅ route 级 `waf_enable: off` |
| 自动注入 | ✅ adapter 自动注入 handler | ❌ 需手动写 `caddyguard` 指令 | ❌ 需手动写 handler |
| 推荐场景 | 多站点统一 WAF | 单站点或精细控制 | 自动化部署 / Docker / K8s |

### 规则目录结构

```
/etc/caddyguard/rule-config/
├── config.json              # 全局 WAF 配置
├── domain.json              # 域名级配置覆盖
├── url.rule                 # URL 路径黑名单
├── args.rule                # URL 参数黑名单（SQL注入/XSS/SSTI/RCE等）
├── post.rule                # POST body 黑名单
├── cookie.rule              # Cookie 黑名单
├── useragent.rule           # 恶意 User-Agent 黑名单（扫描器/爬虫）
├── referer.rule             # 恶意 Referer 黑名单（支付接口保护）
├── whiteip.rule             # IP 白名单
├── whiteua.rule             # User-Agent 白名单（搜索引擎蜘蛛）
├── whiteurl.rule            # URL 白名单
├── blackip.rule             # IP 黑名单
├── cdnip.rule              # CDN/可信代理 IP 列表（控制 XFF 信任，支持 CIDR）
├── fileext.rule             # 文件上传扩展名黑名单
└── domains/                 # 域名级独立规则目录
    └── www.example.com/     # 该域名专用规则（13 个 .rule 文件）
        ├── url.rule
        ├── args.rule
        ├── post.rule
        ├── cookie.rule
        ├── useragent.rule
        ├── whiteua.rule
        ├── referer.rule
        ├── fileext.rule
        ├── whiteip.rule
        ├── whiteurl.rule
        ├── blackip.rule
        └── cdnip.rule
```

### config.json 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_enable` | string | `"on"` | WAF 总开关，`"off"` 完全关闭 |
| `trust_proxy_headers` | string | `"on"` | 是否信任代理转发的 IP 头（X-Forwarded-For 等）。`"on"`=CaddyGuard 在 CDN/反代后，根据 `cdnip.rule` 判断是否信任转发头：`remote_addr` 在 `cdnip.rule` 中才信任 XFF，不在则用 `remote_addr` 防伪造；`cdnip.rule` 不存在或为空则信任所有 XFF（原始方案，存在伪造风险）。`"off"`=CaddyGuard 直接暴露公网，只用 `remote_addr` 防伪造 |
| `log_dir` | string | `/var/log/caddyguard` | WAF 日志目录 |
| `url_check` | string | `"on"` | URL 路径检测开关 |
| `url_args_check` | string | `"on"` | URL 参数检测开关 |
| `post_check` | string | `"on"` | POST body 检测开关 |
| `user_agent_check` | string | `"on"` | User-Agent 检测开关 |
| `cookie_check` | string | `"on"` | Cookie 检测开关 |
| `cc_check` | string | `"on"` | CC 攻击防护开关 |
| `cc_rate` | string | `"60/60"` | CC 速率限制，格式 `请求数/时间窗口秒` |
| `cc_block_ttl` | int | `600` | CC 触发后封禁时长（秒） |
| `white_ip_check` | string | `"on"` | IP 白名单检测开关 |
| `white_ua_check` | string | `"on"` | UA 白名单检测开关 |
| `white_url_check` | string | `"on"` | URL 白名单检测开关。命中后**不再全局放行**，仅跳过指定检测项（默认跳过 URL 路径检测） |
| `black_ip_check` | string | `"on"` | IP 黑名单检测开关 |
| `referer_check` | string | `"off"` | Referer 检测开关 |
| `file_upload_check` | string | `"on"` | 文件上传扩展名检测开关 |
| `bodyless` | string | `"on"` | bodyless 方法跳过开关。`"on"`（默认）= GET/HEAD/OPTIONS 跳过 body/post/file_upload 检测（更低延迟）；`"off"` = 所有方法都扫描 body（更严格，延迟更高） |
| `multipart_streaming_check` | string | `"off"` | multipart body 流式内容扫描开关（`post.rule`）。默认 `off`，关闭时仍保留文件名扩展名检查 |
| `upload_filename_scan_limit` | int | `0` | multipart 文件名扫描上限（字节）。`0`=扫描整个文件；正整数=只扫描前 N 字节 |
| `post_body_scan_limit` | int | `2097152` | 非 multipart body 扫描上限（字节）。超过此值直接拦截，避免部分扫描后误放行 |
| `waf_output` | string | `"html"` | 拦截响应模式：`"html"` 返回拦截页面，`"redirect"` 302 跳转 |
| `waf_redirect_url` | string | - | `waf_output` 为 redirect 时的跳转 URL |

### domain.json 域名级覆盖

```json
{
    "www.example.com": {
        "url_check": "off",
        "cc_rate": "100/60",
        "rule_dir": "domains/www.example.com"
    },
    "api.example.com": {
        "waf_enable": "off"
    },
    "limit.example.com": {
        "_comment": "示例：域名级 body/file 扫描阈值覆盖",
        "multipart_streaming_check": "on",
        "post_body_scan_limit": 1048576,
        "upload_filename_scan_limit": 1024
    },
    "strict.example.com": {
        "_comment": "示例：对该域名强制扫描所有方法的 body（包括 GET/HEAD/OPTIONS）",
        "bodyless": "off"
    },
    "*.test.com": {
        "post_check": "off",
        "cookie_check": "off"
    }
}
```

- **精确域名**：`www.example.com` → O(1) map 查找
- **通配符域名**：`*.example.com` → 加载时预解析为列表，按后缀匹配
- **域名级规则目录**：`rule_dir` 指定域名专用规则目录，该域名请求使用独立规则文件覆盖全局规则

### path 级别 WAF 开关

推荐使用 Caddy 原生 `path` matcher 明确路径，再在对应的 `route` 中写
`caddyguard waf_enable off`。这样路径只维护一份，由 Caddy route 直接管理。

```caddyfile
sub.example.com {
    @webhook path /api/webhook/*
    route @webhook {
        caddyguard waf_enable off
        reverse_proxy 127.0.0.1:8080
    }
}
```

- **路径由 Caddy 管理**：支持 Caddy 原生 `path` matcher 的路径语义和通配符
- **route 局部生效**：只有命中该 path route 的请求会关闭 WAF
- **站点级开关**：在站点级 `caddyguard` 块中写 `waf_enable off` 可关闭整个站点的 WAF
- **自动注入逻辑**：使用 `caddyguardfile` 适配器时，含有站点或 route 级 `caddyguard` 的 route 不会重复注入全局 handler
- **典型场景**：webhook 回调接口、文件上传接口、健康检查接口等需要关闭 WAF 的路径

### 规则文件格式

所有 `.rule` 文件每行一条正则表达式（Go RE2 语法），`#` 开头为注释，空行忽略：

```
# url.rule — URL 路径黑名单（示例）
\/wp-login\.php
\/phpinfo\.php
\/\.env
\/\.git\/
(phpmyadmin|jmx-console|admin-console)

# args.rule — URL 参数黑名单（示例）
select.+(from|limit)
(?:(union(.*?)select))
sleep\((\s*)(\d*)(\s*)\)
\<(iframe|script|body|img|layer|div|meta|style|base|object|input)

# useragent.rule — 恶意 UA 黑名单
(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqlmap|w3af|owasp|Nikto)
(Acunetix|WebVulnScan|Paros|WebInspect|Burp|BurpSuite|WebScarab|Nuclei|httpx)
(Python-urllib|Python-requests|Go-http-client|scrapy|bot|crawl|spider|fetcher)

# fileext.rule — 文件上传扩展名黑名单
\.php\..*\.(htaccess|bash_history)
\.(htaccess|bash_history|htpasswd|gitignore|gitattributes|env|config|sql|bak|backup|old|tmp|log|swp|sql\.gz)

# referer.rule — 恶意 Referer 黑名单（支付接口保护）
\.pay\.
\.alipay\.
\.tenpay\.
\.paypal\.
\.stripe\.

# whiteua.rule — User-Agent 白名单（搜索引擎蜘蛛，仅跳过 UA 黑名单检测）
Googlebot
Baiduspider
bingbot
360Spider
YandexBot

# whiteurl.rule — URL 白名单（支持两种格式）
# 1. 纯路径格式（默认只跳过 url_attack URL路径检测，其他检测照常执行）：
/123/
/static/

# 2. 扩展格式（指定跳过的检测项，逗号分隔）：
/legacy/ user_agent,referer,url_attack,url_args
/api/old/ post,cookie

# 可用检测项：
#   user_agent   - User-Agent 检测
#   referer      - Referer 检测
#   url_attack   - URL 路径检测
#   url_args     - URL 参数检测
#   cookie       - Cookie 检测
#   post         - POST body 检测
#   file_upload  - 文件上传扩展名检测
#   cc           - CC 攻击限速检测
#
# 路径匹配方式：
#   - 纯路径规则（不含正则元字符）：前缀匹配，如 /static/ 匹配 /static/css/app.css
#   - 正则规则（含正则元字符如 ^ $）：正则匹配，如 ^/api$ 精确匹配 /api
#
# 安全建议：
#   - 精确匹配路径用 $ 锚定结尾，如 /ipinfo$ 只匹配 /ipinfo，不匹配 /ipinfo-delete
#   - 匹配子路径用末尾 /，如 /static/ 只匹配 /static/xxx，不匹配 /staticxxx
#   - 避免使用不含 / 结尾的纯路径规则，如 /ipinfo 会误匹配 /ipinfoadmin
```

### IP 规则文件格式

`whiteip.rule`、`blackip.rule` 和 `cdnip.rule` 每行一条 IP 规则，支持三种格式：

```
# 1. CIDR 表示法（推荐，IPv4/IPv6 均支持）
192.168.1.0/24          # IPv4 CIDR
2001:db8::/32           # IPv6 CIDR
10.0.0.0/8              # IPv4 大范围
::1/128                 # IPv6 loopback

# 2. glob 通配符
192.168.1.*             # IPv4 通配符
2001:db8::*             # IPv6 通配符
192.168.*.*             # 多段通配符

# 3. 精确匹配
8.8.8.8                 # IPv4 精确
2001:db8::5             # IPv6 精确
::1                     # IPv6 loopback
```

### CDN 代理 IP 信任（cdnip.rule）

当 CaddyGuard 部署在 CDN/反向代理后面时，需要从 `X-Forwarded-For` 获取真实客户端 IP。但直接信任 XFF 会让攻击者伪造该头绕过 IP 黑白名单。

解决方案：在 `config.json` 中设置 `trust_proxy_headers = "on"`，并在 `cdnip.rule` 中配置你实际使用的 CDN/代理 IP 段：

```json
// config.json
{
    "trust_proxy_headers": "on"
}
```

```bash
# cdnip.rule
# 填入你实际使用的 CDN/代理 IP 段，以下为示例（请按需替换）
# 各家 CDN IP 列表查询地址：
#   Cloudflare:    https://www.cloudflare.com/ips/
#   AWS CloudFront: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
#   Akamai:        https://developer.akamai.com/cli/apps/akamai-cli-list-ip
#   阿里云 CDN:    https://help.aliyun.com/document_detail/27134.html
#   腾讯云 CDN:    https://cloud.tencent.com/document/product/228/52935

# Cloudflare IPv4（示例）
173.245.48.0/20
104.16.0.0/13
# Cloudflare IPv6（示例）
2400:cb00::/32
2606:4700::/32
# 内部代理/负载均衡器
10.0.0.0/8
192.168.0.0/16
```

此时 CaddyGuard 的行为：

| 条件 | XFF 处理 | 说明 |
|------|---------|------|
| `remote_addr` 在 cdnip.rule 中 | 信任 XFF | 提取真实客户端 IP |
| `remote_addr` 不在 cdnip.rule 中 | 不信任 XFF | 使用 `remote_addr`（防直连伪造） |
| `cdnip.rule` 文件不存在 | 信任所有 XFF | 原始行为，向后兼容 |
| `cdnip.rule` 文件为空（或全注释） | 信任所有 XFF | 等同于文件不存在，回落原始行为 |

支持域名级覆盖：

```json
{
    "www.example.com": {
        "trust_proxy_headers": "on"
    },
    "direct.example.com": {
        "trust_proxy_headers": "off"
    }
}
```

### 三种白名单的区别

| 白名单 | 文件 | 行为 | 说明 |
|--------|------|------|------|
| **白名单 IP** | `whiteip.rule` | **全局放行**，跳过全部 12 项检测 | 信任 IP，完全不做任何安全检测 |
| **白名单 URL** | `whiteurl.rule` | **仅跳过指定检测项**（默认只跳过 URL 路径检测），其他检测照常 | 可配置跳过哪些检测项，避免全局放行的安全风险 |
| **白名单 UA** | `whiteua.rule` | **仅跳过 UA 黑名单检测**，其他检测照常 | 搜索引擎蜘蛛免被 UA 黑名单误杀，但仍受 URL/参数/POST 等检测约束 |

## 检测链

按检测成本从低到高排序，命中即返回：

| 顺序 | 检测项 | 来源 | 说明 |
|------|--------|------|------|
| 1 | 白名单 IP | `whiteip.rule` | 命中则**放行**，跳过所有后续检测 |
| 2 | 动态黑名单 IP | CC 自动拉黑 | CC 触发后自动封禁的 IP |
| 3 | 静态黑名单 IP | `blackip.rule` | 手动配置的 IP 黑名单 |
| 4 | 白名单 URL | `whiteurl.rule` | 返回跳过的检测项集合，**不再全局放行**；纯路径默认只跳过 URL 路径检测，扩展格式可指定跳过哪些检测项 |
| 5 | User-Agent | `useragent.rule` | 恶意扫描器/工具 UA（白名单 UA 仅跳过此项；白名单 URL 可指定跳过） |
| 6 | Referer | `referer.rule` | 恶意来源、支付接口保护（白名单 URL 可指定跳过） |
| 7 | CC 攻击 | 实时计数 | 64 分片滑动窗口计数（白名单 URL 可指定跳过） |
| 8 | [非 bodyless] 文件上传 | `fileext.rule` | 需解析 multipart，最昂贵；Content-Type 大小写不敏感匹配（白名单 URL 可指定跳过） |
| 9 | URL 路径 | `url.rule` | 路径遍历、敏感文件、管理后台等（纯路径白名单默认跳过此项） |
| 10 | URL 参数 | `args.rule` | SQL 注入、XSS、SSTI、RCE 等（白名单 URL 可指定跳过） |
| 11 | Cookie | `cookie.rule` | Cookie 注入（白名单 URL 可指定跳过） |
| 12 | [非 bodyless] POST body | `post.rule` | 需读取 body；关键词自动提取预过滤跳过正常请求；multipart 默认跳过（由 `multipart_streaming_check` 控制）；空规则不读取 body（白名单 URL 可指定跳过） |

## 热加载

CaddyGuard 支持规则和配置的热加载：

- **触发方式**：修改 `rule-config/` 目录下的任何 `.rule` 或 `.json` 文件
- **生效时间**：2 秒内（基于 mtime 检查 + 节流）
- **零停机**：加载期间请求不受影响（使用 RWMutex + double-check）
- **无需 reload Caddy**：完全在进程内完成

## CC 防护机制

- **64 分片**：基于 FNV-1a hash 对 `IP+URI` 分片，消除全局锁竞争
- **8 桶滑动窗口**：真正的滑动窗口语义（非 TTL 重置）
- **内存上限**：CC 计数器最大 100 万 key，超过后过期淘汰
- **自动封禁**：超过 `cc_rate` 阈值后自动拉黑 IP，持续 `cc_block_ttl` 秒
- **自动清理**：后台每 60 秒清理过期计数器和过期封禁

## 日志

- **同步写入**：与 Lua 版一致，攻击日志在返回 403 前已落盘，不丢失
- **并发安全**：`sync.Mutex` 保护多 goroutine 并发写入（Go 与 Lua 的唯一差异：Lua 靠 OpenResty 单 worker 天然串行）
- **JSON 格式**：每行一条 JSON，包含时间戳、客户端 IP、攻击类型、命中规则、请求 URL 等
- **日志文件**：`{log_dir}/{YYYY-MM-DD}_waf.log`
- **自动轮转**：单文件超过 100MB 时重命名为 `.old`，按天分文件，轮转检查每 60 秒一次

### 日志字段

```json
{
    "@timestamp": "2026-08-13T04:30:00Z",
    "client_ip": "192.168.2.50",
    "local_time": "2026-08-13 12:30:00",
    "server_name": "www.example.com",
    "user_agent": "sqlmap/1.0",
    "attack_method": "UserAgent",
    "req_url": "/?id=1+union+select",
    "req_data": "",
    "rule_tag": "(sqlmap|nmap|...)"
}
```

| 字段 | 说明 |
|------|------|
| `@timestamp` | UTC 时间戳 |
| `client_ip` | 客户端 IP |
| `local_time` | 本地时间 |
| `server_name` | 域名 |
| `user_agent` | 请求 UA |
| `attack_method` | 命中的检测项（UserAgent / URL / URLArgs / Cookie / Referer / POST / FileUpload） |
| `req_url` | 请求 URL |
| `req_data` | POST body 数据（仅 POST 检测时） |
| `rule_tag` | 命中的具体规则内容 |

## 性能测试结果

### 环境信息

- **测试机**：物理机（4 核 CPU），192.168.2.180
- **发包机**：Apache Bench (ab)，本机回环
- **参数**：50000 请求，200 并发，Keep-Alive
- **日期**：2026-08-19（优化后）

### 压测对比

| 场景 | req/s | P99 | 开销 | 说明 |
|------|-------|-----|------|------|
| Caddy + reverse_proxy（无 WAF） | 6,329 | 73ms | 基准 | 无 WAF 的 Caddy 反向代理 |
| CaddyGuard 规则全关 | 6,405 | 70ms | ~0% | WAF 开启但所有规则关闭 |
| CaddyGuard 规则全开（不含 CC） | 6,223 | 73ms | ~1.7% | 12 项检测全开 + 关键词预过滤 + 匹配缓存 |
| CaddyGuard 攻击 UA 拦截 | 11,027 | 21ms | — | UA 命中直接 403，不走后端 |
| CaddyGuard + POST body | 5,363 | 86ms | ~15% | POST body 读取 + Content-Type 分流 + 关键词预过滤 |
| 路径级 WAF off（webhook） | 10,765 | 22ms | — | waf_enable off 路径直返 |
| 路径级 WAF on（同配置） | 10,739 | 23ms | — | 同配置 WAF on 路径对比 |

> WAF 全开吞吐下降仅 1.7%（6,223 vs 6,329）。相比优化前（11.4%），性能损耗大幅缩减。

### 单项检测性能对比

| 检测项 | req/s | P99 | vs 基准 | 说明 |
|--------|-------|-----|---------|------|
| 无 WAF 基准 | 6,329 | 73ms | — | Caddy + reverse_proxy |
| 仅 URL 检测 | 6,332 | 70ms | -0.04% | URL 路径 regex |
| URL + 参数检测 | 6,400 | 67ms | +1.1% | URL + 参数 regex |
| 仅 UA 检测 | 6,408 | 71ms | +1.2% | Bloom-filter 预检 + 空规则短路 |
| 仅 Cookie 检测 | 6,450 | 69ms | +1.9% | Header 读取 + 空规则短路 |
| 仅 IP 黑白名单 | 6,238 | 72ms | -1.4% | CIDR/glob/精确匹配 |
| 仅 POST body | 5,536 | 78ms | -12.5% | body I/O + Content-Type 分流 + 关键词预过滤 |
| 仅白名单 | 6,222 | 70ms | -1.7% | IP/URL/UA 白名单 |

> POST body 检测使用自动关键词预过滤：加载阶段从每条正则规则中自动提取字面量关键词，请求阶段先做 bytes.Contains 检查（SIMD 优化），不包含任何关键词的 body 直接跳过全部正则。form-urlencoded 请求通过 ParseQuery 解析 key/value 后跳过 raw body 二次扫描。剩余开销来自 Caddy 框架的 body I/O（读取 + 恢复 + reverse_proxy 二次读取），非 WAF 逻辑本身。

### 并发梯度测试（WAF 全开，不含 CC）

| 并发 | req/s | P99 | 说明 |
|-------|-------|-----|------|
| c=10 | 6,085 | 5ms | 低并发延迟极低 |
| c=50 | 6,555 | 18ms | |
| c=100 | 6,343 | 35ms | |
| c=200 | 6,275 | 72ms | 标准压测并发 |
| c=500 | 5,507 | 172ms | 高并发开始排队 |

### CC 防护测试

| 场景 | req/s | Fail | 说明 |
|------|-------|------|------|
| 100 请求 / c=10 | 6,229 | 0 | 不触发 CC，全部放行 |
| 50000 请求 / c=200 | 10,702 | 49,951 | 150/60s 触发封禁，后续全部 403 |

### 性能优化措施

| 优化项 | 说明 |
|--------|------|
| 规则双引擎 | 纯字符串规则用 strings.Contains（快 10x），正则规则用预编译 *regexp.Regexp |
| 关键词预过滤 | 加载阶段从正则提取字面量关键词，请求阶段 bytes.Contains 预检跳过不匹配的正则 |
| worker 级匹配缓存 | 小输入（≤512字节）按规则集+input 做全局缓存，重复请求直接复用结果（上限 4096 条） |
| POST Content-Type 分流 | form-urlencoded 走 ParseQuery 解析 key/value 后跳过 raw body 二次扫描；JSON/XML 直接走 raw body |
| 空规则提前返回 | 各检测函数获取规则后立即判断空规则，避免无意义的 header/body 读取 |
| UA bloom-filter 预检 | 7 个 bot 标记词预过滤，99% 正常流量跳过白名单遍历 |
| URL 参数短路 | 无查询参数时直接返回，跳过 pairs 循环和正则匹配 |
| 最小输入长度检查 | 输入 < 2 字符直接跳过规则匹配 |
| 白名单 URL 路径优先 | 先匹配 URI path（常见场景），再匹配完整 request_uri（兼容含 query 的白名单） |
| 请求类型短路 | `bodyless="on"`（默认）时 GET/HEAD/OPTIONS 跳过 POST 和文件上传检测；`bodyless="off"` 时所有方法都扫描 body；POST/PUT/PATCH/DELETE 始终走 body 检测 |
| Cookie 检测后移 | Cookie 检测移到 URL/Args 之后，攻击请求在 URL 阶段即短路返回 |
| IP 预编译缓存 | CIDR 排序 + 二分搜索 + 精确 IP hash 查找 |
| 配置预合并 | 域名级配置在加载阶段预合并，请求阶段 O(1) 查找 |
| 请求上下文缓存 | clientIP 和 URI 在 context 中缓存，同请求内不重复计算 |

### 优化前后对比

| 场景 | 优化前 req/s | 优化后 req/s | 提升 |
|------|------------|------------|------|
| WAF 全开（不含 CC） | 5,713 | 6,223 | **+8.9%** |
| WAF + POST body | 4,991 | 5,363 | **+7.4%** |
| 仅 UA 检测 | 5,881 | 6,408 | **+9.0%** |
| WAF 全开 vs 无 WAF 开销 | ~11% | ~1.7% | **降低 85%** |

### Go Benchmark 微基准

| 组件 | 性能 | 说明 |
|------|------|------|
| CC Incr (64 分片并行) | 67 ns/op | 无锁竞争 |
| CC IsBanned (并行) | 25 ns/op | 分片读锁 |
| matchRules (大小写不敏感) | 2.2 ns/op | ToLower 只做一次 + worker 缓存 |
| GetEffectiveConfig | 1,474 ns/op | 预合并缓存 O(1) |
| runChecks (正常请求) | 6,431 ns/op | 12 项检测全通过 |

## 稳定性测试结果

| 测试项 | 结果 | 说明 |
|--------|------|------|
| 持续压测 10 分钟 | ✅ | 内存零增长，进程存活 |
| 100 万随机 URL CC 攻击 | ✅ | 内存仅增长 5MB，cleanup 后回收 |
| 1MB POST body | ✅ | 正常处理 (HTTP 200) |
| 10MB POST body | ✅ | 未崩溃 |
| 32MB+ multipart 文件 | ✅ | 未崩溃 |
| .txt 文件上传 | ✅ | 正常放行 |
| .sql 文件上传 | ✅ | 正确拦截 (403) |
| .htaccess 文件上传 | ✅ | 正确拦截 (403) |
| 热加载规则一致性 | ✅ | 配置变更 5s 内生效，服务不中断 |
| Caddy restart | ✅ | 重启后规则正确加载 |
| ReDoS 恶意正则 | ✅ | Go RE2 无回溯，未崩溃 |
| 超长 URL (100KB) | ✅ | 未崩溃 |
| 超长 Header (50KB) | ✅ | 未崩溃 |
| 畸形 HTTP 请求 | ✅ | 未崩溃 |
| 二进制垃圾数据 | ✅ | 未崩溃 |
| 1000 个 Cookie | ✅ | 未崩溃 |
| 44 种攻击拦截 | ✅ | 全部正确拦截 (403)，含 URL/Args/UA/Cookie/POST 各类攻击 |
| IPv4 黑名单 CIDR 拦截 | ✅ | 192.168.1.0/24 正确拦截 (403) |
| IPv6 黑名单 CIDR 拦截 | ✅ | 2001:db8::/32 正确拦截 (403) |
| IPv4 白名单放行 | ✅ | 8.8.8.8 跳过所有检测 (200) |
| IPv6 白名单放行 | ✅ | ::1 / 2001:db8::5 跳过所有检测 (200) |
| bodyless=on/off 切换 | ✅ | on: GET/HEAD/OPTIONS 跳过 body 检测；off: 全方法扫描 |
| bodyless 域名级覆盖 | ✅ | strict.example.com 覆盖为 off，强制扫描所有方法 |
| 日志字段截断保护 | ✅ | 10000 字节攻击 URL 截断到 4110 字节 (4096+...[truncated]) |
| cc_rate 无效配置 | ✅ | CC 检测自动禁用 + 错误日志记录，避免静默 fail-open |
| 回归测试 156 项 | ✅ | 156/156 全部通过，0 失败 |

### 攻击拦截测试详情

| 攻击类型 | 期望 | 实际 | 说明 |
|----------|------|------|------|
| SQL 注入 union select | 403 | ✅ 403 | URL 参数检测 |
| SQL 注入 or 1=1 | 403 | ✅ 403 | URL 参数检测 |
| XSS `<script>alert(1)` | 403 | ✅ 403 | URL 参数检测 |
| XSS `<img onerror=alert(1)>` | 403 | ✅ 403 | URL 参数检测 |
| 路径遍历 `../etc/passwd` | 403 | ✅ 403 | URL 路径检测 |
| wp-login.php | 403 | ✅ 403 | URL 路径检测 |
| phpinfo.php | 403 | ✅ 403 | URL 路径检测 |
| actuator/env | 403 | ✅ 403 | URL 路径检测 |
| sqlmap UA | 403 | ✅ 403 | UA 黑名单检测 |
| nmap UA | 403 | ✅ 403 | UA 黑名单检测 |
| dirb UA | 403 | ✅ 403 | UA 黑名单检测 |
| Cookie 注入 | 403 | ✅ 403 | Cookie 检测 |
| POST SQL 注入 | 403 | ✅ 403 | POST body 检测 |
| POST XSS | 403 | ✅ 403 | POST body 检测 |
| POST 路径遍历 | 403 | ✅ 403 | POST body 检测 |
| POST base64_decode | 403 | ✅ 403 | POST body 检测 |
| POST `$_GET` 注入 | 403 | ✅ 403 | POST body 检测 |
| POST SSTI `{{__class__}}` | 403 | ✅ 403 | POST body 检测 |
| POST `CONCAT()` | 403 | ✅ 403 | POST body 检测（大小写不敏感） |
| POST `concat()` 小写 | 403 | ✅ 403 | POST body 检测（大小写不敏感） |
| POST NoSQL `$eq()` | 403 | ✅ 403 | POST body 检测 |
| 正常 POST（不命中） | 200 | ✅ 200 | 关键词预过滤跳过正则 |
| .txt 文件上传 | 非403 | ✅ 200 | 正常文件放行 |
| .sql 文件上传 | 403 | ✅ 403 | 文件扩展名检测 |
| .htaccess 文件上传 | 403 | ✅ 403 | 文件扩展名检测 |
| bodyless=on GET 跳过 body | 200 | ✅ 200 | GET 无 body 检测开销 |
| bodyless=off 全方法扫描 | 403 | ✅ 403 | POST 攻击仍被拦截 |
| 日志截断 10KB URL | 403 | ✅ 403 | req_url 截断到 4110 字节 |
| cc_rate 无效配置 | 200 | ✅ 200 | CC 禁用 + 错误日志记录 |

## 部署

### 系统服务

```bash
# 复制二进制
cp caddy /usr/local/bin/

# 创建配置目录
mkdir -p /etc/caddyguard/rule-config
cp -r rule-config/* /etc/caddyguard/rule-config/

# systemd 服务（使用 caddyguardfile 适配器，全局自动生效）
cat > /etc/systemd/system/caddy.service << 'EOF'
[Unit]
Description=Caddy with CaddyGuard WAF
After=network.target

[Service]
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyguardfile
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now caddy
```

### Docker

```dockerfile
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/qist/caddyguard

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY rule-config /etc/caddyguard/rule-config
COPY Caddyfile /etc/caddy/Caddyfile
```

## 开发

### 运行测试

```bash
# 单元测试
go test -v ./...

# 基准测试
go test -bench=. -benchmem -count=1

# 稳定性测试
bash test-config/stability_test.sh

# 压测+监控
bash test-config/bench_monitor.sh
```

### 项目结构

```
caddyguard/
├── module.go              # Caddy 模块注册 + Caddyfile 解析 + ServeHTTP
├── handler.go             # 检测链编排 + WAF 响应输出
├── config.go              # Config 结构体定义
├── domain.go              # 域名级配置查找（预合并缓存）
├── rules.go               # 规则缓存 + 热加载 + 配置预合并 + 关键词自动提取
├── adapter.go             # caddyguardfile 适配器（全局自动注入 Guard handler）
├── matcher.go             # 正则匹配引擎（预编译 + (?i) 大小写不敏感 + []byte 直接匹配 + 关键词预过滤）
├── storage.go             # CC 存储（64 分片 + 滑动窗口 + 内存上限）
├── logger.go              # 同步日志（sync.Mutex + 文件句柄复用 + 100MB 轮转）
├── request_context.go     # 请求上下文缓存（clientIP, URI）
├── utils.go               # 辅助工具函数
├── detector_ip.go         # IP 黑白名单检测（IPv4/IPv6 CIDR + glob + 精确匹配）
├── detector_url.go        # URL 路径 + URL 参数检测
├── detector_ua.go         # User-Agent 检测（黑名单 + 白名单）
├── detector_cookie.go     # Cookie 注入检测
├── detector_post.go       # POST body 检测（Content-Type 分流 + 大 body 超限拦截 + multipart_streaming_check 开关 + 关键词预过滤）
├── detector_cc.go         # CC 攻击检测（64 分片滑动窗口）
├── detector_referer.go    # Referer 检测
├── detector_fileupload.go # 文件上传扩展名检测
├── module_test.go         # 适配器单元测试
├── ip_test.go             # IP 匹配单元测试（IPv4/IPv6 CIDR/glob/精确）
├── servehttp_test.go      # ServeHTTP 集成测试
├── keyword_test.go        # 关键词提取与预过滤单元测试
├── bench_test.go          # Go benchmark 测试
├── rule-config/           # 规则配置文件
│   ├── config.json        # 全局 WAF 配置
│   ├── domain.json        # 域名级配置覆盖
│   ├── *.rule             # 规则文件（url/args/post/cookie/ua/referer/fileext/white*）
│   └── domains/           # 域名级独立规则目录
└── test-config/           # 测试用 Caddyfile + 压测脚本
```
