# CaddyGuard

Caddy v2 WAF (Web Application Firewall) 插件 — 用 Go 原生编写，为 Caddy 提供 enterprise 级 Web 安全防护。

## 特性

- **12 项检测链**：白名单 IP/URL/UA、黑名单 IP、CC 攻击防护、URL 路径/参数检测、User-Agent/Cookie/Referer 检测、POST body 检测、文件上传扩展名检测
- **高性能**：正则预编译 + 64 分片 CC 存储 + Config 预合并缓存，WAF 开启仅 ~7% 性能开销
- **热加载**：规则和配置文件修改后 2 秒内自动生效，无需重启 Caddy
- **域名级配置**：支持全局配置 + 按域名覆盖（精确匹配 + 通配符）+ 域名级独立规则目录
- **零 reflect/unsafe**：使用 Caddy 标准中间件链，不依赖私有字段反射
- **ReDoS 安全**：基于 Go RE2 正则引擎，无回溯爆炸风险

## 编译

### 前置要求

- Go 1.21+
- [xcaddy](https://github.com/caddyserver/xcaddy) 构建工具

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
#   http.handlers.caddyguard
```

### 交叉编译

```bash
# Linux AMD64
CGO_ENABLED=0 xcaddy build --with github.com/qist/caddyguard --output ./caddy-linux-amd64
```

## 配置

### Caddyfile 全局配置

```caddyfile
{
    auto_https off

    # 全局 WAF 配置
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
}

example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Caddyfile 站点级配置

```caddyfile
{
    auto_https off
    order caddyguard before reverse_proxy
}

example.com {
    caddyguard {
        rule_dir /etc/caddyguard/rule-config
    }
    reverse_proxy 127.0.0.1:8080
}
```

### 规则目录结构

```
/etc/caddyguard/rule-config/
├── config.json              # 全局 WAF 配置
├── domain.json              # 域名级配置覆盖
├── url.rule                 # URL 路径黑名单（92 条规则）
├── args.rule                # URL 参数黑名单（95 条规则，SQL注入/XSS/SSTI/RCE等）
├── post.rule                # POST body 黑名单（96 条规则）
├── cookie.rule              # Cookie 黑名单（96 条规则）
├── useragent.rule           # 恶意 User-Agent 黑名单（5 条规则，扫描器/爬虫）
├── referer.rule             # 恶意 Referer 黑名单（8 条规则，支付接口保护）
├── whiteip.rule             # IP 白名单（1 条）
├── whiteua.rule             # User-Agent 白名单（44 条，搜索引擎蜘蛛）
├── whiteurl.rule            # URL 白名单（1 条）
├── blackip.rule             # IP 黑名单（0 条，空文件）
├── fileext.rule             # 文件上传扩展名黑名单（2 条规则）
└── domains/                 # 域名级独立规则目录
    └── www.example.com/     # 该域名专用规则（8 个 .rule 文件）
        ├── url.rule
        ├── args.rule
        ├── post.rule
        ├── cookie.rule
        ├── useragent.rule
        ├── whiteip.rule
        ├── whiteurl.rule
        └── blackip.rule
```

### config.json 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_enable` | string | `"on"` | WAF 总开关，`"off"` 完全关闭 |
| `trust_proxy_headers` | string | `"on"` | 信任 X-Forwarded-For 头获取客户端 IP |
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
| `white_url_check` | string | `"on"` | URL 白名单检测开关 |
| `black_ip_check` | string | `"on"` | IP 黑名单检测开关 |
| `referer_check` | string | `"off"` | Referer 检测开关 |
| `file_upload_check` | string | `"on"` | 文件上传扩展名检测开关 |
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
    "*.test.com": {
        "post_check": "off",
        "cookie_check": "off"
    }
}
```

- **精确域名**：`www.example.com` → O(1) map 查找
- **通配符域名**：`*.example.com` → 加载时预解析为列表，按后缀匹配
- **域名级规则目录**：`rule_dir` 指定域名专用规则目录，该域名请求使用独立规则文件覆盖全局规则

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
```

### 三种白名单的区别

| 白名单 | 文件 | 行为 | 说明 |
|--------|------|------|------|
| **白名单 IP** | `whiteip.rule` | **全局放行**，跳过全部 12 项检测 | 信任 IP，完全不做任何安全检测 |
| **白名单 URL** | `whiteurl.rule` | **全局放行**，跳过全部 12 项检测 | 信任 URL 路径，完全不做任何安全检测 |
| **白名单 UA** | `whiteua.rule` | **仅跳过 UA 黑名单检测**，其他检测照常 | 搜索引擎蜘蛛免被 UA 黑名单误杀，但仍受 URL/参数/POST 等检测约束 |

## 检测链

按检测成本从低到高排序，命中即返回：

| 顺序 | 检测项 | 来源 | 说明 |
|------|--------|------|------|
| 1 | 白名单 IP | `whiteip.rule` | 命中则**放行**，跳过所有后续检测 |
| 2 | 白名单 URL | `whiteurl.rule` | 命中则**放行**，跳过所有后续检测 |
| 3 | 动态黑名单 IP | CC 自动拉黑 | CC 触发后自动封禁的 IP |
| 4 | 静态黑名单 IP | `blackip.rule` | 手动配置的 IP 黑名单 |
| 5 | CC 攻击 | 实时计数 | 64 分片滑动窗口计数 |
| 6 | User-Agent | `useragent.rule` | 恶意扫描器/工具 UA（白名单 UA 仅跳过此项） |
| 7 | URL 路径 | `url.rule` | 路径遍历、敏感文件、管理后台等 |
| 8 | URL 参数 | `args.rule` | SQL 注入、XSS、SSTI、RCE 等 |
| 9 | Cookie | `cookie.rule` | Cookie 注入 |
| 10 | Referer | `referer.rule` | 恶意来源、支付接口保护 |
| 11 | POST body | `post.rule` | 需读取 body，最昂贵 |
| 12 | 文件上传 | `fileext.rule` | 需解析 multipart，最昂贵 |

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

- **异步写入**：buffered channel (4096) + worker goroutine
- **队列满时丢弃**：日志队列满时直接丢弃新日志，不阻塞请求
- **JSON 格式**：每行一条 JSON，包含时间戳、客户端 IP、攻击类型、命中规则、请求 URL 等
- **日志文件**：`{log_dir}/{YYYY-MM-DD}_waf.log`
- **自动轮转**：单文件超过 100MB 时重命名为 `.old`，按天分文件

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

- **测试机**：物理机（4 核 CPU）
- **发包机**：Apache Bench (ab)，本机回环
- **参数**：50000 请求，200 并发

### 压测对比

| 场景 | req/s | CPU | RSS | P99 | 开销 |
|------|-------|-----|-----|-----|------|
| Caddy + reverse_proxy（无 WAF） | 6,372 | 140% | 70 MB | 69ms | 基准 |
| CaddyGuard 规则全关 | 6,454 | 168% | 72 MB | 68ms | ~0% |
| CaddyGuard 规则全开（不含 CC） | 5,954 | 178% | 79 MB | 74ms | ~7% |
| CaddyGuard + CC | 5,936 | 179% | 76 MB | 75ms | ~7% |
| CaddyGuard + POST body | 5,092 | 198% | 77 MB | 92ms | ~20% |

> CPU 为压测期间 pidstat 采样的平均值（4 核机器，>100% 表示多核占用）。RSS 为压测期间峰值内存。

### Go Benchmark 微基准

| 组件 | 性能 | 说明 |
|------|------|------|
| CC Incr (64 分片并行) | 67 ns/op | 无锁竞争 |
| CC IsBanned (并行) | 25 ns/op | 分片读锁 |
| matchRules (大小写不敏感) | 2.2 ns/op | ToLower 只做一次 |
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
| 16 种攻击拦截 | ✅ | 全部正确拦截 (403) |

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
| .txt 文件上传 | 非403 | ✅ 200 | 正常文件放行 |
| .sql 文件上传 | 403 | ✅ 403 | 文件扩展名检测 |
| .htaccess 文件上传 | 403 | ✅ 403 | 文件扩展名检测 |

## 部署

### 系统服务

```bash
# 复制二进制
cp caddy /usr/local/bin/

# 创建配置目录
mkdir -p /etc/caddyguard/rule-config
cp -r rule-config/* /etc/caddyguard/rule-config/

# systemd 服务
cat > /etc/systemd/system/caddy.service << 'EOF'
[Unit]
Description=Caddy with CaddyGuard WAF
After=network.target

[Service]
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
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
├── rules.go               # 规则缓存 + 热加载 + 配置预合并
├── matcher.go             # 正则匹配引擎（预编译 + ToLower 优化）
├── storage.go             # CC 存储（64 分片 + 滑动窗口 + 内存上限）
├── logger.go              # 异步日志（buffered channel + worker）
├── request_context.go     # 请求上下文缓存（clientIP, URI）
├── detector_*.go          # 各检测器实现
├── bench_test.go          # Go benchmark 测试
├── rule-config/           # 规则配置文件
│   ├── config.json        # 全局 WAF 配置
│   ├── domain.json        # 域名级配置覆盖
│   ├── *.rule             # 规则文件（url/args/post/cookie/ua/referer/fileext/white*）
│   └── domains/           # 域名级独立规则目录
└── test-config/           # 测试用 Caddyfile + 压测脚本
```
