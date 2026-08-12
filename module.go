package caddyguard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&Guard{})
	// 注册 Caddyfile 指令，可在站点块中使用：caddyguard { rule_dir ... }
	httpcaddyfile.RegisterHandlerDirective("caddyguard", parseCaddyfile)
}

// Guard 实现 caddyhttp.MiddlewareHandler 接口
type Guard struct {
	// 从 Caddyfile 解析的规则目录
	RuleDir string `json:"rule_dir,omitempty"`

	// 运行时状态（不序列化）
	ruleCache *RuleCache
	ccStore   CCStore
	logger    *WAFLogger

	cleanupCtx    context.Context    `json:"-"`
	cleanupCancel context.CancelFunc `json:"-"`
}

// CaddyModule 返回模块信息
func (*Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddyguard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// parseCaddyfile 解析 Caddyfile 中的 caddyguard 指令
// 用法：
//   caddyguard
//   caddyguard {
//       rule_dir /etc/caddyguard/rule-config
//   }
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	g := &Guard{}
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "rule_dir":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.RuleDir = h.Val()
			}
		}
	}
	return g, nil
}

// Provision 实现 caddy.Provisioner
func (g *Guard) Provision(ctx caddy.Context) error {
	if g.RuleDir == "" {
		g.RuleDir = "/etc/caddyguard/rule-config"
	}

	// 初始化运行时组件
	g.ruleCache = NewRuleCache(g.RuleDir)
	g.ccStore = NewMemoryStore()

	// 从 config.json 读取全局配置初始化 logger
	cfg := g.ruleCache.GetGlobalConfig()
	g.logger = NewWAFLogger(cfg.LogDir)

	// 启动后台清理
	g.cleanupCtx, g.cleanupCancel = context.WithCancel(ctx)
	go g.cleanupLoop()

	return nil
}

// Cleanup 实现 caddy.CleanerUpper
func (g *Guard) Cleanup() error {
	if g.cleanupCancel != nil {
		g.cleanupCancel()
	}
	if g.logger != nil {
		g.logger.Close()
	}
	return nil
}

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

// ServeHTTP 实现 caddyhttp.MiddlewareHandler
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// recover 容错
	defer func() {
		if rv := recover(); rv != nil {
			_ = fmt.Sprintf("caddyguard panic: %v", rv)
		}
	}()

	// 1. 获取域名级配置
	cfg := g.GetEffectiveConfig(r)

	// 2. 安全总开关
	if cfg.WAFEnable == "off" {
		return next.ServeHTTP(w, r)
	}

	// 3. 执行检测链
	blocked := g.runChecks(w, r, cfg)
	if blocked {
		return nil
	}

	// 4. 放行
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner          = (*Guard)(nil)
	_ caddy.CleanerUpper         = (*Guard)(nil)
	_ caddyhttp.MiddlewareHandler = (*Guard)(nil)
)
