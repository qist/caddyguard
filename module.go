package caddyguard

import (
	"context"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&Guard{})
	caddy.RegisterModule(&GuardApp{})

	// 全局选项：在 Caddyfile 全局 {} 块中使用
	// 存储 rule_dir；caddyguardfile 适配器会自动注入 handler
	httpcaddyfile.RegisterGlobalOption("caddyguard", parseGlobalOption)

	// 站点级 handler 指令（标准 Caddy 中间件链，无需 reflect/unsafe）
	httpcaddyfile.RegisterHandlerDirective("caddyguard", parseCaddyfile)

	// 站点级配置时默认在 reverse_proxy 之前执行。
	httpcaddyfile.RegisterDirectiveOrder("caddyguard", "before", "tracing")
}

// ============================================================
// GuardApp — Caddy App 模块（全局配置存储）
// ============================================================

// GuardApp 存储全局 caddyguard 配置（rule_dir）。
// 全局选项启用时，caddyguardfile 适配器会向每个 HTTP server 注入 Guard handler。
type GuardApp struct {
	RuleDir string `json:"rule_dir,omitempty"`
}

func (*GuardApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddyguard",
		New: func() caddy.Module { return new(GuardApp) },
	}
}

func (a *GuardApp) Start() error { return nil }
func (a *GuardApp) Stop() error  { return nil }

// ============================================================
// Guard — HTTP 中间件 handler
// ============================================================

type Guard struct {
	RuleDir string `json:"rule_dir,omitempty"`

	ruleCache *RuleCache
	ccStore   CCStore
	logger    *WAFLogger

	cleanupCtx    context.Context    `json:"-"`
	cleanupCancel context.CancelFunc `json:"-"`
}

func (*Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddyguard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// parseGlobalOption 解析全局 {} 块中的 caddyguard 指令
// 存储配置到 GuardApp；适配器随后自动注入所有站点的 handler。
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	cfg := &GuardApp{}
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "rule_dir":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				cfg.RuleDir = d.Val()
			}
		}
	}
	return httpcaddyfile.App{
		Name:  "caddyguard",
		Value: caddyconfig.JSON(cfg, nil),
	}, nil
}

// parseCaddyfile 解析站点块中的 caddyguard 指令
// 解析站点级配置；全局配置已启用时此 handler 会由适配器自动注入。
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

func (g *Guard) Provision(ctx caddy.Context) error {
	// 优先使用站点级配置，为空时从全局 GuardApp 获取
	if g.RuleDir == "" {
		if app, err := ctx.App("caddyguard"); err == nil {
			if guardApp, ok := app.(*GuardApp); ok && guardApp.RuleDir != "" {
				g.RuleDir = guardApp.RuleDir
			}
		}
	}
	if g.RuleDir == "" {
		g.RuleDir = "/etc/caddyguard/rule-config"
	}
	g.ruleCache = NewRuleCache(g.RuleDir)
	g.ccStore = NewMemoryStore()
	cfg := g.ruleCache.GetGlobalConfig()
	g.logger = NewWAFLogger(cfg.LogDir)
	g.cleanupCtx, g.cleanupCancel = context.WithCancel(ctx)
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
// 通过标准 Caddy 中间件链调用，无需 reflect/unsafe
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	defer func() {
		if rv := recover(); rv != nil {
			caddy.Log().Error("caddyguard panic",
				zap.Any("error", rv),
				zap.String("path", r.URL.Path))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("WAF internal error"))
		}
	}()

	cfg := g.GetEffectiveConfig(r)
	if cfg.WAFEnable == "off" {
		return next.ServeHTTP(w, r)
	}
	blocked := g.runChecks(w, r, cfg)
	if blocked {
		return nil
	}
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Guard)(nil)
	_ caddy.CleanerUpper          = (*Guard)(nil)
	_ caddyhttp.MiddlewareHandler = (*Guard)(nil)
	_ caddy.App                   = (*GuardApp)(nil)
)
