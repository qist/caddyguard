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

	// 全局选项：在 Caddyfile 全局 {} 块中使用
	// 解析配置并存储，站点级 caddyguard 指令自动读取
	httpcaddyfile.RegisterGlobalOption("caddyguard", parseGlobalOption)

	// 站点级 handler 指令（标准 Caddy 中间件链，无需 reflect/unsafe）
	httpcaddyfile.RegisterHandlerDirective("caddyguard", parseCaddyfile)
}

// ============================================================
// 全局配置存储（通过全局选项解析，供站点级指令使用）
// ============================================================

// globalGuardConfig 全局 caddyguard 配置（从全局选项解析）
type globalGuardConfig struct {
	RuleDir string
}

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
// 存储配置供站点级指令使用
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	cfg := &globalGuardConfig{}
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
	// 返回 App 类型，Caddy 会注册为 caddyguard app
	// 但实际上我们不需要 GuardApp，这里只是为了利用全局选项机制
	return httpcaddyfile.App{
		Name:  "caddyguard",
		Value: caddyconfig.JSON(cfg, nil),
	}, nil
}

// parseCaddyfile 解析站点块中的 caddyguard 指令
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
)

