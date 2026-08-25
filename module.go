package caddyguard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// wafDisabledCtxKey 用于在 request context 中传递 WAF 已关闭的标记
// 当外层 caddyguard 判定 waf_enable=off 后设置此标记，
// 内层 subroute 的 caddyguard 看到此标记直接跳过，避免 Host 改写后重复检测
type wafDisabledCtxKey struct{}

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

	WAFEnable string `json:"waf_enable,omitempty"` // 站点级 WAF 总开关

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
		// Allow the handler to be attached directly to a Caddy route selected
		// by a path matcher, for example:
		//
		//   @webhook path /api/webhook/*
		//   route @webhook {
		//       caddyguard waf_enable off
		//       reverse_proxy 127.0.0.1:8080
		//   }
		//
		// The route matcher is then the single source of truth for the path;
		// caddyguard only carries the route-local WAF setting.
		if h.NextArg() {
			if h.Val() != "waf_enable" || !h.NextArg() {
				return nil, h.ArgErr()
			}
			g.WAFEnable = h.Val()
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			continue
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "rule_dir":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.RuleDir = h.Val()

			case "waf_enable":
				// 站点级 WAF 总开关：waf_enable off
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.WAFEnable = h.Val()

			default:
				return nil, fmt.Errorf("unknown caddyguard option %q; use caddyguard waf_enable off inside a Caddy path route", h.Val())
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

	// 如果外层 caddyguard 已判定 WAF 关闭，直接跳过（处理 subroute 中 Host 改写后重复检测的问题）
	if _, disabled := r.Context().Value(wafDisabledCtxKey{}).(bool); disabled {
		return next.ServeHTTP(w, r)
	}

	cfg := g.GetEffectiveConfig(r)
	// 站点级 WAF 总开关（Caddyfile 中配置的 waf_enable off 优先于 config.json）
	if g.WAFEnable == "off" || cfg.WAFEnable == "off" {
		// 在 request context 中标记 WAF 已关闭，内层 subroute 的 caddyguard 直接跳过
		ctx := context.WithValue(r.Context(), wafDisabledCtxKey{}, true)
		r = r.WithContext(ctx)
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
