package caddyguard

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"time"
	"unsafe"

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
	httpcaddyfile.RegisterGlobalOption("caddyguard", parseGlobalOption)

	// 保留站点级 handler 指令（向后兼容）
	httpcaddyfile.RegisterHandlerDirective("caddyguard", parseCaddyfile)
}

// ============================================================
// GuardApp — 全局 App，自动将 Guard 中间件注入到所有 HTTP 站点
// ============================================================

type GuardApp struct {
	RuleDir string `json:"rule_dir,omitempty"`
	ctx     caddy.Context
}

func (*GuardApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddyguard",
		New: func() caddy.Module { return new(GuardApp) },
	}
}

// Provision 只保存配置，不注入 route
// route 注入在 Start() 中完成（此时 http.Provision 已编译完 primaryHandlerChain）
func (ga *GuardApp) Provision(ctx caddy.Context) error {
	ga.ctx = ctx
	if ga.RuleDir == "" {
		ga.RuleDir = "/etc/caddyguard/rule-config"
	}
	return nil
}

// Start 在 http.Start() 之前执行（字母序 caddyguard < http）
// 此时 primaryHandlerChain 已编译，用反射包装它
func (ga *GuardApp) Start() error {
	httpAppRaw, err := ga.ctx.App("http")
	if err != nil {
		return nil
	}
	httpApp, ok := httpAppRaw.(*caddyhttp.App)
	if !ok {
		return nil
	}

	for srvName, srv := range httpApp.Servers {
		// 创建 Guard handler
		guard := &Guard{RuleDir: ga.RuleDir}
		if err := guard.Provision(ga.ctx); err != nil {
			return fmt.Errorf("caddyguard: provision guard: %w", err)
		}

		// 用反射读取 primaryHandlerChain（私有字段）
		srvVal := reflect.ValueOf(srv).Elem()
		chainField := srvVal.FieldByName("primaryHandlerChain")

		if !chainField.IsValid() {
			caddy.Log().Warn("caddyguard: primaryHandlerChain field not found", zap.String("server", srvName))
			continue
		}

		// 用 unsafe.Pointer 读取私有字段（reflect.Value.Interface() 不支持非导出字段）
		// primaryHandlerChain 是 caddyhttp.Handler 接口类型，在内存中是一个指针
		chainFieldPtr := (*caddyhttp.Handler)(unsafe.Pointer(chainField.UnsafeAddr()))
		if *chainFieldPtr == nil {
			caddy.Log().Warn("caddyguard: primaryHandlerChain is nil", zap.String("server", srvName))
			continue
		}

		originalChain := *chainFieldPtr

		// 包装：Guard 先执行，放行后调用原始 chain
		wrappedChain := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// recover 容错
			defer func() {
				if rv := recover(); rv != nil {
					caddy.Log().Error("caddyguard panic", zap.Any("error", rv))
				}
			}()

			cfg := guard.GetEffectiveConfig(r)
			if cfg.WAFEnable == "off" {
				return originalChain.ServeHTTP(w, r)
			}
			blocked := guard.runChecks(w, r, cfg)
			if blocked {
				return nil
			}
			return originalChain.ServeHTTP(w, r)
		})

		// 用 unsafe 写入私有字段
		*chainFieldPtr = wrappedChain

		caddy.Log().Info("caddyguard: guard injected into server",
			zap.String("server", srvName))
	}

	return nil
}

func (ga *GuardApp) Stop() error { return nil }

// ============================================================
// Guard — HTTP 中间件 handler（站点级使用，向后兼容）
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
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &GuardApp{}
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "rule_dir":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.RuleDir = d.Val()
			}
		}
	}
	return httpcaddyfile.App{
		Name:  "caddyguard",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// parseCaddyfile 解析站点块中的 caddyguard 指令（向后兼容）
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

// ServeHTTP 实现 caddyhttp.MiddlewareHandler（站点级使用时）
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	defer func() {
		if rv := recover(); rv != nil {
			caddy.Log().Error("caddyguard panic", zap.Any("error", rv))
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
	_ caddy.Provisioner           = (*GuardApp)(nil)
	_ caddy.App                   = (*GuardApp)(nil)
)
