package caddyguard

import (
	"context"
	"net/http"
)

// request-scoped keys for caching per-request computed values
type ctxKey int

const (
	keyClientIP ctxKey = iota
	keyReqURI
)

// getClientIPCached 从 context 缓存中获取 clientIP，未缓存则计算并存入
func (g *Guard) getClientIPCached(r *http.Request, cfg Config) string {
	if v, ok := r.Context().Value(keyClientIP).(string); ok {
		return v
	}
	ip := g.getClientIP(r, cfg)
	// 存入 context（r.WithContext 返回新 *http.Request）
	*r = *r.WithContext(context.WithValue(r.Context(), keyClientIP, ip))
	return ip
}

// reqURI 从 context 缓存中获取 r.URL.RequestURI()，未缓存则计算并存入
func reqURICached(r *http.Request) string {
	if v, ok := r.Context().Value(keyReqURI).(string); ok {
		return v
	}
	uri := r.URL.RequestURI()
	*r = *r.WithContext(context.WithValue(r.Context(), keyReqURI, uri))
	return uri
}
