package caddyguard

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func init() {
	caddyconfig.RegisterAdapter("caddyguardfile", guardCaddyfileAdapter{})
}

// guardCaddyfileAdapter delegates normal Caddyfile parsing to Caddy's built-in
// adapter, then injects the WAF handler into every HTTP server when the global
// caddyguard option is configured.
//
// 注入策略：遍历 server 的每条 route 的 handle 列表：
//   - 如果 handle 中已有 caddyguard handler（如 caddyguard waf_enable off），跳过
//   - 如果 handle 中有 subroute handler，递归进入 subroute 内部处理
//   - 否则，在该 handle 列表最前面注入全局 caddyguard handler
//
// 这确保了 path 级别的 caddyguard waf_enable off 能优先生效，
// 不被全局 handler 拦截。
type guardCaddyfileAdapter struct{}

func (guardCaddyfileAdapter) Adapt(body []byte, options map[string]any) ([]byte, []caddyconfig.Warning, error) {
	base := caddyconfig.GetAdapter("caddyfile")
	if base == nil {
		return nil, nil, fmt.Errorf("caddyfile adapter is not registered")
	}

	config, warnings, err := base.Adapt(body, options)
	if err != nil {
		return nil, warnings, err
	}

	var root map[string]any
	if err := json.Unmarshal(config, &root); err != nil {
		return nil, warnings, fmt.Errorf("decode adapted Caddy config: %w", err)
	}
	apps, _ := root["apps"].(map[string]any)
	if _, enabled := apps["caddyguard"]; !enabled {
		return config, warnings, nil
	}

	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, rawServer := range servers {
		server, ok := rawServer.(map[string]any)
		if !ok {
			continue
		}
		routes, _ := server["routes"].([]any)
		if len(routes) == 0 {
			continue
		}

		// 遍历每条 route，注入全局 caddyguard handler
		for _, rawRoute := range routes {
			route, ok := rawRoute.(map[string]any)
			if !ok {
				continue
			}
			injectGuardIntoHandleList(route)
		}
	}

	config, err = json.Marshal(root)
	if err != nil {
		return nil, warnings, fmt.Errorf("encode adapted Caddy config: %w", err)
	}
	return config, warnings, nil
}

// injectGuardIntoHandleList 处理 route 的 handle 列表：
//   - 如果已有 caddyguard handler，跳过（路径级 WAF 开关优先生效）
//   - 如果有 subroute handler，递归处理 subroute 内部 routes
//   - 否则，在 handle 列表最前面注入全局 caddyguard handler
func injectGuardIntoHandleList(route map[string]any) {
	handles, ok := route["handle"].([]any)
	if !ok || len(handles) == 0 {
		return
	}

	// 1. 检查 handle 列表中是否已有 caddyguard handler
	for _, h := range handles {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if handler, _ := hm["handler"].(string); handler == "caddyguard" {
			// 已有 caddyguard handler（如 waf_enable off），不注入
			return
		}
	}

	// 2. 检查是否有 subroute handler，递归处理
	hasSubroute := false
	for _, h := range handles {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if handler, _ := hm["handler"].(string); handler == "subroute" {
			hasSubroute = true
			subRoutes, ok := hm["routes"].([]any)
			if !ok {
				continue
			}
			for _, subRaw := range subRoutes {
				subRoute, ok := subRaw.(map[string]any)
				if !ok {
					continue
				}
				injectGuardIntoHandleList(subRoute)
			}
		}
	}

	// 3. 如果没有 subroute（直接是 static_response/reverse_proxy 等终端 handler），
	//    在 handle 列表最前面注入全局 caddyguard handler
	if !hasSubroute {
		globalHandler := map[string]any{"handler": "caddyguard"}
		route["handle"] = append([]any{globalHandler}, handles...)
	}
}

// globalGuardRoute 返回一个全局 caddyguard handler route（用于兜底）
func globalGuardRoute() map[string]any {
	return map[string]any{
		"handle": []any{
			map[string]any{"handler": "caddyguard"},
		},
	}
}
