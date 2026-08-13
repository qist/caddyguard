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
// adapter, then adds one WAF route to every HTTP server when the global
// caddyguard option is configured. Keeping this as a separate adapter avoids
// modifying or forking Caddy itself.
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
		server["routes"] = append([]any{globalGuardRoute()}, routes...)
	}

	config, err = json.Marshal(root)
	if err != nil {
		return nil, warnings, fmt.Errorf("encode adapted Caddy config: %w", err)
	}
	return config, warnings, nil
}

func globalGuardRoute() map[string]any {
	return map[string]any{
		"handle": []any{
			map[string]any{"handler": "caddyguard"},
		},
	}
}
