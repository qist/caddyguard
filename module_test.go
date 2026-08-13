package caddyguard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestGlobalCaddyguardInjectsHandlerIntoEveryHTTPServer(t *testing.T) {
	config, err := adaptCaddyfile(t, `
{
    caddyguard {
        rule_dir /tmp/rules
    }
}

one.example:8081 {
    respond one
}

two.example:8082 {
    respond two
}
`)
	if err != nil {
		t.Fatalf("adapt Caddyfile: %v", err)
	}

	if count := strings.Count(string(config), `"handler":"caddyguard"`); count != 2 {
		t.Fatalf("expected one caddyguard handler per HTTP server, got %d in config: %s", count, config)
	}
	if !strings.Contains(string(config), `"rule_dir":"/tmp/rules"`) {
		t.Fatalf("global rule_dir missing from adapted config: %s", config)
	}
	if strings.Index(string(config), `"handler":"caddyguard"`) > strings.Index(string(config), `"handler":"static_response"`) {
		t.Fatalf("caddyguard must execute before terminal handlers: %s", config)
	}
}

func TestCaddyguardIsNotInjectedWithoutGlobalOption(t *testing.T) {
	config, err := adaptCaddyfile(t, `example.com {
    respond ok
}`)
	if err != nil {
		t.Fatalf("adapt Caddyfile: %v", err)
	}
	if strings.Contains(string(config), `"handler":"caddyguard"`) {
		t.Fatalf("caddyguard was injected without its global option: %s", config)
	}
}

func adaptCaddyfile(t *testing.T, input string) ([]byte, error) {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyguardfile")
	if adapter == nil {
		t.Fatal("caddyguardfile adapter is not registered")
	}
	config, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		return nil, err
	}
	if !json.Valid(config) {
		t.Fatalf("adapter returned invalid JSON: %s", config)
	}
	return config, nil
}
