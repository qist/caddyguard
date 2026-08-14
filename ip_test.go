package caddyguard

import "testing"

func TestIPMatch(t *testing.T) {
	tests := []struct {
		name     string
		clientIP string
		rule     string
		want     bool
	}{
		// IPv4 精确匹配
		{"v4 exact", "192.168.1.100", "192.168.1.100", true},
		{"v4 exact no match", "192.168.1.100", "192.168.1.101", false},

		// IPv4 CIDR
		{"v4 cidr /24 match", "192.168.1.100", "192.168.1.0/24", true},
		{"v4 cidr /24 no match", "192.168.2.100", "192.168.1.0/24", false},
		{"v4 cidr /16 match", "10.0.5.10", "10.0.0.0/16", true},
		{"v4 cidr /32", "8.8.8.8", "8.8.8.8/32", true},

		// IPv4 glob
		{"v4 glob match", "192.168.1.100", "192.168.1.*", true},
		{"v4 glob no match", "192.168.2.100", "192.168.1.*", false},
		{"v4 glob multi", "192.168.1.100", "192.168.*.*", true},

		// IPv6 精确匹配
		{"v6 exact", "2001:db8::1", "2001:db8::1", true},
		{"v6 exact no match", "2001:db8::1", "2001:db8::2", false},
		{"v6 loopback", "::1", "::1", true},

		// IPv6 CIDR
		{"v6 cidr /32 match", "2001:db8:1234::5678", "2001:db8::/32", true},
		{"v6 cidr /32 no match", "2001:db9::1", "2001:db8::/32", false},
		{"v6 cidr /128", "2001:db8::1", "2001:db8::1/128", true},
		{"v6 cidr /48", "2001:db8:abcd:1234::1", "2001:db8:abcd::/48", true},

		// IPv6 glob
		{"v6 glob match", "2001:db8::1234", "2001:db8::*", true},
		{"v6 glob no match", "2001:db9::1", "2001:db8::*", false},

		// 混合场景
		{"v4 rule v6 ip", "2001:db8::1", "192.168.1.0/24", false},
		{"v6 rule v4 ip", "192.168.1.1", "2001:db8::/32", false},

		// 边界
		{"empty client", "", "192.168.1.0/24", false},
		{"empty rule", "192.168.1.1", "", false},
		{"invalid cidr", "192.168.1.1", "invalid/24", false},
		{"invalid ip", "not_an_ip", "192.168.1.0/24", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipMatch(tt.clientIP, tt.rule)
			if got != tt.want {
				t.Errorf("ipMatch(%q, %q) = %v, want %v", tt.clientIP, tt.rule, got, tt.want)
			}
		})
	}
}
