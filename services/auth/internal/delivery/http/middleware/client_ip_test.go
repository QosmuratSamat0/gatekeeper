package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func parseCIDRsOrFatal(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("failed to parse test CIDR %q: %v", c, err)
		}
		nets = append(nets, ipNet)
	}
	return nets
}

func TestClientIPResolver_TableDriven(t *testing.T) {
	trustedNets := parseCIDRsOrFatal(t, "10.0.0.0/8", "172.16.0.0/12", "fd00::/8")

	tests := []struct {
		name         string
		trustedCIDRs []*net.IPNet
		remoteAddr   string
		xff          []string
		expectedKey  string
	}{
		{
			name:         "no trusted CIDRs plus a spoofed XFF gives RemoteAddr",
			trustedCIDRs: nil,
			remoteAddr:   "198.51.100.1:12345",
			xff:          []string{"203.0.113.195"},
			expectedKey:  "198.51.100.1",
		},
		{
			name:         "trusted peer with a single XFF value gives that value",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.2:54321",
			xff:          []string{"203.0.113.50"},
			expectedKey:  "203.0.113.50",
		},
		{
			name:         "trusted peer with chain spoofed, client, trusted-proxy gives client",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.1:443",
			xff:          []string{"198.51.100.99, 203.0.113.77, 10.0.0.5"},
			expectedKey:  "203.0.113.77",
		},
		{
			name:         "trusted peer with multiple XFF headers spoofed, client, trusted-proxy gives client",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.1:443",
			xff:          []string{"198.51.100.99", "203.0.113.77, 10.0.0.5"},
			expectedKey:  "203.0.113.77",
		},
		{
			name:         "untrusted peer with XFF gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "198.51.100.10:3344",
			xff:          []string{"203.0.113.88"},
			expectedKey:  "198.51.100.10",
		},
		{
			name:         "trusted peer with malformed XFF string gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.2:1234",
			xff:          []string{"not-an-ip"},
			expectedKey:  "10.0.0.2",
		},
		{
			name:         "trusted peer with malformed trailing XFF value gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.2:1234",
			xff:          []string{"203.0.113.50, 999.999.999.999"},
			expectedKey:  "10.0.0.2",
		},
		{
			name:         "trusted peer with only trusted addresses in XFF gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.1:1234",
			xff:          []string{"10.0.0.2, 10.0.0.3"},
			expectedKey:  "10.0.0.1",
		},
		{
			name:         "trusted peer with empty XFF gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.1:1234",
			xff:          []string{""},
			expectedKey:  "10.0.0.1",
		},
		{
			name:         "trusted peer with missing XFF gives RemoteAddr",
			trustedCIDRs: trustedNets,
			remoteAddr:   "10.0.0.1:1234",
			xff:          nil,
			expectedKey:  "10.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewClientIPResolver(tc.trustedCIDRs)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, val := range tc.xff {
				req.Header.Add("X-Forwarded-For", val)
			}

			resolved := resolver.ResolveClientIP(req)
			if resolved != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, resolved)
			}
		})
	}
}

func TestNormalizeIPKey(t *testing.T) {
	t.Run("IPv4 used as is", func(t *testing.T) {
		ip := net.ParseIP("192.0.2.1")
		key := NormalizeIPKey(ip)
		if key != "192.0.2.1" {
			t.Errorf("expected 192.0.2.1, got %s", key)
		}
	})

	t.Run("IPv4-mapped IPv6 treated as IPv4", func(t *testing.T) {
		mapped := net.ParseIP("::ffff:1.2.3.4")
		rawIPv4 := net.ParseIP("1.2.3.4")

		mappedKey := NormalizeIPKey(mapped)
		rawKey := NormalizeIPKey(rawIPv4)

		if mappedKey != "1.2.3.4" {
			t.Errorf("expected 1.2.3.4, got %s", mappedKey)
		}
		if mappedKey != rawKey {
			t.Errorf("expected ::ffff:1.2.3.4 to match 1.2.3.4 key, got %s vs %s", mappedKey, rawKey)
		}
	})

	t.Run("two IPv6 addresses in same /64 give same key, different /64 gives different key", func(t *testing.T) {
		ip1 := net.ParseIP("2001:db8:abcd:0012:0000:0000:0000:0001")
		ip2 := net.ParseIP("2001:db8:abcd:0012:ffff:eeee:dddd:cccc")
		ipOther := net.ParseIP("2001:db8:abcd:0013:0000:0000:0000:0001")

		key1 := NormalizeIPKey(ip1)
		key2 := NormalizeIPKey(ip2)
		keyOther := NormalizeIPKey(ipOther)

		if key1 != "2001:db8:abcd:12::/64" {
			t.Errorf("expected 2001:db8:abcd:12::/64, got %s", key1)
		}
		if key1 != key2 {
			t.Errorf("expected key1 == key2 for same /64, got %s vs %s", key1, key2)
		}
		if key1 == keyOther {
			t.Errorf("expected key1 != keyOther for different /64, got %s vs %s", key1, keyOther)
		}
	})

	t.Run("nil and invalid IPs return safe strings", func(t *testing.T) {
		if NormalizeIPKey(nil) != "" {
			t.Errorf("expected empty string for nil IP")
		}
	})
}
