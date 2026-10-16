package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIPResolver resolves the real client IP for rate limiting and auditing.
// It strictly validates trusted proxy boundaries before inspecting forwarding headers.
type ClientIPResolver struct {
	trustedCIDRs []*net.IPNet
}

// DefaultClientIPResolver resolves client IP strictly from RemoteAddr without trusting any headers.
var DefaultClientIPResolver = NewClientIPResolver(nil)

// NewClientIPResolver creates a resolver configured with the provided trusted proxy CIDRs.
// If trustedCIDRs is empty, all forwarding headers are ignored and RemoteAddr is used.
func NewClientIPResolver(trustedCIDRs []*net.IPNet) *ClientIPResolver {
	return &ClientIPResolver{
		trustedCIDRs: trustedCIDRs,
	}
}

// ResolveClientIP resolves the client IP from the request and returns a normalized limiter key.
// IPv4 is returned as-is, IPv4-mapped IPv6 is converted to IPv4, and IPv6 is masked to /64.
func (r *ClientIPResolver) ResolveClientIP(req *http.Request) string {
	if req == nil {
		return ""
	}

	directHost, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		directHost = req.RemoteAddr
	}
	directHost = strings.Trim(directHost, "[]")
	peerIP := net.ParseIP(directHost)
	if peerIP == nil {
		return directHost
	}

	// If no trusted CIDRs are configured or direct peer is outside trusted CIDRs,
	// never inspect client-provided forwarding headers; return normalized peer IP.
	if len(r.trustedCIDRs) == 0 || !r.isTrusted(peerIP) {
		return NormalizeIPKey(peerIP)
	}

	// Direct peer is trusted: evaluate X-Forwarded-For from right to left.
	xffValues := req.Header.Values("X-Forwarded-For")
	if len(xffValues) == 0 {
		return NormalizeIPKey(peerIP)
	}

	var rawEntries []string
	for _, val := range xffValues {
		parts := strings.Split(val, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				rawEntries = append(rawEntries, trimmed)
			}
		}
	}

	if len(rawEntries) == 0 {
		return NormalizeIPKey(peerIP)
	}

	// Walk from right to left, skipping trusted addresses.
	// The first untrusted address is the client IP.
	for i := len(rawEntries) - 1; i >= 0; i-- {
		entry := rawEntries[i]
		host, _, err := net.SplitHostPort(entry)
		if err != nil {
			host = entry
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			// Malformed IP in forwarding header: fall back safely to RemoteAddr.
			return NormalizeIPKey(peerIP)
		}

		if r.isTrusted(ip) {
			continue
		}

		// First untrusted address from the right is the actual client IP.
		return NormalizeIPKey(ip)
	}

	// If the header contains only trusted addresses, fall back to RemoteAddr.
	return NormalizeIPKey(peerIP)
}

// isTrusted checks whether the given IP address is contained within any configured trusted CIDR.
func (r *ClientIPResolver) isTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, cidr := range r.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeIPKey formats an IP address for use as a rate limiter key.
// IPv4 is returned as dot-decimal.
// IPv4-mapped IPv6 (::ffff:1.2.3.4) is treated as IPv4 (1.2.3.4).
// IPv6 is masked to its /64 prefix to prevent rotation abuse inside subnets.
func NormalizeIPKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	// Treat IPv4-mapped IPv6 as IPv4
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	// IPv6: mask to /64 prefix
	if len(ip) == net.IPv6len {
		mask := net.CIDRMask(64, 128)
		masked := ip.Mask(mask)
		return (&net.IPNet{IP: masked, Mask: mask}).String()
	}
	return ip.String()
}
