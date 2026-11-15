package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// trustedProxies are the networks (TRUSTED_PROXIES) whose X-Forwarded-For /
// X-Real-Ip the console believes. Empty = none: the client is the address
// the connection comes from.
var trustedProxies []netip.Prefix

// SetTrustedProxies parses TRUSTED_PROXIES: comma-separated CIDRs or single
// addresses.
func SetTrustedProxies(v string) error {
	var out []netip.Prefix
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR", f)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR", f)
		}
		out = append(out, p.Masked())
	}
	trustedProxies = out
	return nil
}

func isTrustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address of the client: the connection's source, unless
// that is a trusted proxy. Then X-Forwarded-For is read from the right and
// the first address that isn't a trusted proxy wins (what the client wrote
// itself is further left and never reached), else X-Real-Ip.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil || !isTrustedProxy(remote) {
		return host
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	client := remote
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			break
		}
		client = a
		if !isTrustedProxy(client) {
			return client.String()
		}
	}
	if len(hops) == 0 {
		if a, ok := parseHop(r.Header.Get("X-Real-Ip")); ok {
			return a.String()
		}
	}
	return client.String()
}

// parseHop reads one forwarded address: "1.2.3.4", "2001:db8::1", or with a
// port as Azure Application Gateway writes it ("1.2.3.4:5678", "[2001:db8::1]:80").
func parseHop(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
