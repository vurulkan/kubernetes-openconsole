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
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = a.Unmap()
		if !isTrustedProxy(client) {
			return client.String()
		}
	}
	if len(hops) == 0 {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-Ip"))); err == nil {
			return a.Unmap().String()
		}
	}
	return client.String()
}
