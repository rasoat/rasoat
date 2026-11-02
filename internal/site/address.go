// Package site reads a site from outside: its page and scripts, as a browser does, and what they say it runs.
package site

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Refused is a refusal, not a failure. Its word is invalid, dns, private or similar.
type Refused struct{ Word string }

func (r *Refused) Error() string { return r.Word }

var privateV4 = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

var (
	global6 = netip.MustParsePrefix("2000::/3")
	doc6    = netip.MustParsePrefix("2001:db8::/32")
	sixTo4  = netip.MustParsePrefix("2002::/16")
)

// IsPublicAddress is public unicast only. IPv6 is allow-listed to global unicast, minus documentation and 6to4.
func IsPublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		for _, p := range privateV4 {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	}
	return ip.Is6() && global6.Contains(ip) && !doc6.Contains(ip) && !sixTo4.Contains(ip)
}

// AssertPublic refuses a host that resolves to anything but public addresses. The dialer checks again at connect time.
func AssertPublic(ctx context.Context, u *url.URL) error {
	host := strings.Trim(u.Hostname(), "[]")
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return &Refused{"dns"}
	}
	if len(addrs) == 0 {
		return &Refused{"private"}
	}
	for _, a := range addrs {
		if !IsPublicAddress(a) {
			return &Refused{"private"}
		}
	}
	return nil
}
