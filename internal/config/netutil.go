package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Tunnel pool: one /24 per WireGuard interface, third octet 201..250.
const (
	PoolFirst = 201
	PoolLast  = 250
)

var (
	poolRange  = netip.MustParsePrefix("172.31.0.0/16")
	ifNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	slugRe     = regexp.MustCompile(`[^a-z0-9]+`)
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,64}$`)
	userRe     = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
)

// PoolPrefix returns 172.31.<octet>.0/24.
func PoolPrefix(octet int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 31, byte(octet), 0}), 24)
}

// InPool reports whether p overlaps any 172.31.201-250.0/24 subnet.
func InPool(p netip.Prefix) bool {
	if !p.Addr().Is4() || !p.Overlaps(poolRange) {
		return false
	}
	for o := PoolFirst; o <= PoolLast; o++ {
		if p.Overlaps(PoolPrefix(o)) {
			return true
		}
	}
	return false
}

// ParseCIDR4 parses an IPv4 CIDR, masks host bits, and rejects /0.
func ParseCIDR4(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q: only IPv4 is supported", s)
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%q: /0 is not allowed, use tunnel_mode=full", s)
	}
	return p.Masked(), nil
}

// HostIn returns the n-th host address of an IPv4 /24 (n=1 -> .1).
func HostIn(p netip.Prefix, n int) netip.Addr {
	b := p.Masked().Addr().As4()
	b[3] = byte(n)
	return netip.AddrFrom4(b)
}

func ValidIfName(s string) bool { return ifNameRe.MatchString(s) && s != "." && s != ".." }

func ValidHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return len(s) <= 253 && hostnameRe.MatchString(s)
}

func ValidName(s string) bool     { return nameRe.MatchString(s) }
func ValidUsername(s string) bool { return userRe.MatchString(s) }

// Slug turns "Site A" into "site-a" for stable, URL-safe IDs.
func Slug(s string) string {
	out := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(out) > 48 {
		out = strings.Trim(out[:48], "-")
	}
	return out
}

// SplitListen splits a comma-separated GOVPN_LISTEN value.
func SplitListen(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ValidListen accepts 1-4 IPv4 HOST:PORT addresses (or localhost:PORT).
// Wildcard binds are refused: the API must never listen on every interface.
func ValidListen(s string) error {
	parts := SplitListen(s)
	if len(parts) == 0 || len(parts) > 4 {
		return fmt.Errorf("need 1-4 comma-separated HOST:PORT addresses")
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if seen[p] {
			return fmt.Errorf("%q listed twice", p)
		}
		seen[p] = true
		if strings.HasPrefix(p, "localhost:") {
			if _, err := netip.ParseAddrPort("127.0.0.1:" + strings.TrimPrefix(p, "localhost:")); err != nil {
				return fmt.Errorf("%q: invalid port", p)
			}
			continue
		}
		ap, err := netip.ParseAddrPort(p)
		if err != nil || ap.Port() == 0 {
			return fmt.Errorf("%q is not HOST:PORT", p)
		}
		if !ap.Addr().Is4() {
			return fmt.Errorf("%q: only IPv4 is supported", p)
		}
		if ap.Addr().IsUnspecified() {
			return fmt.Errorf("%q: wildcard bind is not allowed, use a specific IP", p)
		}
	}
	return nil
}
