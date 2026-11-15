// Package firewall renders and applies the iptables rules that isolate
// govpn-wg interfaces from each other.
//
// Only four owned chains are ever touched:
//
//	filter GOVPN-FWD   jumped from FORWARD (position 1)
//	filter GOVPN-IN    jumped from INPUT (position 1): tunnels -> hub itself
//	nat    GOVPN-POST  jumped from POSTROUTING
//	mangle GOVPN-MSS   jumped from FORWARD (TCP MSS clamping)
//
// Both filter chains end with a static catch-all for every owned interface
// name pattern (wg-s+, wg-c+), so an interface that exists in the kernel but
// is missing from the rendered state is still isolated.
//
// The whole rule set is loaded in one iptables-restore --noflush call, so a
// change replaces the owned chains atomically per table and never flushes
// rules that belong to Docker, the distribution or the administrator.
package firewall

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	ChainForward = "GOVPN-FWD"
	ChainInput   = "GOVPN-IN"
	ChainNAT     = "GOVPN-POST"
	ChainMSS     = "GOVPN-MSS"
)

// NonPublic are destinations a full-tunnel peer may not reach unless granted
// explicitly: RFC1918, CGNAT, loopback, link-local, documentation, multicast.
var NonPublic = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
}

// Iface describes one WireGuard interface and who may do what through it.
type Iface struct {
	Name string
	MTU  int
	// Grants: traffic entering this interface from Sources may go to Dests.
	Grants []Grant
	// Full tunnel sources entering this interface may reach the internet via
	// the public interface (after non-public ranges are dropped).
	FullSources []netip.Prefix
}

// OwnedPatterns are iptables interface wildcards covering every interface
// name the engine may create (see engine.Owned). Used for catch-all drops.
var OwnedPatterns = []string{"wg-s+", "wg-c+"}

// Grant allows Sources -> Dests (all protocols) for packets entering Iface.
type Grant struct {
	Comment string
	Sources []netip.Prefix
	Dests   []netip.Prefix
	// Masquerade source NAT for this grant (server LAN without return route).
	Masquerade bool
}

// Ruleset is the desired state of all owned chains.
type Ruleset struct {
	PublicIf string
	MSSMode  string // "mtu" or "pmtu"
	Ifaces   []Iface
}

// Render returns iptables-restore input for the owned chains.
func (r Ruleset) Render() string {
	var f, in, n, m []string
	add := func(dst *[]string, format string, args ...any) { *dst = append(*dst, fmt.Sprintf(format, args...)) }

	for _, it := range r.Ifaces {
		add(&f, "-A %s -i %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ChainForward, it.Name)
		add(&f, "-A %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ChainForward, it.Name)
		add(&f, "-A %s -i %s -m conntrack --ctstate INVALID -j DROP", ChainForward, it.Name)
	}
	for _, it := range r.Ifaces {
		for _, g := range it.Grants {
			for _, s := range g.Sources {
				for _, d := range g.Dests {
					add(&f, "-A %s -i %s -s %s -d %s -m comment --comment %s -j ACCEPT", ChainForward, it.Name, s, d, quote(g.Comment))
					if g.Masquerade {
						add(&n, "-A %s -s %s -d %s -m comment --comment %s -j MASQUERADE", ChainNAT, s, d, quote(g.Comment))
					}
				}
			}
		}
		if len(it.FullSources) > 0 && r.PublicIf != "" {
			for _, s := range it.FullSources {
				for _, np := range NonPublic {
					add(&f, "-A %s -i %s -s %s -d %s -j DROP", ChainForward, it.Name, s, np)
				}
				add(&f, "-A %s -i %s -s %s -o %s -m comment --comment %s -j ACCEPT", ChainForward, it.Name, s, r.PublicIf, quote("full-tunnel "+it.Name))
				add(&n, "-A %s -s %s -o %s -j MASQUERADE", ChainNAT, s, r.PublicIf)
			}
		}
		add(&f, "-A %s -i %s -j DROP", ChainForward, it.Name)
	}
	// Nothing else may be routed into a tunnel (e.g. hub LAN hosts or other
	// interfaces) unless one of the grants above matched first.
	for _, it := range r.Ifaces {
		add(&f, "-A %s -o %s -j DROP", ChainForward, it.Name)
	}
	// Static catch-all, independent of state.
	for _, pat := range OwnedPatterns {
		add(&f, "-A %s -i %s -j DROP", ChainForward, pat)
		add(&f, "-A %s -o %s -j DROP", ChainForward, pat)
	}
	// Tunnel peers may only reach the hub itself with replies and ICMP
	// (ping the hub address). The API, SSH and any other local service are
	// not reachable through a tunnel. WireGuard UDP arrives on the public
	// interface and is not affected.
	for _, pat := range OwnedPatterns {
		add(&in, "-A %s -i %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ChainInput, pat)
		add(&in, "-A %s -i %s -p icmp -m icmp --icmp-type 8 -j ACCEPT", ChainInput, pat)
		add(&in, "-A %s -i %s -j DROP", ChainInput, pat)
	}
	for _, it := range r.Ifaces {
		for _, dir := range []string{"-o", "-i"} {
			if r.MSSMode == "pmtu" {
				add(&m, "-A %s %s %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ChainMSS, dir, it.Name)
				continue
			}
			mss := it.MTU - 40
			// Only lower the MSS, never raise a smaller one chosen by the host.
			add(&m, "-A %s %s %s -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss %d:65535 -j TCPMSS --set-mss %d", ChainMSS, dir, it.Name, mss+1, mss)
		}
	}

	var b strings.Builder
	type chain struct {
		name  string
		rules []string
	}
	section := func(table string, chains ...chain) {
		fmt.Fprintf(&b, "*%s\n", table)
		for _, c := range chains {
			fmt.Fprintf(&b, ":%s - [0:0]\n-F %s\n", c.name, c.name)
		}
		for _, c := range chains {
			for _, l := range c.rules {
				b.WriteString(l)
				b.WriteByte('\n')
			}
		}
		b.WriteString("COMMIT\n")
	}
	section("filter", chain{ChainForward, f}, chain{ChainInput, in})
	section("nat", chain{ChainNAT, n})
	section("mangle", chain{ChainMSS, m})
	return b.String()
}

// Jump describes the hook rule linking a built-in chain to an owned chain.
type Jump struct {
	Table, From, To string
}

var Jumps = []Jump{
	{"filter", "FORWARD", ChainForward},
	{"filter", "INPUT", ChainInput},
	{"nat", "POSTROUTING", ChainNAT},
	{"mangle", "FORWARD", ChainMSS},
}

func quote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return '-'
		}
		return r
	}, s)
	if len(s) > 250 {
		s = s[:250]
	}
	return `"` + s + `"`
}
