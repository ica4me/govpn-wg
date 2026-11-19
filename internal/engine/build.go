package engine

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("corrupt prefix in state: %q", s))
	}
	return p
}

func prefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		out = append(out, mustPrefix(s))
	}
	return out
}

func host32(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, 32) }

// HubAddr returns the hub (.1) address of an interface subnet, with mask.
func HubAddr(subnet string) netip.Prefix {
	p := mustPrefix(subnet)
	return netip.PrefixFrom(config.HostIn(p, 1), p.Bits())
}

// SitePeerAddr returns the site's tunnel address (.2).
func SitePeerAddr(subnet string) netip.Addr { return config.HostIn(mustPrefix(subnet), 2) }

// Exposed returns the subnets of a site other peers may be granted:
// every local subnet when allow_all_subnets is true, otherwise exactly
// exposed_subnets (an empty list exposes nothing).
func Exposed(s *config.Site) []netip.Prefix {
	if s.AllowAllSubnets {
		return prefixes(s.LocalSubnets)
	}
	return prefixes(s.ExposedSubnets)
}

// build derives kernel specs and the firewall rule set from state.
func (e *Engine) build(st *config.State) ([]wireguard.IfaceSpec, firewall.Ruleset, error) {
	var specs []wireguard.IfaceSpec
	rules := firewall.Ruleset{PublicIf: e.PublicIf(), MSSMode: e.cfg.MSSMode}
	sites := map[string]*config.Site{}
	for _, s := range st.Sites {
		sites[s.ID] = s
	}
	serverLAN := e.ServerLAN()

	for _, s := range st.Sites {
		spec := wireguard.IfaceSpec{
			Name: s.Iface, PrivateKey: s.ServerPrivateKey, Port: s.Port, MTU: s.MTU,
			Address: HubAddr(s.Subnet),
		}
		fw := firewall.Iface{Name: s.Iface, MTU: s.MTU}
		if s.Enabled {
			lan := prefixes(s.LocalSubnets)
			allowed := append([]netip.Prefix{host32(SitePeerAddr(s.Subnet))}, lan...)
			spec.Peers = []wireguard.PeerSpec{{
				PublicKey: s.PeerPublicKey, PresharedKey: s.PresharedKey,
				AllowedIPs: allowed,
			}}
			spec.Routes = lan
			for _, id := range s.AllowedTargetSites {
				t := sites[id]
				if t == nil || !t.Enabled {
					continue
				}
				fw.Grants = append(fw.Grants, firewall.Grant{
					Comment: fmt.Sprintf("site %s -> site %s", s.ID, t.ID),
					Sources: allowed, Dests: Exposed(t),
				})
			}
			if s.CanAccessServerLAN && len(serverLAN) > 0 {
				fw.Grants = append(fw.Grants, firewall.Grant{
					Comment: fmt.Sprintf("site %s -> server lan", s.ID),
					Sources: allowed, Dests: serverLAN, Masquerade: e.cfg.LanNAT,
				})
			}
			if s.TunnelMode == config.ModeFull {
				fw.FullSources = allowed
			}
		}
		specs = append(specs, spec)
		rules.Ifaces = append(rules.Ifaces, fw)
	}

	groupClients := map[string][]*config.Client{}
	for _, c := range st.Clients {
		groupClients[c.GroupID] = append(groupClients[c.GroupID], c)
	}
	for _, g := range st.Groups {
		spec := wireguard.IfaceSpec{
			Name: g.Iface, PrivateKey: g.ServerPrivateKey, Port: g.Port, MTU: g.MTU,
			Address: HubAddr(g.Subnet),
		}
		fw := firewall.Iface{Name: g.Iface, MTU: g.MTU}
		for _, c := range groupClients[g.ID] {
			if !c.Enabled {
				continue
			}
			src := []netip.Prefix{host32(netip.MustParseAddr(c.Address))}
			spec.Peers = append(spec.Peers, wireguard.PeerSpec{
				PublicKey: c.PublicKey, PresharedKey: c.PresharedKey, AllowedIPs: src,
			})
			var dests []netip.Prefix
			for _, id := range c.TargetSites {
				if t := sites[id]; t != nil && t.Enabled {
					dests = append(dests, Exposed(t)...)
				}
			}
			if len(dests) > 0 {
				fw.Grants = append(fw.Grants, firewall.Grant{
					Comment: "client " + c.Username + " -> sites", Sources: src, Dests: dests,
				})
			}
			if c.AllowServerLAN && len(serverLAN) > 0 {
				fw.Grants = append(fw.Grants, firewall.Grant{
					Comment: "client " + c.Username + " -> server lan", Sources: src, Dests: serverLAN,
					Masquerade: e.cfg.LanNAT,
				})
			}
			// Every client may use the hub as an internet gateway, whatever
			// its configured tunnel_mode. Split is only the default profile
			// written to the download; a user may edit AllowedIPs to
			// 0.0.0.0/0 locally without an API change, so the server side
			// must already permit and NAT that traffic. The NonPublic drops
			// rendered for FullSources still keep LAN/private destinations
			// behind the explicit grants above.
			fw.FullSources = append(fw.FullSources, src...)
		}
		specs = append(specs, spec)
		rules.Ifaces = append(rules.Ifaces, fw)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	sort.Slice(rules.Ifaces, func(i, j int) bool { return rules.Ifaces[i].Name < rules.Ifaces[j].Name })
	return specs, rules, nil
}

// SiteAllowedIPs is the AllowedIPs list for the hub peer in a site config.
// Split: every tunnel subnet (so client and site tunnel sources are accepted),
// the exposed subnets of targets, the LANs of sites that may reach this one,
// and the server LAN when granted. Full: everything.
func (e *Engine) SiteAllowedIPs(st *config.State, s *config.Site) []string {
	if s.TunnelMode == config.ModeFull {
		// IPv4 only: the tunnel carries no IPv6, so ::/0 is never written
		// into a site profile.
		return []string{"0.0.0.0/0"}
	}
	set := map[netip.Prefix]bool{}
	for _, p := range wireguard.PoolSummary() {
		set[p] = true
	}
	for _, id := range s.AllowedTargetSites {
		if t := st.Site(id); t != nil {
			for _, p := range Exposed(t) {
				set[p] = true
			}
		}
	}
	for _, o := range st.Sites {
		if o.ID == s.ID {
			continue
		}
		for _, id := range o.AllowedTargetSites {
			if id == s.ID {
				for _, p := range prefixes(o.LocalSubnets) {
					set[p] = true
				}
			}
		}
	}
	if s.CanAccessServerLAN {
		for _, p := range e.ServerLAN() {
			set[p] = true
		}
	}
	return sortedPrefixes(set)
}

// ClientAllowedIPs is the AllowedIPs list in a client config.
func (e *Engine) ClientAllowedIPs(st *config.State, c *config.Client) []string {
	if c.TunnelMode == config.ModeFull {
		// IPv4 only: ::/0 would route native IPv6 into a tunnel that has no
		// IPv6 address or grants, while the profile no longer promises that
		// the client app blocks it. Leaving IPv6 out keeps it on the
		// client's own path and lets the Linux installer harden the link.
		return []string{"0.0.0.0/0"}
	}
	set := map[netip.Prefix]bool{}
	if g := st.Group(c.GroupID); g != nil {
		set[mustPrefix(g.Subnet).Masked()] = true
	}
	for _, id := range c.TargetSites {
		if t := st.Site(id); t != nil {
			for _, p := range Exposed(t) {
				set[p] = true
			}
		}
	}
	if c.AllowServerLAN {
		for _, p := range e.ServerLAN() {
			set[p] = true
		}
	}
	return sortedPrefixes(set)
}

func sortedPrefixes(set map[netip.Prefix]bool) []string {
	list := make([]netip.Prefix, 0, len(set))
	for p := range set {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		if c := list[i].Addr().Compare(list[j].Addr()); c != 0 {
			return c < 0
		}
		return list[i].Bits() < list[j].Bits()
	})
	out := make([]string, len(list))
	for i, p := range list {
		out[i] = p.String()
	}
	return out
}
