package engine

import (
	"github.com/ica4me/govpn-wg/internal/config"
	"net/netip"
	"strconv"

	"github.com/ica4me/govpn-wg/internal/generator"
)

// SitePeer collects everything the site gateway artifacts need.
func (e *Engine) SitePeer(id string) (generator.Peer, error) {
	st := e.Snapshot()
	s := st.Site(id)
	if s == nil {
		return generator.Peer{}, notFound("site", id)
	}
	if e.Endpoint() == "" {
		return generator.Peer{}, conflict("server endpoint unknown: set GOVPN_ENDPOINT")
	}
	subnet := mustPrefix(s.Subnet)
	return generator.Peer{
		Kind: "site", Name: s.Name, FileName: generator.SafeFileName(s.ID),
		Address:    SitePeerAddr(s.Subnet).String() + "/" + strconv.Itoa(subnet.Bits()),
		PrivateKey: s.PeerPrivateKey, ServerKey: s.ServerPublicKey, PSK: s.PresharedKey,
		Endpoint:   generator.HostPort(e.Endpoint(), s.Port),
		AllowedIPs: e.SiteAllowedIPs(st, s), MTU: s.MTU, Keepalive: e.cfg.Keepalive,
		TunnelMode: s.TunnelMode, LocalLANs: s.LocalSubnets, Iface: "wg-hub",
	}, nil
}

// ClientPeer collects everything the client artifacts need.
func (e *Engine) ClientPeer(id string) (generator.Peer, error) {
	st := e.Snapshot()
	c := st.Client(id)
	if c == nil {
		return generator.Peer{}, notFound("client", id)
	}
	g := st.Group(c.GroupID)
	if g == nil {
		return generator.Peer{}, notFound("group", c.GroupID)
	}
	if e.Endpoint() == "" {
		return generator.Peer{}, conflict("server endpoint unknown: set GOVPN_ENDPOINT")
	}
	allowed := e.ClientAllowedIPs(st, c)
	dns := effectiveDNS(c.TunnelMode, c.DNS, allowed)
	return generator.Peer{
		Kind: "client", Name: c.Username, FileName: generator.SafeFileName(c.Username),
		Address:    c.Address + "/32",
		PrivateKey: c.PrivateKey, ServerKey: g.ServerPublicKey, PSK: c.PresharedKey,
		Endpoint:   generator.HostPort(e.Endpoint(), g.Port),
		AllowedIPs: allowed, DNS: dns, MTU: g.MTU, Keepalive: e.cfg.Keepalive,
		TunnelMode: c.TunnelMode, Iface: "govpn",
	}, nil
}

// effectiveDNS decides which DNS servers go into a client config.
//
// A DNS= line makes wg-quick (and most WireGuard apps) take over the system
// resolver. In split mode that is only correct when the resolver is reachable
// through the tunnel; a public resolver like 1.1.1.1 outside AllowedIPs would
// capture every query (systemd-resolved marks the link as the "~." default
// route) and break name resolution for normal traffic. So split mode keeps
// only resolvers inside AllowedIPs, full mode keeps all of them.
func effectiveDNS(mode string, dns, allowed []string) []string {
	if mode == config.ModeFull {
		return dns
	}
	var prefixes []netip.Prefix
	for _, a := range allowed {
		if p, err := netip.ParsePrefix(a); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	var out []string
	for _, d := range dns {
		addr, err := netip.ParseAddr(d)
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(addr) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}
