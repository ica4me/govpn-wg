package engine

import (
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

// SiteInput is the body of POST/PUT /api/v1/sites. Pointer fields make PUT a
// partial merge: omitted fields keep their stored value.
type SiteInput struct {
	Name               *string   `json:"name"`
	LocalSubnets       *[]string `json:"local_subnets"`
	AllowAllSubnets    *bool     `json:"allow_all_subnets"`
	ExposedSubnets     *[]string `json:"exposed_subnets"`
	CanAccessServerLAN *bool     `json:"can_access_server_lan"`
	AllowedTargetSites *[]string `json:"allowed_target_sites"`
	TunnelMode         *string   `json:"tunnel_mode"`
	Port               *int      `json:"port"`
	MTU                *int      `json:"mtu"`
	Enabled            *bool     `json:"enabled"`
	RotateKeys         bool      `json:"rotate_keys"`
}

func (e *Engine) CreateSite(in SiteInput) (*config.Site, error) {
	if in.Name == nil {
		return nil, bad("name is required")
	}
	if in.LocalSubnets == nil || len(*in.LocalSubnets) == 0 {
		return nil, bad("local_subnets is required (LAN behind the site)")
	}
	var created *config.Site
	err := e.mutate(func(st *config.State) error {
		id := config.Slug(*in.Name)
		if id == "" {
			return bad("name must contain letters or digits")
		}
		if st.Site(id) != nil {
			return conflict("site id %q already exists", id)
		}
		srv, err := wireguard.GenerateKeys()
		if err != nil {
			return err
		}
		peer, err := wireguard.GenerateKeys()
		if err != nil {
			return err
		}
		psk, err := wireguard.GeneratePSK()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		s := &config.Site{
			ID: id, ServerPrivateKey: srv.Private, ServerPublicKey: srv.Public,
			PeerPrivateKey: peer.Private, PeerPublicKey: peer.Public, PresharedKey: psk,
			AllowAllSubnets: true, TunnelMode: config.ModeSplit, Enabled: true,
			MTU: e.cfg.DefaultMTU, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.applySiteInput(st, s, in, true); err != nil {
			return err
		}
		if s.Iface, err = e.newIface(st, SitePrefix, s.ID); err != nil {
			return err
		}
		if s.Subnet, err = e.newSubnet(st, s.LocalSubnets); err != nil {
			return err
		}
		if s.Port == 0 {
			if s.Port, err = e.newPort(st); err != nil {
				return err
			}
		}
		st.Sites = append(st.Sites, s)
		created = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.log.Info("site created", "id", created.ID, "iface", created.Iface, "subnet", created.Subnet, "port", created.Port)
	return created, nil
}

func (e *Engine) UpdateSite(id string, in SiteInput) (*config.Site, error) {
	var updated *config.Site
	err := e.mutate(func(st *config.State) error {
		s := st.Site(id)
		if s == nil {
			return notFound("site", id)
		}
		if err := e.applySiteInput(st, s, in, false); err != nil {
			return err
		}
		if in.RotateKeys {
			peer, err := wireguard.GenerateKeys()
			if err != nil {
				return err
			}
			psk, err := wireguard.GeneratePSK()
			if err != nil {
				return err
			}
			s.PeerPrivateKey, s.PeerPublicKey, s.PresharedKey = peer.Private, peer.Public, psk
		}
		s.UpdatedAt = time.Now().UTC()
		updated = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (e *Engine) DeleteSite(id string) error {
	return e.mutate(func(st *config.State) error {
		idx := slices.IndexFunc(st.Sites, func(s *config.Site) bool { return s.ID == id })
		if idx < 0 {
			return notFound("site", id)
		}
		st.Sites = slices.Delete(st.Sites, idx, idx+1)
		// Drop dangling references so no rule points at a removed network.
		for _, s := range st.Sites {
			s.AllowedTargetSites = slices.DeleteFunc(s.AllowedTargetSites, func(x string) bool { return x == id })
		}
		for _, c := range st.Clients {
			c.TargetSites = slices.DeleteFunc(c.TargetSites, func(x string) bool { return x == id })
		}
		return nil
	})
}

func (e *Engine) applySiteInput(st *config.State, s *config.Site, in SiteInput, create bool) error {
	if in.Name != nil {
		if !config.ValidName(*in.Name) {
			return bad("name: 1-64 chars of A-Z a-z 0-9 space _ . @ -")
		}
		s.Name = *in.Name
	}
	if in.LocalSubnets != nil {
		nets, err := cidrList(*in.LocalSubnets, 1, 32, "local_subnets")
		if err != nil {
			return err
		}
		for _, n := range prefixes(nets) {
			if n.Bits() < 8 {
				return bad("local_subnets: %s is too broad (minimum /8)", n)
			}
		}
		s.LocalSubnets = nets
	}
	if in.AllowAllSubnets != nil {
		s.AllowAllSubnets = *in.AllowAllSubnets
	} else if in.ExposedSubnets != nil {
		// Sending an explicit exposure list means "only these".
		s.AllowAllSubnets = false
	}
	if in.ExposedSubnets != nil {
		nets, err := cidrList(*in.ExposedSubnets, 0, 32, "exposed_subnets")
		if err != nil {
			return err
		}
		s.ExposedSubnets = nets
	}
	if in.CanAccessServerLAN != nil {
		s.CanAccessServerLAN = *in.CanAccessServerLAN
	}
	if in.AllowedTargetSites != nil {
		s.AllowedTargetSites = dedupe(*in.AllowedTargetSites)
	}
	if in.TunnelMode != nil {
		if *in.TunnelMode != config.ModeSplit && *in.TunnelMode != config.ModeFull {
			return bad("tunnel_mode must be split or full")
		}
		s.TunnelMode = *in.TunnelMode
	}
	if in.MTU != nil {
		if err := config.ValidMTU(*in.MTU); err != nil {
			return bad("mtu: %v", err)
		}
		s.MTU = *in.MTU
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.Port != nil && *in.Port != s.Port {
		if err := e.checkPort(st, *in.Port, s.Iface); err != nil {
			return err
		}
		s.Port = *in.Port
	}
	return nil
}

func cidrList(list []string, min, max int, field string) ([]string, error) {
	if len(list) < min || len(list) > max {
		return nil, bad("%s: %d-%d IPv4 CIDRs", field, min, max)
	}
	var out []string
	for _, s := range list {
		p, err := config.ParseCIDR4(s)
		if err != nil {
			return nil, bad("%s: %v", field, err)
		}
		if !slices.Contains(out, p.String()) {
			out = append(out, p.String())
		}
	}
	return out, nil
}

func dedupe(list []string) []string {
	out := []string{}
	for _, s := range list {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// newIface returns a free interface name derived from the site/group ID:
// prefix + "-" + up to 10 slug chars (kernel limit 15), with a numeric
// suffix on collision ("wg-s-kantor-pus", "wg-s-kantor-p2"). Names already
// present on the host are skipped so a foreign link is never adopted.
func (e *Engine) newIface(st *config.State, prefix, id string) (string, error) {
	taken := map[string]bool{}
	for _, s := range st.Sites {
		taken[s.Iface] = true
	}
	for _, g := range st.Groups {
		taken[g.Iface] = true
	}
	name := wireguard.NamedIface(prefix+"-", id, 15, func(n string) bool {
		if taken[n] {
			return true
		}
		_, err := net.InterfaceByName(n)
		return err == nil
	})
	if name == "" || !Owned(name) {
		return "", conflict("no free interface name for %q", id)
	}
	return name, nil
}

// newSubnet picks a random free /24 that collides with nothing known.
func (e *Engine) newSubnet(st *config.State, extra []string) (string, error) {
	host, err := e.wg.UsedPrefixes(Owned)
	if err != nil {
		return "", err
	}
	// Supernets such as 172.16.0.0/12 (Docker, VPC) would block the whole
	// pool; a more specific /24 route still wins, so only count > /16.
	var used []netip.Prefix
	for _, p := range host {
		if p.Bits() > 16 {
			used = append(used, p)
		}
	}
	for _, s := range st.Sites {
		used = append(used, mustPrefix(s.Subnet).Masked())
		used = append(used, prefixes(s.LocalSubnets)...)
	}
	for _, g := range st.Groups {
		used = append(used, mustPrefix(g.Subnet).Masked())
	}
	used = append(used, e.cfg.ServerLAN...)
	used = append(used, prefixes(extra)...)
	p, err := wireguard.AllocateSubnet(used)
	if err != nil {
		return "", conflict("%v", err)
	}
	return netip.PrefixFrom(config.HostIn(p, 1), 24).String(), nil
}

func (e *Engine) statePorts(st *config.State, except string) map[int]bool {
	taken := map[int]bool{}
	for _, s := range st.Sites {
		if s.Iface != except {
			taken[s.Port] = true
		}
	}
	for _, g := range st.Groups {
		if g.Iface != except {
			taken[g.Port] = true
		}
	}
	return taken
}

func (e *Engine) newPort(st *config.State) (int, error) {
	taken := e.statePorts(st, "")
	for p := range e.portsInUse() {
		taken[p] = true
	}
	// Ports of our own interfaces are already in taken via state.
	p, err := wireguard.AllocatePort(e.cfg.BasePort, taken)
	if err != nil {
		return 0, conflict("%v", err)
	}
	return p, nil
}

func (e *Engine) checkPort(st *config.State, port int, self string) error {
	if port < 1 || port > 65535 {
		return bad("port must be 1-65535")
	}
	if e.statePorts(st, self)[port] {
		return conflict("UDP port %d is used by another govpn-wg interface", port)
	}
	if self == "" && e.portsInUse()[port] {
		return conflict("UDP port %d is already bound on this host", port)
	}
	return nil
}
