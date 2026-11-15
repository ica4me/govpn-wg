package engine

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

// ClientInput is the body of POST/PUT /api/v1/clients.
type ClientInput struct {
	Username       *string   `json:"username"`
	Group          *string   `json:"group"`
	TargetSites    *[]string `json:"target_sites"`
	AllowServerLAN *bool     `json:"allow_server_lan"`
	TunnelMode     *string   `json:"tunnel_mode"`
	DNS            *[]string `json:"dns"`
	Enabled        *bool     `json:"enabled"`
	RotateKeys     bool      `json:"rotate_keys"`
}

// GroupInput is the body of POST/PUT /api/v1/groups.
type GroupInput struct {
	Name *string `json:"name"`
	Port *int    `json:"port"`
	MTU  *int    `json:"mtu"`
}

func (e *Engine) CreateClient(in ClientInput) (*config.Client, error) {
	if in.Username == nil || !config.ValidUsername(*in.Username) {
		return nil, bad("username: 1-64 chars of A-Z a-z 0-9 _ . @ -")
	}
	var created *config.Client
	err := e.mutate(func(st *config.State) error {
		for _, c := range st.Clients {
			if c.Username == *in.Username {
				return conflict("username %q already exists", *in.Username)
			}
		}
		groupID := DefaultGroup
		if in.Group != nil && *in.Group != "" {
			groupID = *in.Group
		}
		g := st.Group(groupID)
		if g == nil {
			if groupID != DefaultGroup {
				return notFound("group", groupID)
			}
			name := DefaultGroup
			var err error
			if g, err = e.newGroup(st, GroupInput{Name: &name}); err != nil {
				return err
			}
		}
		keys, err := wireguard.GenerateKeys()
		if err != nil {
			return err
		}
		psk, err := wireguard.GeneratePSK()
		if err != nil {
			return err
		}
		taken := map[string]bool{}
		for _, c := range st.Clients {
			if c.GroupID == g.ID {
				taken[c.Address] = true
			}
		}
		addr, err := wireguard.NextHost(mustPrefix(g.Subnet).Masked(), 2, taken)
		if err != nil {
			return conflict("%v", err)
		}
		now := time.Now().UTC()
		c := &config.Client{
			ID: config.Slug(*in.Username), Username: *in.Username, GroupID: g.ID, Address: addr.String(),
			PrivateKey: keys.Private, PublicKey: keys.Public, PresharedKey: psk,
			TunnelMode: config.ModeSplit, DNS: e.cfg.DNS, Enabled: true, TargetSites: []string{},
			AllowServerLAN: true, // default: clients may reach the LANs behind the hub
			CreatedAt:      now, UpdatedAt: now,
		}
		if c.ID == "" || st.Client(c.ID) != nil {
			return conflict("client id %q already exists", c.ID)
		}
		if err := applyClientInput(c, in); err != nil {
			return err
		}
		st.Clients = append(st.Clients, c)
		created = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.log.Info("client created", "id", created.ID, "group", created.GroupID, "address", created.Address)
	return created, nil
}

func (e *Engine) UpdateClient(id string, in ClientInput) (*config.Client, error) {
	if in.Group != nil {
		return nil, bad("group cannot be changed; delete and recreate the client")
	}
	var updated *config.Client
	err := e.mutate(func(st *config.State) error {
		c := st.Client(id)
		if c == nil {
			return notFound("client", id)
		}
		if in.Username != nil && *in.Username != c.Username {
			return bad("username cannot be changed")
		}
		if err := applyClientInput(c, in); err != nil {
			return err
		}
		if in.RotateKeys {
			keys, err := wireguard.GenerateKeys()
			if err != nil {
				return err
			}
			psk, err := wireguard.GeneratePSK()
			if err != nil {
				return err
			}
			c.PrivateKey, c.PublicKey, c.PresharedKey = keys.Private, keys.Public, psk
		}
		c.UpdatedAt = time.Now().UTC()
		updated = c
		return nil
	})
	return updated, err
}

func (e *Engine) DeleteClient(id string) error {
	return e.mutate(func(st *config.State) error {
		idx := slices.IndexFunc(st.Clients, func(c *config.Client) bool { return c.ID == id })
		if idx < 0 {
			return notFound("client", id)
		}
		st.Clients = slices.Delete(st.Clients, idx, idx+1)
		return nil
	})
}

func applyClientInput(c *config.Client, in ClientInput) error {
	if in.TargetSites != nil {
		c.TargetSites = dedupe(*in.TargetSites)
	}
	if in.AllowServerLAN != nil {
		c.AllowServerLAN = *in.AllowServerLAN
	}
	if in.TunnelMode != nil {
		if *in.TunnelMode != config.ModeSplit && *in.TunnelMode != config.ModeFull {
			return bad("tunnel_mode must be split or full")
		}
		c.TunnelMode = *in.TunnelMode
	}
	if in.DNS != nil {
		var out []string
		for _, d := range *in.DNS {
			a, err := netip.ParseAddr(d)
			if err != nil {
				return bad("dns: %q is not an IP address", d)
			}
			out = append(out, a.String())
		}
		if len(out) > 4 {
			return bad("dns: at most 4 servers")
		}
		c.DNS = out
	}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	return nil
}

// Groups ----------------------------------------------------------------

func (e *Engine) CreateGroup(in GroupInput) (*config.Group, error) {
	if in.Name == nil || !config.ValidName(*in.Name) {
		return nil, bad("name: 1-64 chars of A-Z a-z 0-9 space _ . @ -")
	}
	var created *config.Group
	err := e.mutate(func(st *config.State) error {
		g, err := e.newGroup(st, in)
		created = g
		return err
	})
	return created, err
}

func (e *Engine) newGroup(st *config.State, in GroupInput) (*config.Group, error) {
	id := config.Slug(*in.Name)
	if id == "" {
		return nil, bad("name must contain letters or digits")
	}
	if st.Group(id) != nil {
		return nil, conflict("group %q already exists", id)
	}
	keys, err := wireguard.GenerateKeys()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	g := &config.Group{ID: id, Name: *in.Name, ServerPrivateKey: keys.Private, ServerPublicKey: keys.Public,
		MTU: e.cfg.DefaultMTU, CreatedAt: now, UpdatedAt: now}
	if in.MTU != nil {
		if err := config.ValidMTU(*in.MTU); err != nil {
			return nil, bad("mtu: %v", err)
		}
		g.MTU = *in.MTU
	}
	if g.Iface, err = e.newIface(st, GroupPrefix, g.ID); err != nil {
		return nil, err
	}
	if g.Subnet, err = e.newSubnet(st, nil); err != nil {
		return nil, err
	}
	if in.Port != nil {
		if err := e.checkPort(st, *in.Port, ""); err != nil {
			return nil, err
		}
		g.Port = *in.Port
	} else if g.Port, err = e.newPort(st); err != nil {
		return nil, err
	}
	st.Groups = append(st.Groups, g)
	return g, nil
}

func (e *Engine) UpdateGroup(id string, in GroupInput) (*config.Group, error) {
	var updated *config.Group
	err := e.mutate(func(st *config.State) error {
		g := st.Group(id)
		if g == nil {
			return notFound("group", id)
		}
		if in.Name != nil {
			if !config.ValidName(*in.Name) {
				return bad("name: 1-64 chars of A-Z a-z 0-9 space _ . @ -")
			}
			g.Name = *in.Name
		}
		if in.MTU != nil {
			if err := config.ValidMTU(*in.MTU); err != nil {
				return bad("mtu: %v", err)
			}
			g.MTU = *in.MTU
		}
		if in.Port != nil && *in.Port != g.Port {
			if err := e.checkPort(st, *in.Port, g.Iface); err != nil {
				return err
			}
			g.Port = *in.Port
		}
		g.UpdatedAt = time.Now().UTC()
		updated = g
		return nil
	})
	return updated, err
}

func (e *Engine) DeleteGroup(id string) error {
	return e.mutate(func(st *config.State) error {
		idx := slices.IndexFunc(st.Groups, func(g *config.Group) bool { return g.ID == id })
		if idx < 0 {
			return notFound("group", id)
		}
		for _, c := range st.Clients {
			if c.GroupID == id {
				return conflict("group %q still has clients", id)
			}
		}
		st.Groups = slices.Delete(st.Groups, idx, idx+1)
		return nil
	})
}

// validate checks cross-object invariants on the whole candidate state.
func (e *Engine) validate(st *config.State) error {
	if err := st.Check(); err != nil {
		return bad("invalid state: %v", err)
	}
	type owner struct {
		p    netip.Prefix
		what string
	}
	var nets []owner
	// A site LAN must never replace or cover a route/address the host
	// already uses (uplink, management network, Docker...), or the hub
	// could cut itself off. More specific carve-outs of a broad host route
	// are allowed: the kernel picks the longest prefix without replacing.
	host, err := e.wg.UsedPrefixes(Owned)
	if err != nil {
		return fmt.Errorf("inspect host networks: %w", err)
	}
	{
		for _, s := range st.Sites {
			for _, l := range prefixes(s.LocalSubnets) {
				for _, h := range host {
					if l.Overlaps(h) && l.Bits() <= h.Bits() {
						return conflict("site %s: local subnet %s overlaps host network %s", s.ID, l, h)
					}
				}
			}
		}
	}
	for _, p := range e.cfg.ServerLAN {
		nets = append(nets, owner{p, "server LAN"})
	}
	ifaces, ports := map[string]bool{}, map[int]string{}
	for _, s := range st.Sites {
		nets = append(nets, owner{mustPrefix(s.Subnet).Masked(), "tunnel " + s.Iface})
		for _, l := range prefixes(s.LocalSubnets) {
			if config.InPool(l) {
				return bad("site %s: local subnet %s overlaps the tunnel pool 172.31.201-250.0/24", s.ID, l)
			}
			nets = append(nets, owner{l, "site " + s.ID})
		}
		local := prefixes(s.LocalSubnets)
		for _, x := range prefixes(s.ExposedSubnets) {
			inside := false
			for _, l := range local {
				if l.Contains(x.Addr()) && l.Bits() <= x.Bits() {
					inside = true
				}
			}
			if !inside {
				return bad("site %s: exposed subnet %s is not inside local_subnets", s.ID, x)
			}
		}
		for _, t := range s.AllowedTargetSites {
			if t == s.ID {
				return bad("site %s: allowed_target_sites cannot contain itself", s.ID)
			}
			if st.Site(t) == nil {
				return bad("site %s: target site %q does not exist", s.ID, t)
			}
		}
		if ifaces[s.Iface] {
			return conflict("duplicate interface %s", s.Iface)
		}
		ifaces[s.Iface] = true
		if o, ok := ports[s.Port]; ok {
			return conflict("UDP port %d used by %s and %s", s.Port, o, s.Iface)
		}
		ports[s.Port] = s.Iface
	}
	for _, g := range st.Groups {
		nets = append(nets, owner{mustPrefix(g.Subnet).Masked(), "tunnel " + g.Iface})
		if ifaces[g.Iface] {
			return conflict("duplicate interface %s", g.Iface)
		}
		ifaces[g.Iface] = true
		if o, ok := ports[g.Port]; ok {
			return conflict("UDP port %d used by %s and %s", g.Port, o, g.Iface)
		}
		ports[g.Port] = g.Iface
	}
	for _, n := range nets {
		if !strings.HasPrefix(n.what, "tunnel ") {
			continue
		}
		for _, h := range host {
			if n.p.Overlaps(h) && n.p.Bits() <= h.Bits() {
				return conflict("%s (%s) overlaps host network %s", n.p, n.what, h)
			}
		}
	}
	for i := range nets {
		for j := i + 1; j < len(nets); j++ {
			if nets[i].p.Overlaps(nets[j].p) {
				return conflict("%s (%s) overlaps %s (%s)", nets[i].p, nets[i].what, nets[j].p, nets[j].what)
			}
		}
	}
	for _, c := range st.Clients {
		if st.Group(c.GroupID) == nil {
			return bad("client %s: group %q does not exist", c.ID, c.GroupID)
		}
		for _, t := range c.TargetSites {
			if st.Site(t) == nil {
				return bad("client %s: target site %q does not exist", c.ID, t)
			}
		}
	}
	return nil
}
