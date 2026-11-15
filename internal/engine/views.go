package engine

import (
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

// Runtime is the live WireGuard view of one peer.
type Runtime struct {
	Status        string     `json:"status"` // online, offline, disabled, unknown
	Endpoint      string     `json:"endpoint,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RxBytes       int64      `json:"rx_bytes"`
	TxBytes       int64      `json:"tx_bytes"`
}

// SiteView is the public (secret-free) representation of a site.
type SiteView struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Iface              string    `json:"iface"`
	Subnet             string    `json:"subnet"`
	HubAddress         string    `json:"hub_address"`
	VirtualIP          string    `json:"virtual_ip"`
	Port               int       `json:"port"`
	MTU                int       `json:"mtu"`
	ServerPublicKey    string    `json:"server_public_key"`
	PeerPublicKey      string    `json:"peer_public_key"`
	LocalSubnets       []string  `json:"local_subnets"`
	AllowAllSubnets    bool      `json:"allow_all_subnets"`
	ExposedSubnets     []string  `json:"exposed_subnets"`
	CanAccessServerLAN bool      `json:"can_access_server_lan"`
	AllowedTargetSites []string  `json:"allowed_target_sites"`
	TunnelMode         string    `json:"tunnel_mode"`
	Enabled            bool      `json:"enabled"`
	AllowedIPs         []string  `json:"peer_allowed_ips"`
	Runtime            Runtime   `json:"runtime"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ClientView is the public representation of a client.
type ClientView struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	Group          string    `json:"group"`
	Iface          string    `json:"iface"`
	Address        string    `json:"address"`
	PublicKey      string    `json:"public_key"`
	TargetSites    []string  `json:"target_sites"`
	AllowServerLAN bool      `json:"allow_server_lan"`
	TunnelMode     string    `json:"tunnel_mode"`
	DNS            []string  `json:"dns"`
	Enabled        bool      `json:"enabled"`
	AllowedIPs     []string  `json:"allowed_ips"`
	Runtime        Runtime   `json:"runtime"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type GroupView struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Iface           string    `json:"iface"`
	Subnet          string    `json:"subnet"`
	Port            int       `json:"port"`
	MTU             int       `json:"mtu"`
	ServerPublicKey string    `json:"server_public_key"`
	Clients         int       `json:"clients"`
	CreatedAt       time.Time `json:"created_at"`
}

type peerCache map[string]map[string]wireguard.PeerStatus

func (e *Engine) peers(cache peerCache, iface string) map[string]wireguard.PeerStatus {
	if p, ok := cache[iface]; ok {
		return p
	}
	p, err := e.wg.Peers(iface)
	if err != nil {
		p = nil
	}
	cache[iface] = p
	return p
}

func runtimeOf(peers map[string]wireguard.PeerStatus, pub string, enabled bool, now time.Time) Runtime {
	if !enabled {
		return Runtime{Status: "disabled"}
	}
	if peers == nil {
		return Runtime{Status: "unknown"}
	}
	p, ok := peers[pub]
	if !ok {
		return Runtime{Status: "unknown"}
	}
	r := Runtime{Status: "offline", Endpoint: p.Endpoint, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
	if !p.LastHandshake.IsZero() {
		t := p.LastHandshake.UTC()
		r.LastHandshake = &t
	}
	if wireguard.Online(p.LastHandshake, now) {
		r.Status = "online"
	}
	return r
}

func (e *Engine) siteView(st *config.State, s *config.Site, cache peerCache, now time.Time) SiteView {
	exposed := s.ExposedSubnets
	if exposed == nil {
		exposed = []string{}
	}
	targets := s.AllowedTargetSites
	if targets == nil {
		targets = []string{}
	}
	return SiteView{
		ID: s.ID, Name: s.Name, Iface: s.Iface, Subnet: mustPrefix(s.Subnet).Masked().String(),
		HubAddress: HubAddr(s.Subnet).Addr().String(), VirtualIP: SitePeerAddr(s.Subnet).String(),
		Port: s.Port, MTU: s.MTU, ServerPublicKey: s.ServerPublicKey, PeerPublicKey: s.PeerPublicKey,
		LocalSubnets: s.LocalSubnets, AllowAllSubnets: s.AllowAllSubnets, ExposedSubnets: exposed,
		CanAccessServerLAN: s.CanAccessServerLAN, AllowedTargetSites: targets,
		TunnelMode: s.TunnelMode, Enabled: s.Enabled, AllowedIPs: e.SiteAllowedIPs(st, s),
		Runtime:   runtimeOf(e.peers(cache, s.Iface), s.PeerPublicKey, s.Enabled, now),
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func (e *Engine) clientView(st *config.State, c *config.Client, cache peerCache, now time.Time) ClientView {
	iface := ""
	if g := st.Group(c.GroupID); g != nil {
		iface = g.Iface
	}
	return ClientView{
		ID: c.ID, Username: c.Username, Group: c.GroupID, Iface: iface, Address: c.Address,
		PublicKey: c.PublicKey, TargetSites: c.TargetSites, AllowServerLAN: c.AllowServerLAN,
		TunnelMode: c.TunnelMode, DNS: c.DNS, Enabled: c.Enabled,
		AllowedIPs: e.ClientAllowedIPs(st, c),
		Runtime:    runtimeOf(e.peers(cache, iface), c.PublicKey, c.Enabled, now),
		CreatedAt:  c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (e *Engine) ListSites() []SiteView {
	st, cache, now := e.Snapshot(), peerCache{}, time.Now()
	out := make([]SiteView, 0, len(st.Sites))
	for _, s := range st.Sites {
		out = append(out, e.siteView(st, s, cache, now))
	}
	return out
}

func (e *Engine) GetSite(id string) (SiteView, error) {
	st := e.Snapshot()
	s := st.Site(id)
	if s == nil {
		return SiteView{}, notFound("site", id)
	}
	return e.siteView(st, s, peerCache{}, time.Now()), nil
}

func (e *Engine) ListClients() []ClientView {
	st, cache, now := e.Snapshot(), peerCache{}, time.Now()
	out := make([]ClientView, 0, len(st.Clients))
	for _, c := range st.Clients {
		out = append(out, e.clientView(st, c, cache, now))
	}
	return out
}

func (e *Engine) GetClient(id string) (ClientView, error) {
	st := e.Snapshot()
	c := st.Client(id)
	if c == nil {
		return ClientView{}, notFound("client", id)
	}
	return e.clientView(st, c, peerCache{}, time.Now()), nil
}

func (e *Engine) ListGroups() []GroupView {
	st := e.Snapshot()
	out := make([]GroupView, 0, len(st.Groups))
	for _, g := range st.Groups {
		n := 0
		for _, c := range st.Clients {
			if c.GroupID == g.ID {
				n++
			}
		}
		out = append(out, GroupView{ID: g.ID, Name: g.Name, Iface: g.Iface, Subnet: mustPrefix(g.Subnet).Masked().String(),
			Port: g.Port, MTU: g.MTU, ServerPublicKey: g.ServerPublicKey, Clients: n, CreatedAt: g.CreatedAt})
	}
	return out
}

// SiteView/ClientView by ID after a mutation.
func (e *Engine) SiteViewOf(s *config.Site) SiteView {
	v, _ := e.GetSite(s.ID)
	return v
}

func (e *Engine) ClientViewOf(c *config.Client) ClientView {
	v, _ := e.GetClient(c.ID)
	return v
}

func (e *Engine) GroupViewOf(g *config.Group) GroupView {
	for _, v := range e.ListGroups() {
		if v.ID == g.ID {
			return v
		}
	}
	return GroupView{}
}
