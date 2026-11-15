package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const StateVersion = 1

// ownedIfaceRe matches the only interface names the engine may manage.
var ownedIfaceRe = regexp.MustCompile(`^wg-[sc][0-9]{1,11}$`)

// Tunnel modes.
const (
	ModeSplit = "split"
	ModeFull  = "full"
)

// Site is one remote network (VPN-Hub spoke) with its own WireGuard interface.
type Site struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Iface string `json:"iface"`
	// Subnet is the interface /24 from the pool; hub uses .1, the site uses .2.
	Subnet string `json:"subnet"`
	Port   int    `json:"port"`
	MTU    int    `json:"mtu"`

	ServerPrivateKey string `json:"server_private_key"`
	ServerPublicKey  string `json:"server_public_key"`
	PeerPrivateKey   string `json:"peer_private_key"`
	PeerPublicKey    string `json:"peer_public_key"`
	PresharedKey     string `json:"preshared_key"`

	LocalSubnets       []string `json:"local_subnets"`
	AllowAllSubnets    bool     `json:"allow_all_subnets"`
	ExposedSubnets     []string `json:"exposed_subnets"`
	CanAccessServerLAN bool     `json:"can_access_server_lan"`
	AllowedTargetSites []string `json:"allowed_target_sites"`
	TunnelMode         string   `json:"tunnel_mode"`
	Enabled            bool     `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Group is a Client-to-Site interface shared by many clients.
type Group struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Iface  string `json:"iface"`
	Subnet string `json:"subnet"`
	Port   int    `json:"port"`
	MTU    int    `json:"mtu"`

	ServerPrivateKey string `json:"server_private_key"`
	ServerPublicKey  string `json:"server_public_key"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Client is a single road-warrior peer inside a Group.
type Client struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	GroupID  string `json:"group_id"`
	Address  string `json:"address"` // x.y.z.n inside the group subnet

	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`

	TargetSites    []string `json:"target_sites"`
	AllowServerLAN bool     `json:"allow_server_lan"`
	TunnelMode     string   `json:"tunnel_mode"`
	DNS            []string `json:"dns"`
	Enabled        bool     `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type State struct {
	Version int       `json:"version"`
	Sites   []*Site   `json:"sites"`
	Groups  []*Group  `json:"groups"`
	Clients []*Client `json:"clients"`
}

func (s *State) Site(id string) *Site {
	for _, x := range s.Sites {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (s *State) Group(id string) *Group {
	for _, x := range s.Groups {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (s *State) Client(id string) *Client {
	for _, x := range s.Clients {
		if x.ID == id {
			return x
		}
	}
	return nil
}

// Clone returns a deep copy; handlers mutate clones, never the live state.
func (s *State) Clone() *State {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	out := &State{}
	if err := json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}

// Sort keeps the file and API output deterministic.
func (s *State) Sort() {
	sort.Slice(s.Sites, func(i, j int) bool { return s.Sites[i].ID < s.Sites[j].ID })
	sort.Slice(s.Groups, func(i, j int) bool { return s.Groups[i].ID < s.Groups[j].ID })
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].ID < s.Clients[j].ID })
}

// Store persists State as JSON (mode 0600) with atomic replace and a .bak copy.
type Store struct {
	mu    sync.RWMutex
	path  string
	state *State
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &Store{path: filepath.Join(dir, "state.json"), state: &State{Version: StateVersion}}
	b, err := os.ReadFile(st.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return st, nil
	case err != nil:
		return nil, err
	}
	loaded := &State{}
	if err := json.Unmarshal(b, loaded); err != nil {
		return nil, fmt.Errorf("%s is corrupt (restore %s.bak): %w", st.path, st.path, err)
	}
	if loaded.Version > StateVersion {
		return nil, fmt.Errorf("%s was written by a newer govpn-wg (version %d)", st.path, loaded.Version)
	}
	if err := loaded.Check(); err != nil {
		return nil, fmt.Errorf("%s is invalid (fix it or restore %s.bak): %w", st.path, st.path, err)
	}
	loaded.Version = StateVersion
	st.state = loaded
	return st, nil
}

// Snapshot returns a deep copy of the current state.
func (st *Store) Snapshot() *State {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.state.Clone()
}

// Replace writes next to disk and swaps it in only after the write succeeded.
func (st *Store) Replace(next *State) error {
	if err := next.Check(); err != nil {
		return err
	}
	next.Sort()
	next.Version = StateVersion
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if old, err := os.ReadFile(st.path); err == nil {
		_ = writeAtomic(st.path+".bak", old)
	}
	if err := writeAtomic(st.path, append(b, '\n')); err != nil {
		return err
	}
	st.state = next.Clone()
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// Make the rename durable.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// WriteFileAtomic is exported for other packages (sysctl file, secrets).
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(path, data); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// Check verifies the fields the engine parses without error handling, so a
// hand-edited or damaged state file fails at load instead of panicking.
func (s *State) Check() error {
	if s == nil {
		return errors.New("null state")
	}
	ids, ifaces, ports := map[string]bool{}, map[string]bool{}, map[int]bool{}
	identity := func(kind, id, iface, subnet string, port, mtu int) error {
		key := kind + ":" + id
		if id == "" || ids[key] {
			return fmt.Errorf("%s: empty or duplicate id %q", kind, id)
		}
		ids[key] = true
		// Only interfaces this engine owns may reach the kernel: a damaged
		// state must never point at eth0 (or any host link).
		want := "wg-s"
		if kind == "group" {
			want = "wg-c"
		}
		if !ownedIfaceRe.MatchString(iface) || iface[:len(want)] != want || ifaces[iface] {
			return fmt.Errorf("%s: invalid or duplicate owned interface %q", key, iface)
		}
		ifaces[iface] = true
		if port < 1 || port > 65535 || ports[port] {
			return fmt.Errorf("%s: invalid or duplicate port %d", key, port)
		}
		ports[port] = true
		if err := ValidMTU(mtu); err != nil {
			return err
		}
		p, err := netip.ParsePrefix(subnet)
		if err != nil || p.Bits() != 24 || !InPool(p) || p.Addr().As4()[3] != 1 {
			return fmt.Errorf("%s: subnet must be a hub /24 (.1) inside the tunnel pool", key)
		}
		return nil
	}
	// An empty mode is legacy state and behaves as split; anything else
	// unrecognised would silently disable the split/full firewall branch.
	mode := func(m string) bool { return m == "" || m == ModeSplit || m == ModeFull }
	for _, x := range s.Sites {
		if x == nil {
			return errors.New("null site")
		}
		if err := identity("site", x.ID, x.Iface, x.Subnet, x.Port, x.MTU); err != nil {
			return err
		}
		if !mode(x.TunnelMode) {
			return fmt.Errorf("site %s: invalid tunnel mode", x.ID)
		}
		for _, l := range append(append([]string{}, x.LocalSubnets...), x.ExposedSubnets...) {
			if _, err := ParseCIDR4(l); err != nil {
				return fmt.Errorf("site %s: %v", x.ID, err)
			}
		}
	}
	for _, g := range s.Groups {
		if g == nil {
			return errors.New("null group")
		}
		if err := identity("group", g.ID, g.Iface, g.Subnet, g.Port, g.MTU); err != nil {
			return err
		}
	}
	addresses := map[string]bool{}
	for _, c := range s.Clients {
		if c == nil {
			return errors.New("null client")
		}
		if c.ID == "" || ids["client:"+c.ID] || !mode(c.TunnelMode) {
			return fmt.Errorf("client %s: invalid identity or tunnel mode", c.ID)
		}
		ids["client:"+c.ID] = true
		a, err := netip.ParseAddr(c.Address)
		if err != nil || !a.Is4() {
			return fmt.Errorf("client %s: bad address %q", c.ID, c.Address)
		}
		g := s.Group(c.GroupID)
		if g == nil {
			return fmt.Errorf("client %s: unknown group", c.ID)
		}
		p, _ := netip.ParsePrefix(g.Subnet)
		if !p.Contains(a) || a.As4()[3] < 2 || a.As4()[3] == 255 || addresses[a.String()] {
			return fmt.Errorf("client %s: invalid or duplicate group address", c.ID)
		}
		addresses[a.String()] = true
	}
	return nil
}
