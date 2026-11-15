//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RouteProtocol tags routes created by govpn-wg so reconcile only touches
// its own entries (see /etc/iproute2/rt_protos, values 192-252 are free).
const RouteProtocol = netlink.RouteProtocol(222)

// Kernel is the netlink-backed Manager.
type Kernel struct {
	client *wgctrl.Client
}

func NewKernel() (*Kernel, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return &Kernel{client: c}, nil
}

func (k *Kernel) Close() error { return k.client.Close() }

func (k *Kernel) Sync(specs []IfaceSpec, owned func(string) bool) error {
	want := map[string]bool{}
	var errs []error
	for _, s := range specs {
		want[s.Name] = true
		if err := k.ensure(s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, l := range links {
		name := l.Attrs().Name
		if l.Type() == "wireguard" && owned(name) && !want[name] {
			if err := netlink.LinkDel(l); err != nil {
				errs = append(errs, fmt.Errorf("delete %s: %w", name, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (k *Kernel) ensure(s IfaceSpec) error {
	link, err := netlink.LinkByName(s.Name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if !errors.As(err, &nf) {
			return err
		}
		la := netlink.NewLinkAttrs()
		la.Name = s.Name
		la.MTU = s.MTU
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
			return fmt.Errorf("create link (is the wireguard module available?): %w", err)
		}
		if link, err = netlink.LinkByName(s.Name); err != nil {
			return err
		}
	} else if link.Type() != "wireguard" {
		return fmt.Errorf("interface exists but is %q, not wireguard", link.Type())
	}
	if link.Attrs().MTU != s.MTU {
		if err := netlink.LinkSetMTU(link, s.MTU); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	if err := k.syncAddress(link, s.Address); err != nil {
		return err
	}
	if err := k.syncDevice(s); err != nil {
		return err
	}
	if err := disableIPv6(s.Name); err != nil {
		return err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("link up: %w", err)
		}
	}
	return k.syncRoutes(link, s.Routes)
}

func (k *Kernel) syncAddress(link netlink.Link, want netip.Prefix) error {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	have := false
	for _, a := range addrs {
		p, ok := prefixOf(a.IPNet)
		if ok && p == want {
			have = true
			continue
		}
		if err := netlink.AddrDel(link, &a); err != nil {
			return fmt.Errorf("remove address %s: %w", a.IPNet, err)
		}
	}
	if have {
		return nil
	}
	ipn := &net.IPNet{IP: want.Addr().AsSlice(), Mask: net.CIDRMask(want.Bits(), 32)}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipn}); err != nil {
		return fmt.Errorf("add address %s: %w", want, err)
	}
	return nil
}

func (k *Kernel) syncDevice(s IfaceSpec) error {
	priv, err := wgtypes.ParseKey(s.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	dev, err := k.client.Device(s.Name)
	if err != nil {
		return fmt.Errorf("read device: %w", err)
	}
	cfg := wgtypes.Config{}
	if dev.PrivateKey != priv {
		cfg.PrivateKey = &priv
	}
	if dev.ListenPort != s.Port {
		port := s.Port
		cfg.ListenPort = &port
	}
	wanted := map[wgtypes.Key]bool{}
	for _, p := range s.Peers {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer key: %w", err)
		}
		wanted[pub] = true
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				return fmt.Errorf("preshared key: %w", err)
			}
			pc.PresharedKey = &psk
		}
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())})
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	for _, p := range dev.Peers {
		if !wanted[p.PublicKey] {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	if cfg.PrivateKey == nil && cfg.ListenPort == nil && len(cfg.Peers) == 0 {
		return nil
	}
	if err := k.client.ConfigureDevice(s.Name, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	return nil
}

func (k *Kernel) syncRoutes(link netlink.Link, want []netip.Prefix) error {
	for _, p := range want {
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 || p != p.Masked() {
			return fmt.Errorf("unsafe hub route %s", p)
		}
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	keep := map[netip.Prefix]bool{}
	for _, p := range want {
		keep[p] = true
	}
	for _, r := range routes {
		if r.Protocol != RouteProtocol || r.Dst == nil {
			continue
		}
		if p, ok := prefixOf(r.Dst); ok && keep[p] {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil {
			return fmt.Errorf("remove route %s: %w", r.Dst, err)
		}
	}
	for _, p := range want {
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)},
			Scope:     netlink.SCOPE_LINK,
			Protocol:  RouteProtocol,
		}
		// Exclusive creation is atomic: a route installed concurrently must
		// never be overwritten, even between inspection and the netlink call.
		if err := netlink.RouteAdd(r); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("route %s: %w", p, err)
			}
			cur, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: r.Dst, Table: unix.RT_TABLE_MAIN},
				netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
			if err != nil {
				return fmt.Errorf("inspect route %s: %w", p, err)
			}
			matched := false
			for _, c := range cur {
				if c.Protocol != RouteProtocol || c.LinkIndex != r.LinkIndex || c.Scope != r.Scope || c.Gw != nil || c.Priority != 0 || len(c.MultiPath) != 0 {
					return fmt.Errorf("route %s already exists and is not the expected govpn-wg route", p)
				}
				matched = true
			}
			if !matched {
				return fmt.Errorf("route %s collided but could not be verified", p)
			}
		}
	}
	return nil
}

func (k *Kernel) Peers(name string) (map[string]PeerStatus, error) {
	dev, err := k.client.Device(name)
	if err != nil {
		return nil, err
	}
	out := map[string]PeerStatus{}
	for _, p := range dev.Peers {
		st := PeerStatus{PublicKey: p.PublicKey.String(), LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		out[st.PublicKey] = st
	}
	return out, nil
}

func (k *Kernel) UsedPrefixes(owned func(string) bool) ([]netip.Prefix, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	skip := map[int]bool{}
	for _, l := range links {
		if owned(l.Attrs().Name) {
			skip[l.Attrs().Index] = true
		}
	}
	var out []netip.Prefix
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst == nil || skip[r.LinkIndex] {
			continue
		}
		if p, ok := prefixOf(r.Dst); ok && p.Bits() >= 1 {
			out = append(out, p.Masked())
		}
	}
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if skip[a.LinkIndex] {
			continue
		}
		if p, ok := prefixOf(a.IPNet); ok {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a, ones), true
}

// disableIPv6 keeps the tunnel IPv4-only: no link-local address, no IPv6
// routing through it. Scoped to this link; host IPv6 is left untouched.
// A missing path means IPv6 is already disabled kernel-wide.
func disableIPv6(name string) error {
	p := filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 && b[0] == '1' {
		return nil
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.WriteFile(p, []byte("1"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("disable ipv6: %w", err)
	}
	return nil
}
