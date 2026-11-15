//go:build linux

package wireguard

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"testing"
)

func TestConcurrentForeignRouteNeverReplaced(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	foreign := netlink.Route{Dst: &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}, LinkIndex: 99, Protocol: 99, Table: unix.RT_TABLE_MAIN}
	adds := 0
	ops := routeOps{
		list:     func(netlink.Link, int) ([]netlink.Route, error) { return nil, nil },
		add:      func(r *netlink.Route) error { adds++; return unix.EEXIST },
		del:      func(*netlink.Route) error { t.Fatal("unexpected delete"); return nil },
		filtered: func(int, *netlink.Route, uint64) ([]netlink.Route, error) { return []netlink.Route{foreign}, nil },
	}
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 7}}
	if err := syncRoutesWith(l, []netip.Prefix{p}, ops); err == nil {
		t.Fatal("foreign collision accepted")
	}
	if adds != 1 {
		t.Fatalf("exclusive adds: %d", adds)
	}
}
