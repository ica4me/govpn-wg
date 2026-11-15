//go:build linux

package wireguard

import (
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRouteSafetyInNamespace(t *testing.T) {
	if os.Getenv("GOVPN_TEST_NETNS") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if ns == "" || host == "" || ns == host {
		t.Fatal("refusing host network namespace")
	}
	k := &Kernel{}
	t.Run("default rejected before netlink", func(t *testing.T) {
		if err := k.syncRoutes(nil, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); err == nil {
			t.Fatal("default route accepted")
		}
	})
	t.Run("foreign collision and idempotence", func(t *testing.T) {
		l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "route-test"}}
		if err := netlink.LinkAdd(l); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(l)
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		p := netip.MustParsePrefix("192.0.2.0/24")
		if err := k.syncRoutes(l, []netip.Prefix{p}); err != nil {
			t.Fatal(err)
		}
		if err := k.syncRoutes(l, []netip.Prefix{p}); err != nil {
			t.Fatalf("idempotence: %v", err)
		}
		routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 {
			t.Fatalf("routes: %v", routes)
		}
		r := routes[0]
		if err := netlink.RouteDel(&r); err != nil {
			t.Fatal(err)
		}
		r.Protocol = 99
		if err := netlink.RouteAdd(&r); err != nil {
			t.Fatal(err)
		}
		if err := k.syncRoutes(l, []netip.Prefix{p}); err == nil {
			t.Fatal("foreign route accepted")
		}
		routes, err = netlink.RouteList(l, netlink.FAMILY_V4)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].Protocol != 99 {
			t.Fatalf("foreign route changed: %v", routes)
		}
	})
}
