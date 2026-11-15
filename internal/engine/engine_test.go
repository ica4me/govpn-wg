package engine_test

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

type rig struct {
	e  *engine.Engine
	wg *wireguard.Fake
	fw *firewall.Fake
}

func newRig(t *testing.T) rig {
	t.Helper()
	t.Setenv("GOVPN_SERVER_LAN", "10.10.9.0/24")
	t.Setenv("GOVPN_ENDPOINT", "203.0.113.7")
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	t.Setenv("GOVPN_DRY_RUN", "1")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	wg, fw := wireguard.NewFake(), &firewall.Fake{}
	wg.Used = []netip.Prefix{netip.MustParsePrefix("172.31.230.0/24")}
	e := engine.New(engine.Options{Config: cfg, Store: st, WG: wg, Firewall: fw,
		PortsInUse:   func() map[int]bool { return map[int]bool{3479: true} },
		DetectPublic: func() (string, netip.Addr, error) { return "ens3", netip.MustParseAddr("203.0.113.7"), nil }})
	return rig{e, wg, fw}
}

func ptr[T any](v T) *T { return &v }

func TestSiteLifecycle(t *testing.T) {
	r := newRig(t)
	a, err := r.e.CreateSite(engine.SiteInput{Name: ptr("Site A"), LocalSubnets: ptr([]string{"192.168.10.0/24"}), CanAccessServerLAN: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.e.CreateSite(engine.SiteInput{Name: ptr("Site B"), LocalSubnets: ptr([]string{"10.20.0.0/16"}), AllowedTargetSites: ptr([]string{"site-a"})})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "site-a" || a.Iface != "wg-s-site-a" || b.Iface != "wg-s-site-b" {
		t.Fatalf("ids/ifaces: %s %s %s", a.ID, a.Iface, b.Iface)
	}
	if a.Port != 3478 || b.Port != 3480 {
		t.Fatalf("ports %d %d (3479 is busy on host)", a.Port, b.Port)
	}
	if a.Subnet == b.Subnet || strings.HasPrefix(a.Subnet, "172.31.230.") || strings.HasPrefix(b.Subnet, "172.31.230.") {
		t.Fatalf("subnet collision: %s %s", a.Subnet, b.Subnet)
	}
	if a.MTU != 1360 {
		t.Fatal("default mtu")
	}
	spec := r.wg.Ifaces["wg-s-site-a"]
	if len(spec.Peers) != 1 || len(spec.Routes) != 1 || spec.Routes[0].String() != "192.168.10.0/24" {
		t.Fatalf("spec: %+v", spec)
	}
	rules := r.fw.Last
	for _, want := range []string{
		"-A GOVPN-FWD -i wg-s-site-b -s 10.20.0.0/16 -d 192.168.10.0/24",
		"-A GOVPN-FWD -i wg-s-site-a -s 192.168.10.0/24 -d 10.10.9.0/24",
		"-A GOVPN-MSS -o wg-s-site-a -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1321:65535 -j TCPMSS --set-mss 1320",
		"-A GOVPN-FWD -i wg-s-site-a -j DROP",
		"-A GOVPN-FWD -o wg-s-site-b -j DROP",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing rule %q in\n%s", want, rules)
		}
	}
	// site-a has not granted anything to site-b, so no a->b rule.
	if strings.Contains(rules, "-i wg-s-site-a -s 192.168.10.0/24 -d 10.20.0.0/16") {
		t.Fatal("unexpected reverse grant")
	}
	// A's peer config must route B's LAN back (B may reach A).
	va, _ := r.e.GetSite("site-a")
	if !contains(va.AllowedIPs, "10.20.0.0/16") || !contains(va.AllowedIPs, "10.10.9.0/24") {
		t.Fatalf("site-a allowed ips %v", va.AllowedIPs)
	}

	// Overlapping LAN is refused and state is unchanged.
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("dup"), LocalSubnets: ptr([]string{"192.168.10.128/25"})}); engine.StatusOf(err) != 409 {
		t.Fatalf("want 409, got %v", err)
	}
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("pool"), LocalSubnets: ptr([]string{"172.31.240.0/24"})}); err == nil {
		t.Fatal("pool overlap accepted")
	}

	// Update: full tunnel + restricted exposure.
	if _, err := r.e.UpdateSite("site-a", engine.SiteInput{TunnelMode: ptr("full"), AllowAllSubnets: ptr(false), ExposedSubnets: ptr([]string{"192.168.10.0/25"})}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.fw.Last, "-i wg-s-site-b -s 10.20.0.0/16 -d 192.168.10.0/25") || strings.Contains(r.fw.Last, "-d 192.168.10.0/24 -m comment --comment \"site site-b") {
		t.Fatalf("exposure not narrowed:\n%s", r.fw.Last)
	}
	if !strings.Contains(r.fw.Last, "-o ens3 -m comment --comment \"full-tunnel wg-s-site-a\" -j ACCEPT") {
		t.Fatal("full tunnel egress missing")
	}
	if _, err := r.e.UpdateSite("site-a", engine.SiteInput{ExposedSubnets: ptr([]string{"10.99.0.0/24"})}); err == nil {
		t.Fatal("exposed outside local accepted")
	}

	// Delete A: B's target reference is cleaned, interface removed.
	if err := r.e.DeleteSite("site-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.wg.Ifaces["wg-s-site-a"]; ok {
		t.Fatal("wg-s-site-a still present")
	}
	vb, _ := r.e.GetSite("site-b")
	if len(vb.AllowedTargetSites) != 0 {
		t.Fatal("dangling target")
	}
}

func TestClients(t *testing.T) {
	r := newRig(t)
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("hq"), LocalSubnets: ptr([]string{"192.168.50.0/24"})}); err != nil {
		t.Fatal(err)
	}
	c, err := r.e.CreateClient(engine.ClientInput{Username: ptr("budi"), TargetSites: ptr([]string{"hq"}), AllowServerLAN: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if c.GroupID != "default" || !strings.HasSuffix(c.Address, ".2") {
		t.Fatalf("client %+v", c)
	}
	g := r.e.ListGroups()[0]
	if g.Iface != "wg-c-default" {
		t.Fatal(g.Iface)
	}
	v, _ := r.e.GetClient("budi")
	want := []string{g.Subnet, "10.10.9.0/24", "192.168.50.0/24"}
	for _, w := range want {
		if !contains(v.AllowedIPs, w) {
			t.Fatalf("allowed %v missing %s", v.AllowedIPs, w)
		}
	}
	if !strings.Contains(r.fw.Last, "-i wg-c-default -s "+c.Address+"/32 -d 192.168.50.0/24") {
		t.Fatalf("client grant missing\n%s", r.fw.Last)
	}
	c2, err := r.e.CreateClient(engine.ClientInput{Username: ptr("sari"), TunnelMode: ptr("full")})
	if err != nil {
		t.Fatal(err)
	}
	if c2.Address == c.Address {
		t.Fatal("address reuse")
	}
	v2, _ := r.e.GetClient("sari")
	if !contains(v2.AllowedIPs, "0.0.0.0/0") {
		t.Fatal("full mode allowed ips")
	}
	if _, err := r.e.CreateClient(engine.ClientInput{Username: ptr("budi")}); engine.StatusOf(err) != 409 {
		t.Fatal("duplicate username")
	}
	if _, err := r.e.UpdateClient("budi", engine.ClientInput{TargetSites: ptr([]string{"nope"})}); engine.StatusOf(err) != 422 {
		t.Fatal("unknown target accepted")
	}
	if _, err := r.e.UpdateClient("budi", engine.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if n := len(r.wg.Ifaces["wg-c-default"].Peers); n != 1 {
		t.Fatalf("disabled client still a peer (%d peers)", n)
	}
	if err := r.e.DeleteGroup("default"); engine.StatusOf(err) != 409 {
		t.Fatal("group with clients deleted")
	}
	p, err := r.e.ClientPeer("budi")
	if err != nil || p.Endpoint != "203.0.113.7:"+strconv.Itoa(g.Port) {
		t.Fatal(p.Endpoint, err)
	}
}

func TestStatePersists(t *testing.T) {
	r := newRig(t)
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("x"), LocalSubnets: ptr([]string{"192.168.1.0/24"})}); err != nil {
		t.Fatal(err)
	}
	st, err := config.OpenStore(r.e.Config().DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Snapshot().Sites) != 1 {
		t.Fatal("not persisted")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
