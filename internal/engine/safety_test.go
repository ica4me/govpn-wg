package engine_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

type failFW struct{ firewall.Fake }

func (f *failFW) Apply(firewall.Ruleset) error { return errors.New("iptables broken") }

func TestFirewallFailureKeepsLinksDown(t *testing.T) {
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	t.Setenv("GOVPN_ENDPOINT", "203.0.113.7")
	cfg, _ := config.Load("")
	st, _ := config.OpenStore(cfg.DataDir)
	wg := wireguard.NewFake()
	e := engine.New(engine.Options{Config: cfg, Store: st, WG: wg, Firewall: &failFW{},
		PortsInUse:   func() map[int]bool { return nil },
		DetectPublic: func() (string, netip.Addr, error) { return "ens3", netip.Addr{}, nil }})
	if _, err := e.CreateSite(engine.SiteInput{Name: ptr("a"), LocalSubnets: ptr([]string{"192.168.1.0/24"})}); err == nil {
		t.Fatal("create must fail when firewall fails")
	}
	if len(wg.Ifaces) != 0 {
		t.Fatalf("interface created without firewall: %v", wg.Ifaces)
	}
	if len(st.Snapshot().Sites) != 0 {
		t.Fatal("state persisted after failed apply")
	}
}

func TestExposeNothingAndHostRoutes(t *testing.T) {
	r := newRig(t)
	r.wg.Used = append(r.wg.Used, netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("38.47.85.0/24"))
	// A /12 host supernet must not exhaust the pool.
	a, err := r.e.CreateSite(engine.SiteInput{Name: ptr("a"), LocalSubnets: ptr([]string{"192.168.10.0/24"}), AllowAllSubnets: ptr(false), ExposedSubnets: ptr([]string{})})
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Exposed(r.e.Snapshot().Site(a.ID)); len(got) != 0 {
		t.Fatalf("expose nothing exposed %v", got)
	}
	// Site LAN equal to / covering a host route is refused.
	for _, bad := range []string{"38.47.85.0/24", "38.0.0.0/8", "172.16.0.0/12"} {
		if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("x" + bad[:2]), LocalSubnets: ptr([]string{bad})}); engine.StatusOf(err) != 409 {
			t.Fatalf("%s accepted: %v", bad, err)
		}
	}
	// A carve-out more specific than a broad host route is fine.
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("b"), LocalSubnets: ptr([]string{"172.20.5.0/24"})}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("c"), LocalSubnets: ptr([]string{"0.0.0.0/1"})}); engine.StatusOf(err) != 422 {
		t.Fatalf("expected subnet rejection (422), got %v", err)
	}
}
