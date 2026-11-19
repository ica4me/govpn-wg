package engine_test

import (
	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
	"net/netip"
	"testing"
)

func TestServerPublicSubnetNeverExportedAsSplitLAN(t *testing.T) {
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	t.Setenv("GOVPN_SERVER_LAN", "38.47.90.0/23,10.10.9.0/24,172.16.50.0/24,192.168.1.0/24")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.Options{Config: cfg, Store: st, WG: wireguard.NewFake(), Firewall: &firewall.Fake{}, DetectPublic: func() (string, netip.Addr, error) { return "ens3", netip.MustParseAddr("38.47.91.222"), nil }})
	c, err := e.CreateClient(engine.ClientInput{Username: ptr("regression")})
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.CreateSite(engine.SiteInput{Name: ptr("remote"), LocalSubnets: ptr([]string{"10.99.0.0/24"}), CanAccessServerLAN: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	for _, ips := range [][]string{e.ClientAllowedIPs(st.Snapshot(), c), e.SiteAllowedIPs(st.Snapshot(), s)} {
		if contains(ips, "38.47.90.0/23") {
			t.Errorf("public server subnet leaked: %v", ips)
		}
		for _, p := range []string{"10.10.9.0/24", "172.16.50.0/24", "192.168.1.0/24"} {
			if !contains(ips, p) {
				t.Errorf("private LAN lost %s: %v", p, ips)
			}
		}
	}
}
