package engine_test

import (
	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
	"net/netip"
	"testing"
)

type countedPrefixes struct {
	*wireguard.Fake
	calls int
}

func (w *countedPrefixes) UsedPrefixes(owned func(string) bool) ([]netip.Prefix, error) {
	w.calls++
	return w.Fake.UsedPrefixes(owned)
}
func TestMutationInspectsHostOnce(t *testing.T) {
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	w := &countedPrefixes{Fake: wireguard.NewFake()}
	e := engine.New(engine.Options{Config: cfg, Store: st, WG: w, Firewall: &firewall.Fake{}, PortsInUse: func() map[int]bool { return nil }})
	site, err := e.CreateSite(engine.SiteInput{Name: ptr("test"), LocalSubnets: ptr([]string{"192.168.10.0/24"})})
	if err != nil {
		t.Fatal(err)
	}
	w.calls = 0
	_, err = e.UpdateSite(site.ID, engine.SiteInput{Name: ptr("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if w.calls != 1 {
		t.Fatalf("host inspections: got %d, want 1", w.calls)
	}
}
