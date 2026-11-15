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

type prefixFailure struct{ *wireguard.Fake }

func (w *prefixFailure) UsedPrefixes(func(string) bool) ([]netip.Prefix, error) {
	return nil, errors.New("netlink unavailable")
}

func TestStartRejectsHostInspectionFailure(t *testing.T) {
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	wg, fw := &prefixFailure{wireguard.NewFake()}, &firewall.Fake{}
	e := engine.New(engine.Options{Config: cfg, Store: st, WG: wg, Firewall: fw})
	if err := e.Start(); err == nil {
		t.Fatal("startup accepted failed host route inspection")
	}
	if fw.Last != "" || len(wg.Ifaces) != 0 {
		t.Fatal("invalid state reached kernel apply")
	}
}

func TestStartAndReconcileValidatePersistedState(t *testing.T) {
	r := newRig(t)
	s, err := r.e.CreateSite(engine.SiteInput{Name: ptr("a"), LocalSubnets: ptr([]string{"192.168.10.0/24"})})
	if err != nil {
		t.Fatal(err)
	}
	// Host gained a conflicting management route after the state was committed.
	r.wg.Used = append(r.wg.Used, netip.MustParsePrefix(s.LocalSubnets[0]))
	r.fw.Last = "sentinel"
	for _, apply := range []func() error{r.e.Start, r.e.Reconcile} {
		if err := apply(); err == nil {
			t.Fatal("persisted site hijacking host route accepted")
		}
		if r.fw.Last != "sentinel" {
			t.Fatal("validation occurred after firewall apply")
		}
	}
}
