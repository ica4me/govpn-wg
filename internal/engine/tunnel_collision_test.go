package engine_test

import (
	"github.com/ica4me/govpn-wg/internal/engine"
	"net/netip"
	"testing"
)

func TestReconcileRejectsHostTunnelCollision(t *testing.T) {
	r := newRig(t)
	s, err := r.e.CreateSite(engine.SiteInput{Name: ptr("site"), LocalSubnets: ptr([]string{"192.168.10.0/24"})})
	if err != nil {
		t.Fatal(err)
	}
	tunnel := netip.MustParsePrefix(s.Subnet).Masked()
	r.wg.Used = append(r.wg.Used, tunnel)
	r.fw.Last = "sentinel"
	if err := r.e.Reconcile(); err == nil {
		t.Fatal("accepted foreign network overlapping tunnel")
	}
	if r.fw.Last != "sentinel" {
		t.Fatal("applied firewall before collision check")
	}
}
