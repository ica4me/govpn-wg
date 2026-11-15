package engine_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/generator"
)

// Every client may use the hub as an internet gateway no matter what
// tunnel_mode the API stores: split only describes the downloaded profile,
// and a user may hand-edit AllowedIPs to 0.0.0.0/0.
func TestAllClientsGetInternetRegardlessOfMode(t *testing.T) {
	r := newRig(t)
	if _, err := r.e.CreateSite(engine.SiteInput{Name: ptr("hq"), LocalSubnets: ptr([]string{"192.168.50.0/24"})}); err != nil {
		t.Fatal(err)
	}
	split, err := r.e.CreateClient(engine.ClientInput{Username: ptr("budi"), TargetSites: ptr([]string{"hq"}), AllowServerLAN: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if split.TunnelMode != "split" {
		t.Fatalf("new client default mode = %q, want split", split.TunnelMode)
	}
	full, err := r.e.CreateClient(engine.ClientInput{Username: ptr("sari"), TunnelMode: ptr("full")})
	if err != nil {
		t.Fatal(err)
	}

	rules := r.fw.Last
	for _, c := range []struct{ user, addr string }{{"budi", split.Address}, {"sari", full.Address}} {
		src := c.addr + "/32"
		accept := fmt.Sprintf(`-A GOVPN-FWD -i wg-c-default -s %s -o ens3 -m comment --comment "full-tunnel wg-c-default" -j ACCEPT`, src)
		nat := fmt.Sprintf("-A GOVPN-POST -s %s -o ens3 -j MASQUERADE", src)
		for _, want := range []string{accept, nat} {
			if !strings.Contains(rules, want) {
				t.Fatalf("client %s (%s) has no internet egress rule %q:\n%s", c.user, c.addr, want, rules)
			}
		}
	}

	// Non-public destinations stay denied by default for the split client...
	drop := fmt.Sprintf("-A GOVPN-FWD -i wg-c-default -s %s -d 192.168.0.0/16 -j DROP", split.Address+"/32")
	// ...while the explicit site and server-LAN grants are still rendered
	// before that drop, so private access is unchanged.
	grant := fmt.Sprintf(`-A GOVPN-FWD -i wg-c-default -s %s -d 192.168.50.0/24 -m comment --comment "client budi -> sites" -j ACCEPT`, split.Address+"/32")
	lan := fmt.Sprintf(`-A GOVPN-FWD -i wg-c-default -s %s -d 10.10.9.0/24 -m comment --comment "client budi -> server lan" -j ACCEPT`, split.Address+"/32")
	for _, want := range []string{drop, grant, lan} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing rule %q:\n%s", want, rules)
		}
	}
	if !(strings.Index(rules, grant) < strings.Index(rules, drop) && strings.Index(rules, lan) < strings.Index(rules, drop)) {
		t.Fatalf("explicit grants must precede the non-public drop:\n%s", rules)
	}
}

func TestFullTunnelProfilesAreIPv4Only(t *testing.T) {
	r := newRig(t)
	s, err := r.e.CreateSite(engine.SiteInput{Name: ptr("hq"), LocalSubnets: ptr([]string{"192.168.50.0/24"}), TunnelMode: ptr("full")})
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.e.CreateClient(engine.ClientInput{Username: ptr("sari"), TunnelMode: ptr("full")})
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.e.GetSite(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.AllowedIPs) != 1 || v.AllowedIPs[0] != "0.0.0.0/0" {
		t.Fatalf("full site AllowedIPs = %v, want [0.0.0.0/0]", v.AllowedIPs)
	}
	cv, err := r.e.GetClient(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cv.AllowedIPs) != 1 || cv.AllowedIPs[0] != "0.0.0.0/0" {
		t.Fatalf("full client AllowedIPs = %v, want [0.0.0.0/0]", cv.AllowedIPs)
	}
	sp, err := r.e.SitePeer(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := r.e.ClientPeer(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range [][]string{sp.AllowedIPs, cp.AllowedIPs} {
		for _, a := range allowed {
			if strings.Contains(a, ":") || a == "::/0" {
				t.Fatalf("generated AllowedIPs contains IPv6 %q", a)
			}
		}
	}
	conf, err := generator.Conf(cp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "::/0") {
		t.Fatalf("generated full conf contains ::/0:\n%s", conf)
	}
}

// A split profile remains the default download, but the same peer can be
// re-rendered locally with an IPv4 default route; the server rules already
// permit it, so no API change is involved.
func TestSplitProfileCanBeEditedToFullLocally(t *testing.T) {
	r := newRig(t)
	c, err := r.e.CreateClient(engine.ClientInput{Username: ptr("budi")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.e.ClientPeer(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if contains(p.AllowedIPs, "0.0.0.0/0") || contains(p.AllowedIPs, "::/0") {
		t.Fatalf("split profile is not split: %v", p.AllowedIPs)
	}
	p.AllowedIPs = []string{"0.0.0.0/0"}
	conf, err := generator.Conf(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0\n") || strings.Contains(conf, "::/0") {
		t.Fatalf("hand-edited profile is not IPv4-only full tunnel:\n%s", conf)
	}
}
