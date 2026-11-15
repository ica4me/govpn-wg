//go:build linux

package engine_test

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

// Run only in an isolated network namespace, never on the host network.
func TestKernelIsolation(t *testing.T) {
	if os.Getenv("GOVPN_TEST_NETNS") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if ns == host {
		t.Fatal("refusing integration test in host network namespace")
	}
	cmd := func(args ...string) string {
		t.Helper()
		b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %v %s", args, e, b)
		}
		return string(b)
	}
	cmd("ip", "link", "set", "lo", "up")
	cmd("ip", "link", "add", "uplink", "type", "dummy")
	cmd("ip", "addr", "add", "198.18.0.2/24", "dev", "uplink")
	cmd("ip", "link", "set", "uplink", "up")
	cmd("ip", "route", "add", "default", "via", "198.18.0.1", "dev", "uplink", "metric", "50")
	before := cmd("ip", "-4", "route", "show", "default")
	t.Setenv("GOVPN_DATA_DIR", t.TempDir())
	t.Setenv("GOVPN_ENDPOINT", "198.18.0.2")
	t.Setenv("GOVPN_DRY_RUN", "0")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	wg, err := wireguard.NewKernel()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	fw, err := firewall.NewIPTables()
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.Options{Config: cfg, Store: store, WG: wg, Firewall: fw, PortsInUse: func() map[int]bool { return nil }, DetectPublic: func() (string, netip.Addr, error) { return "uplink", netip.MustParseAddr("198.18.0.2"), nil }})
	defer func() {
		if e := eng.Teardown(); e != nil {
			t.Error(e)
		}
	}()
	s, err := eng.CreateSite(engine.SiteInput{Name: ptr("integration"), LocalSubnets: ptr([]string{"192.168.123.0/24"})})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd("wg", "show", "interfaces"), s.Iface) {
		t.Fatal("real WG link missing")
	}
	if got := cmd("ip", "-4", "route", "show", "default"); got != before {
		t.Fatalf("default changed: %s -> %s", before, got)
	}
	// Simulate flushed chains and a foreign rule placed above our jump.
	cmd("iptables", "-F", "GOVPN-FWD")
	cmd("iptables", "-I", "FORWARD", "1", "-j", "ACCEPT")
	if err := eng.Reconcile(); err != nil {
		t.Fatal(err)
	}
	out := cmd("iptables", "-S", "FORWARD")
	var first string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			first = l
			break
		}
	}
	if first != "-A FORWARD -j GOVPN-FWD" {
		t.Fatalf("isolation jump not first: %s", out)
	}
	if !strings.Contains(cmd("iptables", "-S", "GOVPN-FWD"), "-i wg-s+ -j DROP") {
		t.Fatal("drift not repaired")
	}
	if !strings.Contains(cmd("iptables", "-S", "GOVPN-IN"), "-i wg-c+ -j DROP") {
		t.Fatal("INPUT isolation missing")
	}
	if got := cmd("ip", "-4", "route", "show", "default"); got != before {
		t.Fatal("reconcile changed default")
	}
	if err := eng.DeleteSite(s.ID); err != nil {
		t.Fatal(err)
	}
	if got := cmd("ip", "-4", "route", "show", "default"); got != before {
		t.Fatal("delete changed default")
	}
	t.Log("real WireGuard create/delete, iptables apply/drift repair, INPUT isolation, and unchanged default route verified")
}
