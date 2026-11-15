package generator_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ica4me/govpn-wg/internal/generator"
)

func clientPeer() generator.Peer {
	return generator.Peer{
		Kind: "client", Name: "phone", FileName: "phone",
		Address: "172.31.201.2/32", PrivateKey: "priv", ServerKey: "pub", PSK: "psk",
		Endpoint: "203.0.113.7:3478", AllowedIPs: []string{"0.0.0.0/0"},
		MTU: 1360, Keepalive: 25, TunnelMode: "full", Iface: "govpn",
	}
}

func sitePeer() generator.Peer {
	return generator.Peer{
		Kind: "site", Name: "hq", FileName: "hq",
		Address: "172.31.201.2/24", PrivateKey: "priv", ServerKey: "pub", PSK: "psk",
		Endpoint: "203.0.113.7:3478", AllowedIPs: []string{"0.0.0.0/0"},
		MTU: 1360, Keepalive: 25, TunnelMode: "full", LocalLANs: []string{"192.168.50.0/24"}, Iface: "wg-hub",
	}
}

// The downloaded .conf is also the Windows artefact: IPv4 only, no Linux
// hooks, and an explicit warning instead of an IPv6 leak-blocking claim.
func TestConfIsIPv4OnlyWithoutLinuxHooks(t *testing.T) {
	out, err := generator.Conf(clientPeer())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "::/0") {
		t.Fatalf("generated profile contains ::/0:\n%s", out)
	}
	if !strings.Contains(out, "AllowedIPs = 0.0.0.0/0\n") {
		t.Fatalf("missing IPv4 default route:\n%s", out)
	}
	for _, unwanted := range []string{"PostUp", "PreDown", "sysctl"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("platform-neutral conf contains Linux hook %q:\n%s", unwanted, out)
		}
	}
	for _, want := range []string{"IPv4-only profile", "claims no IPv6 leak blocking"} {
		if !strings.Contains(out, want) {
			t.Fatalf("conf warning %q missing:\n%s", want, out)
		}
	}
}

// The Linux installer hardens only the GoVPN link; host-wide IPv6 keys must
// never appear.
func TestLinuxClientScriptHardensLinkOnly(t *testing.T) {
	out, err := generator.ClientScript(clientPeer())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PostUp = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=1",
		"PreDown = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=0",
		"AllowedIPs = 0.0.0.0/0\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("client script missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "::/0") {
		t.Fatalf("client script contains ::/0:\n%s", out)
	}
	for _, hostWide := range []string{"net.ipv6.conf.all.", "net.ipv6.conf.default."} {
		if strings.Contains(out, hostWide) {
			t.Fatalf("client script touches host-wide IPv6 key %q:\n%s", hostWide, out)
		}
	}
	assertBashSyntax(t, "client", out)
}

func TestSiteScriptHardensLinkOnly(t *testing.T) {
	out, err := generator.SiteScript(sitePeer())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PostUp = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=1",
		"PreDown = sysctl -q -w net.ipv6.conf.%i.disable_ipv6=0",
		"ip -4 route replace default",
		"AllowedIPs = 0.0.0.0/0\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("site script missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "::/0") {
		t.Fatalf("site script contains ::/0:\n%s", out)
	}
	for _, hostWide := range []string{"net.ipv6.conf.all.", "net.ipv6.conf.default."} {
		if strings.Contains(out, hostWide) {
			t.Fatalf("site script touches host-wide IPv6 key %q:\n%s", hostWide, out)
		}
	}
	assertBashSyntax(t, "site", out)
}

func TestSplitProfileStaysSplitButIPv4Only(t *testing.T) {
	p := clientPeer()
	p.TunnelMode = "split"
	p.AllowedIPs = []string{"172.31.201.0/24", "192.168.50.0/24"}
	out, err := generator.Conf(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "AllowedIPs = 0.0.0.0/0") || strings.Contains(out, "::/0") {
		t.Fatalf("split profile must not carry a full-tunnel route:\n%s", out)
	}
	if !strings.Contains(out, "AllowedIPs = 172.31.201.0/24, 192.168.50.0/24") {
		t.Fatalf("split routes missing:\n%s", out)
	}
}

func assertBashSyntax(t *testing.T, name, script string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Logf("bash not installed, skipping %s syntax check", name)
		return
	}
	f := filepath.Join(t.TempDir(), name+".sh")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
		t.Fatalf("%s script syntax: %v\n%s", name, err, out)
	}
}
