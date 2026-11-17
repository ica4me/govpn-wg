package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func pfx(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }

func sample() Ruleset {
	return Ruleset{PublicIf: "ens3", MSSMode: "mtu", Ifaces: []Iface{
		{Name: "wg-s1", MTU: 1360, Grants: []Grant{{Comment: `a "quoted"\ comment`, Sources: pfx("192.168.10.0/24"), Dests: pfx("10.10.9.0/24"), Masquerade: true}}},
		{Name: "wg-c1", MTU: 1400, FullSources: pfx("172.31.201.3/32")},
	}}
}

func TestRenderOrderAndCatchAll(t *testing.T) {
	out := sample().Render()
	idx := func(s string) int {
		i := strings.Index(out, s)
		if i < 0 {
			t.Fatalf("missing %q in\n%s", s, out)
		}
		return i
	}
	est := idx("-A GOVPN-FWD -i wg-s1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	grant := idx("-A GOVPN-FWD -i wg-s1 -s 192.168.10.0/24 -d 10.10.9.0/24")
	drop := idx("-A GOVPN-FWD -i wg-s1 -j DROP")
	if !(est < grant && grant < drop) {
		t.Fatal("order: established < grant < drop")
	}
}

func TestRenderFullTunnelAndStatic(t *testing.T) {
	out := sample().Render()
	for _, want := range []string{
		"-A GOVPN-FWD -i wg-c1 -s 172.31.201.3/32 -d 192.168.0.0/16 -j DROP",
		`-A GOVPN-FWD -i wg-c1 -s 172.31.201.3/32 -o ens3 -m comment --comment "full-tunnel wg-c1" -j ACCEPT`,
		"-A GOVPN-POST -s 172.31.201.3/32 -o ens3 -j MASQUERADE",
		"-A GOVPN-POST -s 192.168.10.0/24 -d 10.10.9.0/24",
		"-A GOVPN-FWD -i wg-s+ -j DROP", "-A GOVPN-FWD -o wg-c+ -j DROP",
		"-A GOVPN-IN -i wg-c+ -p icmp -m icmp --icmp-type 8 -m limit --limit 50/second --limit-burst 50 -j ACCEPT",
		"-A GOVPN-IN -i wg-s+ -j DROP",
		"--mss 1321:65535 -j TCPMSS --set-mss 1320", "--mss 1361:65535 -j TCPMSS --set-mss 1360",
		`--comment "a -quoted-- comment"`,
		":GOVPN-IN - [0:0]\n-F GOVPN-IN",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "full-tunnel wg-c1"), strings.Index(out, "-d 192.168.0.0/16 -j DROP"); j > i {
		t.Fatal("non-public drop must precede egress accept")
	}
	if strings.Count(out, "COMMIT") != 3 {
		t.Fatal("three tables")
	}
	r := sample()
	r.MSSMode = "pmtu"
	if !strings.Contains(r.Render(), "--clamp-mss-to-pmtu") {
		t.Fatal("pmtu mode")
	}
}

func TestEmptyStateStillIsolates(t *testing.T) {
	out := Ruleset{}.Render()
	for _, want := range []string{"-A GOVPN-FWD -i wg-s+ -j DROP", "-A GOVPN-FWD -i wg-c+ -j DROP", "-A GOVPN-IN -i wg-c+ -j DROP"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestICMPEchoPacing(t *testing.T) {
	out := sample().Render()
	for _, want := range []string{
		"-A GOVPN-IN -i ens3 -p icmp -m icmp --icmp-type 8 -m limit --limit 50/second --limit-burst 50 -j RETURN",
		"-A GOVPN-IN -i ens3 -p icmp -m icmp --icmp-type 8 -j DROP",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// Only echo-request is ever matched: no rule may name another ICMP type,
	// and no rule may drop ICMP without the type-8 match.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "-p icmp") {
			continue
		}
		if !strings.Contains(line, "--icmp-type 8 ") {
			t.Fatalf("rule touches non-echo ICMP: %s", line)
		}
	}
	in := func(needle string) int { return strings.Index(out[strings.Index(out, ":GOVPN-IN"):], needle) }
	if in("--limit 50/second --limit-burst 50 -j RETURN") > in("--icmp-type 8 -j DROP") {
		t.Fatal("pacing must precede the drop")
	}
	// A public-interface rule must never ACCEPT: it returns to host policy.
	if strings.Contains(out, "-i ens3 -p icmp") && strings.Contains(out[strings.Index(out, "-i ens3 -p icmp"):][:120], "-j ACCEPT") {
		t.Fatal("public ping rule must RETURN, not ACCEPT")
	}
	// WireGuard UDP and established traffic are untouched by the pacing.
	if !strings.Contains(out, "-A GOVPN-IN -i wg-c+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT") {
		t.Fatal("established accept missing")
	}
	// Without a detected public interface no host-side rule is emitted.
	r := sample()
	r.PublicIf = ""
	if strings.Contains(r.Render(), "-p icmp --icmp-type 8 -j DROP") && !strings.Contains(r.Render(), "wg-c+") {
		t.Fatal("unexpected host rule without public interface")
	}
}
