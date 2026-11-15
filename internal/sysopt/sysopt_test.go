package sysopt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplySysctlFakeRoot(t *testing.T) {
	root := t.TempDir()
	write := func(key, val string) {
		p := procPath(root, key)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(val+"\n"), 0o644)
	}
	write("net.ipv4.ip_forward", "0")
	write("net.core.rmem_max", "212992")
	write("net.ipv4.tcp_rmem", "4096\t131072\t33554432")
	_ = os.MkdirAll(filepath.Join(root, "/proc/sys/net/ipv6/conf/ens3"), 0o755)
	write("net.ipv6.conf.ens3.accept_ra", "1")

	steps, applied := ApplySysctl(root, map[string]string{
		"net.ipv4.ip_forward": "1", "net.core.rmem_max": "33554432",
		"net.ipv4.tcp_rmem": "4096 131072 33554432", "net.bogus": "1", "bad key": "1",
	}, false)
	status := map[string]string{}
	for _, s := range steps {
		status[s.Item] = s.Status
	}
	if status["net.ipv4.ip_forward"] != "applied" || status["net.ipv4.tcp_rmem"] != "unchanged" ||
		status["net.bogus"] != "unsupported" || status["bad key"] != "failed" || status["net.ipv6.conf.ens3.accept_ra"] != "applied" {
		t.Fatalf("%v", status)
	}
	if b, _ := os.ReadFile(procPath(root, "net.ipv4.ip_forward")); strings.TrimSpace(string(b)) != "1" {
		t.Fatal("not written")
	}
	if _, ok := applied["net.bogus"]; ok {
		t.Fatal("unsupported key persisted")
	}
	file := RenderSysctlFile(applied)
	if !strings.Contains(file, "net.ipv4.ip_forward = 1") {
		t.Fatal(file)
	}
	// accept_ra before ip_forward before the rest.
	if strings.Index(file, "accept_ra") > strings.Index(file, "ip_forward") {
		t.Fatal("order")
	}
}

func TestValuesScale(t *testing.T) {
	v := Values(1<<30, map[string]string{"net.core.somaxconn": "8192"})
	if v["net.netfilter.nf_conntrack_max"] != "262144" || v["net.core.somaxconn"] != "8192" {
		t.Fatal(v["net.netfilter.nf_conntrack_max"], v["net.core.somaxconn"])
	}
	if v["net.ipv4.udp_mem"] != "16384 32768 65536" {
		t.Fatal(v["net.ipv4.udp_mem"])
	}
}

func TestParseRingsAndFeatures(t *testing.T) {
	out := `Ring parameters for ens3:
Pre-set maximums:
RX:		1024
RX Mini:	n/a
TX:		1024
Current hardware settings:
RX:		256
TX:		256
`
	mrx, mtx, crx, ctx := ParseRings(out)
	if mrx != 1024 || mtx != 1024 || crx != 256 || ctx != 256 {
		t.Fatal(mrx, mtx, crx, ctx)
	}
	f := ParseFeatures("generic-receive-offload: on\nlarge-receive-offload: off [fixed]\n")
	if f["generic-receive-offload"][0] != "on" || f["large-receive-offload"][1] != "fixed" {
		t.Fatal(f)
	}
}
