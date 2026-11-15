// Package sysopt tunes the kernel network stack and the virtual NIC of a VM
// that acts as a WireGuard hub. Every step is best effort: unsupported keys or
// NIC features are reported, never faked as applied.
package sysopt

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ica4me/govpn-wg/internal/config"
)

const SysctlFile = "/etc/sysctl.d/99-govpn-wg.conf"

// Step is one reported action.
type Step struct {
	Item   string `json:"item"`
	Value  string `json:"value,omitempty"`
	Status string `json:"status"` // applied, unchanged, unsupported, failed, skipped
	Detail string `json:"detail,omitempty"`
}

// Report is the result of a tuning run.
type Report struct {
	PublicIf string `json:"public_if"`
	Sysctl   []Step `json:"sysctl"`
	Modules  []Step `json:"modules"`
	NIC      []Step `json:"nic"`
}

// Options controls a run.
type Options struct {
	Root      string // "" = real system; tests point this at a temp dir
	PublicIf  string
	TuneNIC   bool
	RingMode  string
	Extra     map[string]string
	WriteFile bool // persist /etc/sysctl.d/99-govpn-wg.conf
	DryRun    bool
}

// MemTotalBytes reads MemTotal from /proc/meminfo.
func MemTotalBytes(root string) uint64 {
	f, err := os.Open(filepath.Join(root, "/proc/meminfo"))
	if err != nil {
		return 1 << 30
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			return kb * 1024
		}
	}
	return 1 << 30
}

// Values returns the sysctl set, scaled to RAM where it matters.
func Values(mem uint64, extra map[string]string) map[string]string {
	pages := mem / 4096
	conntrack := clamp(mem/(1<<20)*256, 65536, 1048576) // ~256 entries per MiB RAM
	v := map[string]string{
		"net.ipv4.ip_forward":              "1",
		"net.ipv4.conf.all.forwarding":     "1",
		"net.ipv4.conf.default.forwarding": "1",
		// IPv6 forwarding stays as the OS set it: the dataplane is IPv4 only
		// and no ip6tables policy is managed, so enabling it host-wide could
		// turn a dual-stack VM into an open IPv6 router.
		"net.ipv4.conf.all.rp_filter":            "2",
		"net.ipv4.conf.default.rp_filter":        "2",
		"net.ipv4.conf.all.accept_redirects":     "0",
		"net.ipv4.conf.default.accept_redirects": "0",
		"net.ipv4.conf.all.send_redirects":       "0",
		"net.ipv4.conf.default.send_redirects":   "0",
		"net.ipv6.conf.all.accept_redirects":     "0",
		"net.ipv6.conf.default.accept_redirects": "0",
		// Forwarding=1 makes the kernel ignore Router Advertisements; cloud
		// VMs learning their IPv6 default route via RA would lose it.
		"net.ipv6.conf.all.accept_ra":     "2",
		"net.ipv6.conf.default.accept_ra": "2",

		"net.core.default_qdisc":                        "fq",
		"net.ipv4.tcp_congestion_control":               "bbr",
		"net.core.rmem_max":                             "33554432",
		"net.core.wmem_max":                             "33554432",
		"net.core.rmem_default":                         "1048576",
		"net.core.wmem_default":                         "1048576",
		"net.core.optmem_max":                           "65536",
		"net.core.netdev_max_backlog":                   "16384",
		"net.core.netdev_budget":                        "600",
		"net.core.somaxconn":                            "4096",
		"net.ipv4.tcp_rmem":                             "4096 131072 33554432",
		"net.ipv4.tcp_wmem":                             "4096 65536 33554432",
		"net.ipv4.udp_mem":                              fmt.Sprintf("%d %d %d", pages/16, pages/8, pages/4),
		"net.ipv4.udp_rmem_min":                         "16384",
		"net.ipv4.udp_wmem_min":                         "16384",
		"net.ipv4.tcp_mtu_probing":                      "1",
		"net.ipv4.ip_no_pmtu_disc":                      "0",
		"net.netfilter.nf_conntrack_max":                strconv.FormatUint(conntrack, 10),
		"net.netfilter.nf_conntrack_udp_timeout":        "60",
		"net.netfilter.nf_conntrack_udp_timeout_stream": "180",
		"fs.file-max":                                   "2097152",
	}
	for k, val := range extra {
		v[k] = val
	}
	return v
}

func clamp(x, lo, hi uint64) uint64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// order applies ip_forward first: toggling it resets per-interface defaults.
func order(v map[string]string) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	rank := func(k string) int {
		switch {
		case strings.Contains(k, "accept_ra"):
			return 0
		case k == "net.ipv4.ip_forward":
			return 1
		case strings.Contains(k, "forwarding"):
			return 2
		}
		return 3
	}
	sort.Slice(keys, func(i, j int) bool {
		if rank(keys[i]) != rank(keys[j]) {
			return rank(keys[i]) < rank(keys[j])
		}
		return keys[i] < keys[j]
	})
	return keys
}

func procPath(root, key string) string {
	return filepath.Join(root, "/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

func validKey(k string) bool {
	if k == "" || strings.Contains(k, "..") || strings.ContainsAny(k, "/ \t") {
		return false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validValue(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r == ' ' || r == '_') {
			return false
		}
	}
	return true
}

// ApplySysctl writes values to /proc/sys and returns what happened.
func ApplySysctl(root string, values map[string]string, dry bool) ([]Step, map[string]string) {
	var steps []Step
	applied := map[string]string{}
	// Keep RA on every existing interface before forwarding flips.
	if entries, err := os.ReadDir(filepath.Join(root, "/proc/sys/net/ipv6/conf")); err == nil {
		for _, e := range entries {
			if n := e.Name(); n != "all" && n != "default" && n != "lo" && config.ValidIfName(n) {
				values["net.ipv6.conf."+n+".accept_ra"] = "2"
			}
		}
	}
	for _, k := range order(values) {
		val := values[k]
		if !validKey(k) || !validValue(val) {
			steps = append(steps, Step{Item: k, Value: val, Status: "failed", Detail: "rejected key/value"})
			continue
		}
		p := procPath(root, k)
		cur, err := os.ReadFile(p)
		if err != nil {
			steps = append(steps, Step{Item: k, Value: val, Status: "unsupported", Detail: "not present in this kernel"})
			continue
		}
		if strings.Join(strings.Fields(string(cur)), " ") == val {
			steps = append(steps, Step{Item: k, Value: val, Status: "unchanged"})
			applied[k] = val
			continue
		}
		if dry {
			steps = append(steps, Step{Item: k, Value: val, Status: "skipped", Detail: "dry-run"})
			continue
		}
		if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
			steps = append(steps, Step{Item: k, Value: val, Status: "failed", Detail: err.Error()})
			continue
		}
		steps = append(steps, Step{Item: k, Value: val, Status: "applied"})
		applied[k] = val
	}
	return steps, applied
}

// RenderSysctlFile produces /etc/sysctl.d/99-govpn-wg.conf from the keys
// that were actually accepted by the running kernel.
func RenderSysctlFile(applied map[string]string) string {
	var b strings.Builder
	b.WriteString("# Managed by govpn-wg. Only keys accepted by this kernel are listed.\n")
	for _, k := range order(applied) {
		fmt.Fprintf(&b, "%s = %s\n", k, applied[k])
	}
	return b.String()
}

// EnsureForwarding is the minimum the engine needs even with tuning disabled.
func EnsureForwarding(root string, dry bool) []Step {
	steps, _ := ApplySysctl(root, map[string]string{
		"net.ipv4.ip_forward":          "1",
		"net.ipv4.conf.all.forwarding": "1",
	}, dry)
	return steps
}

var runMu sync.Mutex

// Run performs the full tuning pass. Concurrent calls are serialized.
func Run(o Options) Report {
	runMu.Lock()
	defer runMu.Unlock()
	r := Report{PublicIf: o.PublicIf}
	if !o.DryRun {
		r.Modules = LoadModules([]string{"wireguard", "tcp_bbr", "sch_fq", "nf_conntrack", "xt_TCPMSS", "iptable_mangle", "iptable_nat"})
	}
	values := Values(MemTotalBytes(o.Root), o.Extra)
	if !bbrAvailable(o.Root) {
		delete(values, "net.ipv4.tcp_congestion_control")
		r.Sysctl = append(r.Sysctl, Step{Item: "net.ipv4.tcp_congestion_control", Value: "bbr", Status: "unsupported", Detail: "tcp_bbr not available; current algorithm kept"})
	}
	steps, applied := ApplySysctl(o.Root, values, o.DryRun)
	r.Sysctl = append(r.Sysctl, steps...)
	if o.WriteFile && !o.DryRun {
		path := filepath.Join(o.Root, SysctlFile)
		if err := config.WriteFileAtomic(path, []byte(RenderSysctlFile(applied)), 0o644); err != nil {
			r.Sysctl = append(r.Sysctl, Step{Item: SysctlFile, Status: "failed", Detail: err.Error()})
		} else {
			r.Sysctl = append(r.Sysctl, Step{Item: SysctlFile, Status: "applied"})
		}
	}
	if o.TuneNIC && o.PublicIf != "" {
		r.NIC = TuneNIC(o.PublicIf, o.RingMode, o.DryRun)
	} else {
		r.NIC = []Step{{Item: "nic", Status: "skipped", Detail: "disabled or no public interface"}}
	}
	return r
}

func bbrAvailable(root string) bool {
	b, err := os.ReadFile(filepath.Join(root, "/proc/sys/net/ipv4/tcp_available_congestion_control"))
	return err == nil && strings.Contains(" "+string(b)+" ", " bbr")
}
