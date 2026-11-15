package sysopt

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
)

func command(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// LoadModules modprobes each module and persists the loadable ones.
func LoadModules(mods []string) []Step {
	var steps, ok []string
	var out []Step
	for _, m := range mods {
		if _, err := os.Stat("/sys/module/" + m); err == nil {
			out = append(out, Step{Item: m, Status: "unchanged", Detail: "loaded"})
			ok = append(ok, m)
			continue
		}
		if msg, err := command("modprobe", m); err != nil {
			out = append(out, Step{Item: m, Status: "unsupported", Detail: firstLine(msg)})
			continue
		}
		out = append(out, Step{Item: m, Status: "applied", Detail: "loaded"})
		ok = append(ok, m)
	}
	_ = steps
	if len(ok) > 0 {
		_ = config.WriteFileAtomic("/etc/modules-load.d/govpn-wg.conf", []byte(strings.Join(ok, "\n")+"\n"), 0o644)
	}
	return out
}

// Offload targets for a WireGuard forwarder. GRO/GSO/TSO stay on: WireGuard
// in kernel >= 5.19 batches UDP via GRO, and turning offloads off moves the
// segmentation cost onto the (often single) vCPU. UDP GRO forwarding lets the
// NIC hand coalesced UDP to the forwarding path; GRO list must be off for it.
var offloads = []struct{ short, long, want string }{
	{"gro", "generic-receive-offload", "on"},
	{"gso", "generic-segmentation-offload", "on"},
	{"tso", "tcp-segmentation-offload", "on"},
	{"rx-udp-gro-forwarding", "rx-udp-gro-forwarding", "on"},
	{"rx-gro-list", "rx-gro-list", "off"},
}

// TuneNIC sets ring buffers to their hardware maximum and aligns offloads.
func TuneNIC(dev, ringMode string, dry bool) []Step {
	if !config.ValidIfName(dev) {
		return []Step{{Item: "nic", Status: "failed", Detail: "invalid interface name"}}
	}
	if _, err := exec.LookPath("ethtool"); err != nil {
		return []Step{{Item: "ethtool", Status: "unsupported", Detail: "ethtool not installed"}}
	}
	var steps []Step
	if driver, err := command("ethtool", "-i", dev); err == nil {
		steps = append(steps, Step{Item: dev + " driver", Status: "unchanged", Detail: firstLine(driver)})
	}
	if ringMode == "max" {
		steps = append(steps, tuneRings(dev, dry)...)
	}
	steps = append(steps, tuneOffloads(dev, dry)...)
	steps = append(steps, tuneQueueLen(dev, dry))
	return steps
}

// ParseRings parses `ethtool -g` output into max and current rx/tx.
func ParseRings(out string) (maxRX, maxTX, curRX, curTX int) {
	section := 0
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "Pre-set maximums"):
			section = 1
		case strings.HasPrefix(l, "Current hardware settings"):
			section = 2
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		switch {
		case section == 1 && k == "RX":
			maxRX = n
		case section == 1 && k == "TX":
			maxTX = n
		case section == 2 && k == "RX":
			curRX = n
		case section == 2 && k == "TX":
			curTX = n
		}
	}
	return
}

func tuneRings(dev string, dry bool) []Step {
	out, err := command("ethtool", "-g", dev)
	if err != nil {
		return []Step{{Item: dev + " ring", Status: "unsupported", Detail: firstLine(out)}}
	}
	maxRX, maxTX, curRX, curTX := ParseRings(out)
	if maxRX == 0 && maxTX == 0 {
		return []Step{{Item: dev + " ring", Status: "unsupported", Detail: "driver reports no ring sizes"}}
	}
	val := fmt.Sprintf("rx %d tx %d", maxRX, maxTX)
	if curRX == maxRX && curTX == maxTX {
		return []Step{{Item: dev + " ring", Value: val, Status: "unchanged"}}
	}
	if dry {
		return []Step{{Item: dev + " ring", Value: val, Status: "skipped", Detail: "dry-run"}}
	}
	args := []string{"-G", dev}
	if maxRX > 0 && curRX != maxRX {
		args = append(args, "rx", strconv.Itoa(maxRX))
	}
	if maxTX > 0 && curTX != maxTX {
		args = append(args, "tx", strconv.Itoa(maxTX))
	}
	if msg, err := command("ethtool", args...); err != nil {
		// virtio-net only allows ring changes on recent QEMU/kernels.
		return []Step{{Item: dev + " ring", Value: val, Status: "unsupported", Detail: firstLine(msg)}}
	}
	return []Step{{Item: dev + " ring", Value: val, Status: "applied", Detail: fmt.Sprintf("was rx %d tx %d", curRX, curTX)}}
}

// ParseFeatures returns feature -> (state, fixed) from `ethtool -k`.
func ParseFeatures(out string) map[string][2]string {
	res := map[string][2]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		state, rest, _ := strings.Cut(v, " ")
		fixed := ""
		if strings.Contains(rest, "[fixed]") {
			fixed = "fixed"
		}
		res[k] = [2]string{state, fixed}
	}
	return res
}

func tuneOffloads(dev string, dry bool) []Step {
	out, err := command("ethtool", "-k", dev)
	if err != nil {
		return []Step{{Item: dev + " offload", Status: "unsupported", Detail: firstLine(out)}}
	}
	feats := ParseFeatures(out)
	var steps []Step
	for _, o := range offloads {
		item := dev + " " + o.short
		f, ok := feats[o.long]
		switch {
		case !ok:
			steps = append(steps, Step{Item: item, Value: o.want, Status: "unsupported", Detail: "feature absent"})
		case f[0] == o.want:
			steps = append(steps, Step{Item: item, Value: o.want, Status: "unchanged"})
		case f[1] == "fixed":
			steps = append(steps, Step{Item: item, Value: o.want, Status: "unsupported", Detail: "fixed " + f[0] + " by driver"})
		case dry:
			steps = append(steps, Step{Item: item, Value: o.want, Status: "skipped", Detail: "dry-run"})
		default:
			if msg, err := command("ethtool", "-K", dev, o.short, o.want); err != nil {
				steps = append(steps, Step{Item: item, Value: o.want, Status: "failed", Detail: firstLine(msg)})
			} else {
				steps = append(steps, Step{Item: item, Value: o.want, Status: "applied"})
			}
		}
	}
	return steps
}

func tuneQueueLen(dev string, dry bool) Step {
	const want = 10000
	item := dev + " txqueuelen"
	b, err := os.ReadFile("/sys/class/net/" + dev + "/tx_queue_len")
	if err != nil {
		return Step{Item: item, Status: "unsupported"}
	}
	cur, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if cur >= want {
		return Step{Item: item, Value: strconv.Itoa(cur), Status: "unchanged"}
	}
	if dry {
		return Step{Item: item, Value: strconv.Itoa(want), Status: "skipped", Detail: "dry-run"}
	}
	if err := os.WriteFile("/sys/class/net/"+dev+"/tx_queue_len", []byte(strconv.Itoa(want)), 0o644); err != nil {
		return Step{Item: item, Value: strconv.Itoa(want), Status: "failed", Detail: err.Error()}
	}
	return Step{Item: item, Value: strconv.Itoa(want), Status: "applied", Detail: fmt.Sprintf("was %d", cur)}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
