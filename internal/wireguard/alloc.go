package wireguard

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/ica4me/govpn-wg/internal/config"
)

// ErrPoolExhausted is returned when every 172.31.201-250.0/24 is taken.
var ErrPoolExhausted = errors.New("no free /24 left in 172.31.201.0-172.31.250.0")

// AllocateSubnet picks a random free /24 from the tunnel pool. A candidate is
// rejected when it overlaps any prefix in used (state subnets, kernel routes,
// interface addresses, site LANs, server LAN).
func AllocateSubnet(used []netip.Prefix) (netip.Prefix, error) {
	var free []netip.Prefix
	for o := config.PoolFirst; o <= config.PoolLast; o++ {
		cand := config.PoolPrefix(o)
		clash := false
		for _, u := range used {
			// The 172.16.0.0/12 style supernets of a default-ish LAN route
			// would block the entire pool; only exact overlaps count, so
			// callers must not pass routes broader than /16 here.
			if u.Overlaps(cand) {
				clash = true
				break
			}
		}
		if !clash {
			free = append(free, cand)
		}
	}
	if len(free) == 0 {
		return netip.Prefix{}, ErrPoolExhausted
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(free))))
	if err != nil {
		return netip.Prefix{}, err
	}
	return free[n.Int64()], nil
}

// PoolSummary returns the minimal CIDR set covering 172.31.201.0-172.31.250.255.
func PoolSummary() []netip.Prefix {
	var out []netip.Prefix
	start, end := config.PoolFirst, config.PoolLast+1 // half-open, in /24 units
	for start < end {
		size := 1
		for size*2 <= end-start && start%(size*2) == 0 {
			size *= 2
		}
		bits := 24
		for s := size; s > 1; s /= 2 {
			bits--
		}
		out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 31, byte(start), 0}), bits))
		start += size
	}
	return out
}

// AllocatePort returns the lowest port >= base not present in taken.
func AllocatePort(base int, taken map[int]bool) (int, error) {
	for p := base; p <= 65535; p++ {
		if !taken[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free UDP port at or above %d", base)
}

// UsedUDPPorts reads /proc/net/udp{,6} for locally bound UDP ports.
func UsedUDPPorts() map[int]bool {
	out := map[int]bool{}
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if p, err := strconv.ParseUint(hexPort, 16, 16); err == nil {
				out[int(p)] = true
			}
		}
	}
	return out
}

// NextIfaceName returns prefix+N with the lowest unused N >= 1.
func NextIfaceName(prefix string, taken map[string]bool) string {
	for n := 1; ; n++ {
		name := prefix + strconv.Itoa(n)
		if !taken[name] {
			return name
		}
	}
}

// NextHost returns the lowest free host address .first-.254 in a /24.
func NextHost(subnet netip.Prefix, first int, taken map[string]bool) (netip.Addr, error) {
	for n := first; n <= 254; n++ {
		a := config.HostIn(subnet, n)
		if !taken[a.String()] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("subnet %s is full", subnet)
}
