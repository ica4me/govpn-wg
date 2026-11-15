//go:build linux

package sysopt

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// PublicInterface returns the egress interface of the lowest-metric IPv4
// default route, and its primary global address.
func PublicInterface() (string, netip.Addr, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", netip.Addr{}, err
	}
	best, bestMetric := -1, int(^uint(0)>>1)
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if r.LinkIndex == 0 || r.Table != 254 {
			continue
		}
		if r.Priority < bestMetric {
			best, bestMetric = r.LinkIndex, r.Priority
		}
	}
	if best < 0 {
		return "", netip.Addr{}, fmt.Errorf("no IPv4 default route")
	}
	link, err := netlink.LinkByIndex(best)
	if err != nil {
		return "", netip.Addr{}, err
	}
	var addr netip.Addr
	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil {
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok && ip.Unmap().IsGlobalUnicast() {
				addr = ip.Unmap()
				break
			}
		}
	}
	return link.Attrs().Name, addr, nil
}
