// Package config loads /etc/govpn/wg.env and owns the persistent state file.
//
// The env file is parsed by the binary itself (KEY=VALUE, '#' comments,
// optional single/double quotes). Process environment variables with the same
// name override file values, which keeps systemd units and tests simple.
package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultConfigPath = "/etc/govpn/wg.env"
	DefaultDataDir    = "/var/lib/govpn/wg"
	DefaultListen     = "127.0.0.1:8080"
	DefaultBasePort   = 3478
	DefaultMTU        = 1360
	DefaultDNS        = "1.1.1.1"
	DefaultKeepalive  = 25
)

// Config is the runtime configuration. Zero values are never used directly:
// Load fills defaults and Validate rejects anything unsafe.
type Config struct {
	Path string

	Listen   string // REST API bind address
	DataDir  string // state.json, jwt.key
	LogLevel string

	AdminUser         string
	AdminPasswordHash string // bcrypt
	TokenTTL          time.Duration

	Endpoint string // public IP/hostname written into peer configs; auto when empty
	PublicIf string // egress interface for full tunnel; auto when empty

	BasePort   int
	DefaultMTU int
	DNS        []string
	Keepalive  int

	ServerLAN []netip.Prefix // networks behind this hub that peers may be granted
	LanNAT    bool           // masquerade tunnel traffic towards ServerLAN

	MSSMode string // "mtu" (MTU-40) or "pmtu" (--clamp-mss-to-pmtu)

	TuneOnStart bool
	TuneNIC     bool
	RingMode    string // "max" or "skip"
	SysctlExtra map[string]string

	Firewall string // "iptables" (only backend for now)
	DryRun   bool   // no kernel/netfilter changes; used by tests
}

// Load reads the env file (missing file is allowed: defaults + process env).
func Load(path string) (*Config, error) {
	values := map[string]string{}
	if path != "" {
		f, err := os.Open(path)
		switch {
		case err == nil:
			defer f.Close()
			if err := parseEnv(f, values); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case os.IsNotExist(err):
		default:
			return nil, err
		}
	}
	get := func(key, def string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		if v, ok := values[key]; ok {
			return v
		}
		return def
	}
	c := &Config{
		Path:              path,
		Listen:            get("GOVPN_LISTEN", DefaultListen),
		DataDir:           get("GOVPN_DATA_DIR", DefaultDataDir),
		LogLevel:          get("GOVPN_LOG_LEVEL", "info"),
		AdminUser:         get("GOVPN_ADMIN_USER", "admin"),
		AdminPasswordHash: get("GOVPN_ADMIN_PASSWORD_HASH", ""),
		Endpoint:          get("GOVPN_ENDPOINT", ""),
		PublicIf:          get("GOVPN_PUBLIC_IF", ""),
		MSSMode:           get("GOVPN_MSS_MODE", "mtu"),
		RingMode:          get("GOVPN_NIC_RING", "max"),
		Firewall:          get("GOVPN_FIREWALL", "iptables"),
		SysctlExtra:       map[string]string{},
	}
	var err error
	if c.BasePort, err = atoi(get("GOVPN_BASE_PORT", strconv.Itoa(DefaultBasePort))); err != nil {
		return nil, fmt.Errorf("GOVPN_BASE_PORT: %w", err)
	}
	if c.DefaultMTU, err = atoi(get("GOVPN_DEFAULT_MTU", strconv.Itoa(DefaultMTU))); err != nil {
		return nil, fmt.Errorf("GOVPN_DEFAULT_MTU: %w", err)
	}
	if c.Keepalive, err = atoi(get("GOVPN_KEEPALIVE", strconv.Itoa(DefaultKeepalive))); err != nil {
		return nil, fmt.Errorf("GOVPN_KEEPALIVE: %w", err)
	}
	ttl, err := time.ParseDuration(get("GOVPN_TOKEN_TTL", "12h"))
	if err != nil {
		return nil, fmt.Errorf("GOVPN_TOKEN_TTL: %w", err)
	}
	if ttl < 5*time.Minute || ttl > 7*24*time.Hour {
		return nil, fmt.Errorf("GOVPN_TOKEN_TTL: %s outside 5m..168h", ttl)
	}
	c.TokenTTL = ttl
	if c.DNS, err = ParseDNS(get("GOVPN_DNS", DefaultDNS)); err != nil {
		return nil, fmt.Errorf("GOVPN_DNS: %w", err)
	}
	if c.ServerLAN, err = ParsePrefixList(get("GOVPN_SERVER_LAN", "")); err != nil {
		return nil, fmt.Errorf("GOVPN_SERVER_LAN: %w", err)
	}
	c.LanNAT = parseBool(get("GOVPN_LAN_NAT", "1"))
	c.TuneOnStart = parseBool(get("GOVPN_TUNE_ON_START", "1"))
	c.TuneNIC = parseBool(get("GOVPN_TUNE_NIC", "1"))
	c.DryRun = parseBool(get("GOVPN_DRY_RUN", "0"))
	for _, item := range strings.Split(get("GOVPN_SYSCTL_EXTRA", ""), ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("GOVPN_SYSCTL_EXTRA: %q is not key=value", item)
		}
		c.SysctlExtra[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return c, c.Validate()
}

// Validate rejects values that would produce broken or unsafe kernel config.
func (c *Config) Validate() error {
	if c.BasePort < 1 || c.BasePort > 65535 {
		return fmt.Errorf("GOVPN_BASE_PORT out of range")
	}
	if err := ValidMTU(c.DefaultMTU); err != nil {
		return fmt.Errorf("GOVPN_DEFAULT_MTU: %w", err)
	}
	if c.Keepalive < 0 || c.Keepalive > 3600 {
		return fmt.Errorf("GOVPN_KEEPALIVE out of range")
	}
	if c.MSSMode != "mtu" && c.MSSMode != "pmtu" {
		return fmt.Errorf("GOVPN_MSS_MODE must be mtu or pmtu")
	}
	if c.RingMode != "max" && c.RingMode != "skip" {
		return fmt.Errorf("GOVPN_NIC_RING must be max or skip")
	}
	if c.Firewall != "iptables" {
		return fmt.Errorf("GOVPN_FIREWALL: only iptables is supported")
	}
	if c.PublicIf != "" && !ValidIfName(c.PublicIf) {
		return fmt.Errorf("GOVPN_PUBLIC_IF invalid")
	}
	if c.Endpoint != "" && !ValidHost(c.Endpoint) {
		return fmt.Errorf("GOVPN_ENDPOINT must be an IP or hostname")
	}
	if !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("GOVPN_DATA_DIR must be absolute")
	}
	for _, p := range c.ServerLAN {
		if InPool(p) {
			return fmt.Errorf("GOVPN_SERVER_LAN %s overlaps the tunnel pool", p)
		}
	}
	return nil
}

// ValidMTU accepts the range WireGuard can actually carry over IPv4/IPv6.
func ValidMTU(mtu int) error {
	if mtu < 1280 || mtu > 9000 {
		return fmt.Errorf("mtu must be 1280-9000")
	}
	return nil
}

func ParseDNS(s string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", part)
		}
		out = append(out, a.String())
	}
	if len(out) > 4 {
		return nil, fmt.Errorf("at most 4 DNS servers")
	}
	return out, nil
}

// ParsePrefixList parses comma separated IPv4 CIDRs, masking host bits.
func ParsePrefixList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := ParseCIDR4(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseEnv(f *os.File, out map[string]string) error {
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '\'' && v[len(v)-1] == '\'' || v[0] == '"' && v[len(v)-1] == '"') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return sc.Err()
}

func atoi(s string) (int, error) { return strconv.Atoi(strings.TrimSpace(s)) }

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "y":
		return true
	}
	return false
}
