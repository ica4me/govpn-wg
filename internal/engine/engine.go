// Package engine turns the persistent state into kernel objects: WireGuard
// interfaces and peers (via wireguard.Manager), routes, and iptables rules
// (via firewall.Applier). Every mutation follows the same transaction:
//
//	clone state -> mutate clone -> validate -> apply to kernel -> persist
//
// If the kernel apply fails the previous state is re-applied; if the write to
// disk fails the kernel is rolled back too. The live state is only replaced
// after both steps succeeded.
package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

// Interface name prefixes. Kernel limit is 15 bytes. New interfaces are
// named after the site/group ("wg-s-kantor-pus", "wg-c-default"); legacy
// numbered names ("wg-s1") from older versions stay valid and are never renamed.
const (
	SitePrefix   = "wg-s"
	GroupPrefix  = "wg-c"
	DefaultGroup = "default"
)

var ownedRe = regexp.MustCompile(config.OwnedIfacePattern)

// Owned reports whether an interface name belongs to govpn-wg.
func Owned(name string) bool { return ownedRe.MatchString(name) }

// Error carries an HTTP status for the API layer.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func bad(format string, a ...any) error {
	return &Error{http.StatusUnprocessableEntity, fmt.Sprintf(format, a...)}
}
func conflict(format string, a ...any) error {
	return &Error{http.StatusConflict, fmt.Sprintf(format, a...)}
}
func notFound(kind, id string) error {
	return &Error{http.StatusNotFound, fmt.Sprintf("%s %q not found", kind, id)}
}

// StatusOf maps an error to an HTTP status code.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}

// Options wires dependencies; tests replace the kernel parts with fakes.
type Options struct {
	Config       *config.Config
	Store        *config.Store
	WG           wireguard.Manager
	Firewall     firewall.Applier
	Logger       *slog.Logger
	PortsInUse   func() map[int]bool
	DetectPublic func() (string, netip.Addr, error)
}

type Engine struct {
	cfg   *config.Config
	store *config.Store
	wg    wireguard.Manager
	fw    firewall.Applier
	log   *slog.Logger

	portsInUse   func() map[int]bool
	detectPublic func() (string, netip.Addr, error)

	mu       sync.Mutex // serializes mutations and kernel apply
	pubMu    sync.RWMutex
	publicIf string
	endpoint string
	lastErr  string
	lastSync time.Time
}

func New(o Options) *Engine {
	e := &Engine{cfg: o.Config, store: o.Store, wg: o.WG, fw: o.Firewall, log: o.Logger,
		portsInUse: o.PortsInUse, detectPublic: o.DetectPublic}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.portsInUse == nil {
		e.portsInUse = wireguard.UsedUDPPorts
	}
	e.refreshPublic()
	return e
}

// refreshPublic resolves the egress interface and the endpoint host.
func (e *Engine) refreshPublic() {
	pubIf, addr := e.cfg.PublicIf, netip.Addr{}
	if e.detectPublic != nil {
		if dev, a, err := e.detectPublic(); err == nil {
			if pubIf == "" {
				pubIf = dev
			}
			addr = a
		} else {
			e.log.Warn("public interface detection failed", "err", err)
		}
	}
	endpoint := e.cfg.Endpoint
	if endpoint == "" && addr.IsValid() {
		endpoint = addr.String()
	}
	e.pubMu.Lock()
	e.publicIf, e.endpoint = pubIf, endpoint
	e.pubMu.Unlock()
}

func (e *Engine) PublicIf() string {
	e.pubMu.RLock()
	defer e.pubMu.RUnlock()
	return e.publicIf
}

// Endpoint is the host written into generated peer configs.
func (e *Engine) Endpoint() string {
	e.pubMu.RLock()
	defer e.pubMu.RUnlock()
	return e.endpoint
}

// Start applies the persisted state once (boot / service restart).
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLocked(e.store.Snapshot())
}

// Reconcile re-applies the state: repairs deleted links, flushed rules and a
// changed public interface. Cheap when nothing drifted.
func (e *Engine) Reconcile() error {
	e.refreshPublic()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLocked(e.store.Snapshot())
}

// Loop runs Reconcile every interval until stop is closed.
func (e *Engine) Loop(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := e.Reconcile(); err != nil {
				e.log.Error("reconcile failed", "err", err)
			}
		}
	}
}

func (e *Engine) applyLocked(st *config.State) error {
	err := e.validate(st)
	var specs []wireguard.IfaceSpec
	var rules firewall.Ruleset
	if err == nil {
		specs, rules, err = e.build(st)
	}
	// Firewall first: iptables accepts interface names that do not exist yet,
	// so isolation is in place before a link comes up. If the firewall cannot
	// be applied the kernel is left untouched (fail closed: the previous rule
	// set plus the static wg-s+/wg-c+ catch-all stay active).
	if err == nil {
		if ferr := e.fw.Apply(rules); ferr != nil {
			err = fmt.Errorf("firewall: %w", ferr)
		}
	}
	if err == nil {
		err = e.wg.Sync(specs, Owned)
	}
	e.pubMu.Lock()
	e.lastSync = time.Now()
	e.lastErr = ""
	if err != nil {
		e.lastErr = err.Error()
	}
	e.pubMu.Unlock()
	return err
}

// mutate runs fn on a clone of the state and commits it transactionally.
func (e *Engine) mutate(fn func(st *config.State) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.store.Snapshot()
	next := prev.Clone()
	if err := fn(next); err != nil {
		return err
	}
	if err := e.validate(next); err != nil {
		return err
	}
	if err := e.applyLocked(next); err != nil {
		e.log.Error("apply failed, restoring previous state", "err", err)
		if rerr := e.applyLocked(prev); rerr != nil {
			e.log.Error("restore failed", "err", rerr)
		}
		return &Error{http.StatusBadGateway, "kernel apply failed: " + err.Error()}
	}
	if err := e.store.Replace(next); err != nil {
		perr := fmt.Errorf("persist state: %w", err)
		if rerr := e.applyLocked(prev); rerr != nil {
			e.log.Error("restore after persist failure failed", "err", rerr)
			perr = errors.Join(perr, fmt.Errorf("restore: %w", rerr))
		}
		e.pubMu.Lock()
		e.lastErr = perr.Error()
		e.pubMu.Unlock()
		return perr
	}
	return nil
}

// LastSync returns time and error of the most recent kernel apply.
func (e *Engine) LastSync() (time.Time, string) {
	e.pubMu.RLock()
	defer e.pubMu.RUnlock()
	return e.lastSync, e.lastErr
}

// Snapshot exposes a copy of the state (read-only use).
func (e *Engine) Snapshot() *config.State { return e.store.Snapshot() }

// Config exposes runtime configuration.
func (e *Engine) Config() *config.Config { return e.cfg }

// Close releases the netlink handles.
func (e *Engine) Close() error { return e.wg.Close() }

// Teardown removes every owned interface and firewall chain (uninstall).
func (e *Engine) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(e.wg.Sync(nil, Owned), e.fw.Clean())
}
