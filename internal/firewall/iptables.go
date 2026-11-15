package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Applier loads a Ruleset into the kernel.
type Applier interface {
	Apply(r Ruleset) error
	// Clean removes jumps and owned chains (uninstall).
	Clean() error
}

// IPTables shells out to iptables-restore / iptables with fixed arguments
// only. No user-controlled string reaches a shell: rules are passed on stdin
// and every value was validated as CIDR / interface name before rendering.
type IPTables struct {
	mu sync.Mutex
}

func NewIPTables() (*IPTables, error) {
	for _, bin := range []string{"iptables", "iptables-restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("%s not found (apt-get install iptables)", bin)
		}
	}
	return &IPTables{}, nil
}

func run(stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// Apply always reloads the owned chains (cheap, atomic per table), so a
// flushed or edited chain is repaired on the next reconcile, and makes sure
// every jump exists exactly once at position 1 of its built-in chain, so
// rules inserted later by Docker/ufw cannot run before the isolation rules.
func (t *IPTables) Apply(r Ruleset) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	text := r.Render()
	if _, err := run(text, "iptables-restore", "-w", "5", "--noflush", "--test"); err != nil {
		return fmt.Errorf("rule set rejected: %w", err)
	}
	if _, err := run(text, "iptables-restore", "-w", "5", "--noflush"); err != nil {
		return err
	}
	for _, j := range Jumps {
		if err := ensureFirst(j); err != nil {
			return err
		}
	}
	return nil
}

// ensureFirst makes "-A From -j To" the first rule of From, exactly once.
func ensureFirst(j Jump) error {
	out, err := run("", "iptables", "-w", "5", "-t", j.Table, "-S", j.From)
	if err != nil {
		return err
	}
	want := "-A " + j.From + " -j " + j.To
	var rules []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			rules = append(rules, strings.TrimSpace(l))
		}
	}
	count := 0
	for _, l := range rules {
		if l == want {
			count++
		}
	}
	if count == 1 && rules[0] == want {
		return nil
	}
	for i := 0; i < count; i++ {
		if _, err := run("", "iptables", "-w", "5", "-t", j.Table, "-D", j.From, "-j", j.To); err != nil {
			return err
		}
	}
	_, err = run("", "iptables", "-w", "5", "-t", j.Table, "-I", j.From, "1", "-j", j.To)
	return err
}

func (t *IPTables) Clean() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var errs []error
	for _, j := range Jumps {
		for {
			if _, err := run("", "iptables", "-w", "5", "-t", j.Table, "-D", j.From, "-j", j.To); err != nil {
				break
			}
		}
		if _, err := run("", "iptables", "-w", "5", "-t", j.Table, "-F", j.To); err == nil {
			if _, err := run("", "iptables", "-w", "5", "-t", j.Table, "-X", j.To); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Fake keeps the last rendered rule set (tests and dry-run).
type Fake struct {
	mu   sync.Mutex
	Last string
	N    int
}

func (f *Fake) Apply(r Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Last = r.Render()
	f.N++
	return nil
}

func (f *Fake) Clean() error { f.Last = ""; return nil }
