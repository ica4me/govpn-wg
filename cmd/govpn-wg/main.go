// Command govpn-wg is the GoVPN WireGuard engine: a REST API that manages
// isolated WireGuard interfaces for site-to-site hubs and remote clients.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ica4me/govpn-wg/internal/api"
	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/sysopt"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

const usage = `GoVPN (WireGuard Engine) %s

Usage:
  govpn-wg serve        [-config /etc/govpn/wg.env]   run the REST API and engine
  govpn-wg tune         [-config ...] [-dry-run]      kernel + NIC tuning, prints a JSON report
  govpn-wg reconcile    [-config ...]                 apply persisted state once and exit
  govpn-wg teardown     [-config ...]                 remove all govpn-wg interfaces and rules
  govpn-wg hash-password                              read a password, print a bcrypt hash
  govpn-wg version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, api.Version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	path := fs.String("config", envOr("GOVPN_CONFIG", config.DefaultConfigPath), "env file")
	dry := fs.Bool("dry-run", false, "report only, change nothing (tune)")
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "serve":
		err = serve(*path)
	case "tune":
		err = tune(*path, *dry)
	case "reconcile":
		err = withEngine(*path, func(e *engine.Engine) error { return e.Start() })
	case "teardown":
		err = withEngine(*path, func(e *engine.Engine) error { return e.Teardown() })
	case "hash-password":
		err = hashPassword()
	case "version", "-v", "--version":
		fmt.Println(api.Version)
	case "help", "-h", "--help":
		fmt.Printf(usage, api.Version)
	default:
		fmt.Fprintf(os.Stderr, usage, api.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "govpn-wg:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func logger(level string) *slog.Logger {
	l := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func buildEngine(cfg *config.Config, log *slog.Logger) (*engine.Engine, error) {
	store, err := config.OpenStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	var wg wireguard.Manager
	var fw firewall.Applier
	if cfg.DryRun {
		log.Warn("GOVPN_DRY_RUN=1: kernel and firewall are simulated")
		wg, fw = wireguard.NewFake(), &firewall.Fake{}
	} else {
		k, err := wireguard.NewKernel()
		if err != nil {
			return nil, err
		}
		ipt, err := firewall.NewIPTables()
		if err != nil {
			k.Close()
			return nil, err
		}
		wg, fw = k, ipt
	}
	return engine.New(engine.Options{
		Config: cfg, Store: store, WG: wg, Firewall: fw, Logger: log,
		DetectPublic: sysopt.PublicInterface,
	}), nil
}

func withEngine(path string, fn func(*engine.Engine) error) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	e, err := buildEngine(cfg, logger(cfg.LogLevel))
	if err != nil {
		return err
	}
	defer e.Close()
	return fn(e)
}

func tuneOptions(cfg *config.Config, publicIf string, dry bool) sysopt.Options {
	return sysopt.Options{PublicIf: publicIf, TuneNIC: cfg.TuneNIC, RingMode: cfg.RingMode,
		Extra: cfg.SysctlExtra, WriteFile: true, DryRun: dry || cfg.DryRun}
}

func tune(path string, dry bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	pub := cfg.PublicIf
	if pub == "" {
		pub, _, _ = sysopt.PublicInterface()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sysopt.Run(tuneOptions(cfg, pub, dry)))
}

func serve(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	log := logger(cfg.LogLevel)
	key, err := api.LoadSigningKey(cfg.DataDir)
	if err != nil {
		return err
	}
	auth, err := api.NewAuth(cfg.AdminUser, cfg.AdminPasswordHash, key, cfg.TokenTTL)
	if err != nil {
		return err
	}
	eng, err := buildEngine(cfg, log)
	if err != nil {
		return err
	}
	defer eng.Close()

	runTune := func() sysopt.Report {
		r := sysopt.Run(tuneOptions(cfg, eng.PublicIf(), false))
		summarize(log, r)
		return r
	}
	if cfg.TuneOnStart {
		runTune()
	} else if !cfg.DryRun {
		sysopt.EnsureForwarding("", false)
	}
	if err := eng.Start(); err != nil {
		return fmt.Errorf("initial apply failed: %w", err)
	}
	log.Info("engine started", "endpoint", eng.Endpoint(), "public_if", eng.PublicIf())

	stop := make(chan struct{})
	go eng.Loop(30*time.Second, stop)

	srv := &http.Server{
		Addr: cfg.Listen, Handler: api.New(eng, auth, log, runTune).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("api listening", "addr", ln.Addr().String(), "version", api.Version)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("SIGHUP: reconciling")
			if err := eng.Reconcile(); err != nil {
				log.Error("reconcile failed", "err", err)
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	close(stop)
	shut, c2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer c2()
	log.Info("shutting down; tunnels stay up")
	return srv.Shutdown(shut)
}

func summarize(log *slog.Logger, r sysopt.Report) {
	count := map[string]int{}
	for _, group := range [][]sysopt.Step{r.Sysctl, r.Modules, r.NIC} {
		for _, s := range group {
			count[s.Status]++
			if s.Status == "failed" || (s.Status == "unsupported" && !strings.Contains(s.Item, "accept_ra")) {
				log.Warn("tuning", "item", s.Item, "status", s.Status, "detail", s.Detail)
			}
		}
	}
	log.Info("tuning done", "public_if", r.PublicIf, "applied", count["applied"], "unchanged", count["unchanged"],
		"unsupported", count["unsupported"], "failed", count["failed"])
}

func hashPassword() error {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pw = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("no password on stdin")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	h, err := api.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
