package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ica4me/govpn-wg/internal/api"
	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/engine"
	"github.com/ica4me/govpn-wg/internal/firewall"
	"github.com/ica4me/govpn-wg/internal/sysopt"
	"github.com/ica4me/govpn-wg/internal/wireguard"
)

func setup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GOVPN_DATA_DIR", dir)
	t.Setenv("GOVPN_ENDPOINT", "vpn.example.org")
	t.Setenv("GOVPN_SERVER_LAN", "10.10.9.0/24")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := config.OpenStore(dir)
	eng := engine.New(engine.Options{Config: cfg, Store: st, WG: wireguard.NewFake(), Firewall: &firewall.Fake{},
		PortsInUse:   func() map[int]bool { return nil },
		DetectPublic: func() (string, netip.Addr, error) { return "eth0", netip.Addr{}, nil }})
	hash, _ := api.HashPassword("s3cret-pass")
	key, _ := api.LoadSigningKey(dir)
	auth, err := api.NewAuth("admin", hash, key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(eng, auth, discard(), func() sysopt.Report { return sysopt.Report{} }).Handler())
	t.Cleanup(srv.Close)

	res := do(t, srv, "", "POST", "/api/v1/auth/login", `{"username":"admin","password":"s3cret-pass"}`, 200)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(res, &tok)
	return srv, tok.AccessToken
}

func do(t *testing.T, srv *httptest.Server, token, method, path, body string, want int) []byte {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		t.Fatalf("%s %s: status %d want %d: %s", method, path, res.StatusCode, want, b)
	}
	return b
}

func TestAuth(t *testing.T) {
	srv, tok := setup(t)
	do(t, srv, "", "GET", "/api/v1/health", "", 200)
	do(t, srv, "", "GET", "/api/v1/sites", "", 401)
	do(t, srv, "garbage", "GET", "/api/v1/sites", "", 401)
	do(t, srv, "", "POST", "/api/v1/auth/login", `{"username":"admin","password":"wrong"}`, 401)
	do(t, srv, tok, "GET", "/api/v1/sites", "", 200)
	do(t, srv, tok, "GET", "/api/v1/system/status", "", 200)
}

func TestFlow(t *testing.T) {
	srv, tok := setup(t)
	do(t, srv, tok, "POST", "/api/v1/sites", `{"name":"Site A","local_subnets":["192.168.10.0/24"],"bogus":1}`, 400)
	b := do(t, srv, tok, "POST", "/api/v1/sites", `{"name":"Site A","local_subnets":["192.168.10.0/24","10.50.0.0/16"],"can_access_server_lan":true}`, 201)
	if strings.Contains(string(b), "private_key") || strings.Contains(string(b), "preshared") {
		t.Fatal("secret leaked in site view")
	}
	do(t, srv, tok, "POST", "/api/v1/sites", `{"name":"Site B","local_subnets":["192.168.20.0/24"],"allowed_target_sites":["site-a"],"tunnel_mode":"full","mtu":1400}`, 201)
	do(t, srv, tok, "PUT", "/api/v1/sites/site-a", `{"allowed_target_sites":["site-b"]}`, 200)
	do(t, srv, tok, "GET", "/api/v1/sites/site-x", "", 404)

	script := string(do(t, srv, tok, "GET", "/api/v1/sites/site-a/download/linux", "", 200))
	for _, want := range []string{"Endpoint = vpn.example.org:3478", "wg-quick@$IFACE", "masquerade", "192.168.20.0/24"} {
		if !strings.Contains(script, want) {
			t.Fatalf("site script missing %q", want)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		f := filepath.Join(t.TempDir(), "s.sh")
		_ = os.WriteFile(f, []byte(script), 0o600)
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("site script syntax: %v %s", err, out)
		}
	}
	conf := string(do(t, srv, tok, "GET", "/api/v1/sites/site-b/download/windows", "", 200))
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0\n") || strings.Contains(conf, "::/0") || !strings.Contains(conf, "MTU = 1400") {
		t.Fatalf("full-tunnel conf must be IPv4 only:\n%s", conf)
	}

	do(t, srv, tok, "POST", "/api/v1/clients", `{"username":"andi","target_sites":["site-a"],"allow_server_lan":false,"tunnel_mode":"split","dns":["9.9.9.9"]}`, 201)
	c := string(do(t, srv, tok, "GET", "/api/v1/clients/andi/download/conf", "", 200))
	// Split tunnel + public resolver outside AllowedIPs: no DNS= line, so the
	// client's system resolver is not hijacked.
	if strings.Contains(c, "DNS =") || !strings.Contains(c, "192.168.10.0/24") || strings.Contains(c, "10.10.9.0/24") {
		t.Fatalf("client conf:\n%s", c)
	}
	if strings.Contains(sh0(t, srv, tok), "resolvconf") {
		t.Fatal("split client script touches resolver")
	}
	sh := string(do(t, srv, tok, "GET", "/api/v1/clients/andi/download/linux", "", 200))
	if bash, err := exec.LookPath("bash"); err == nil {
		f := filepath.Join(t.TempDir(), "c.sh")
		_ = os.WriteFile(f, []byte(sh), 0o600)
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("client script syntax: %v %s", err, out)
		}
	}
	png := do(t, srv, tok, "GET", "/api/v1/clients/andi/download/qr", "", 200)
	if !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatal("qr is not png")
	}
	do(t, srv, tok, "PUT", "/api/v1/clients/andi", `{"tunnel_mode":"full"}`, 200)
	if c := string(do(t, srv, tok, "GET", "/api/v1/clients/andi/download/conf", "", 200)); !strings.Contains(c, "DNS = 9.9.9.9") {
		t.Fatalf("full tunnel must keep DNS:\n%s", c)
	}
	// Resolver inside the tunnel (server LAN) is kept in split mode.
	do(t, srv, tok, "PUT", "/api/v1/clients/andi", `{"tunnel_mode":"split","allow_server_lan":true,"dns":["10.10.9.53","1.1.1.1"]}`, 200)
	if c := string(do(t, srv, tok, "GET", "/api/v1/clients/andi/download/conf", "", 200)); !strings.Contains(c, "DNS = 10.10.9.53\n") {
		t.Fatalf("split tunnel internal DNS:\n%s", c)
	}
	do(t, srv, tok, "DELETE", "/api/v1/sites/site-a", "", 204)
	list := string(do(t, srv, tok, "GET", "/api/v1/clients/andi", "", 200))
	if strings.Contains(list, "site-a") {
		t.Fatal("deleted site still referenced")
	}
	do(t, srv, tok, "DELETE", "/api/v1/clients/andi", "", 204)
	do(t, srv, tok, "DELETE", "/api/v1/clients/andi", "", 404)
}

func sh0(t *testing.T, srv *httptest.Server, tok string) string {
	return string(do(t, srv, tok, "GET", "/api/v1/clients/andi/download/linux", "", 200))
}
