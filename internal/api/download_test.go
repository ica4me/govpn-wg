package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// downloadHeaders performs an authenticated download and returns its headers.
func downloadHeaders(t *testing.T, base, token, path string) http.Header {
	t.Helper()
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, res.StatusCode)
	}
	return res.Header
}

// TestDownloadFilenamesKeepExtensions guards the operational contract that a
// WireGuard profile is saved as .conf (never .conf.txt) and a Linux installer
// as .sh, in every supported browser.
func TestDownloadFilenamesKeepExtensions(t *testing.T) {
	srv, tok := setup(t)
	do(t, srv, tok, "POST", "/api/v1/sites", `{"name":"Site A","local_subnets":["192.168.10.0/24"]}`, 201)
	do(t, srv, tok, "POST", "/api/v1/clients", `{"username":"xccvme","target_sites":["site-a"],"tunnel_mode":"split","allow_server_lan":true,"dns":["1.1.1.1"]}`, 201)

	cases := []struct {
		path  string
		name  string
		ctype string
	}{
		{"/api/v1/clients/xccvme/download/conf", "xccvme.conf", "application/octet-stream"},
		{"/api/v1/clients/xccvme/download/linux", "config-xccvme.sh", "text/x-shellscript; charset=utf-8"},
		{"/api/v1/sites/site-a/download/conf", "site-site-a.conf", "application/octet-stream"},
		{"/api/v1/sites/site-a/download/windows", "site-site-a.conf", "application/octet-stream"},
		{"/api/v1/sites/site-a/download/linux", "install-site-site-a.sh", "text/x-shellscript; charset=utf-8"},
	}
	for _, c := range cases {
		h := downloadHeaders(t, srv.URL, tok, c.path)
		cd := h.Get("Content-Disposition")
		if got := h.Get("Content-Type"); got != c.ctype {
			t.Errorf("%s content-type = %q, want %q", c.path, got, c.ctype)
		}
		if !strings.HasPrefix(cd, "attachment;") {
			t.Errorf("%s disposition = %q, want attachment", c.path, cd)
		}
		if !strings.Contains(cd, `filename="`+c.name+`"`) {
			t.Errorf("%s disposition = %q, want filename %q", c.path, cd, c.name)
		}
		if !strings.Contains(cd, "filename*=UTF-8''"+c.name) {
			t.Errorf("%s disposition = %q, want RFC 5987 filename", c.path, cd)
		}
		if strings.Contains(cd, ".txt") {
			t.Errorf("%s disposition = %q must not gain a .txt suffix", c.path, cd)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s x-content-type-options = %q, want nosniff", c.path, got)
		}
	}
}
