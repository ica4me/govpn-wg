package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func credServer(t *testing.T, user, password string) (*Server, *Auth, string) {
	t.Helper()
	dir := t.TempDir()
	hash, err := HashInitialPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth(user, hash, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a.SetPasswordDir(dir)
	return New(nil, a, slog.New(slog.NewTextHandler(io.Discard, nil)), nil), a, dir
}

func call(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.RemoteAddr = "192.0.2.10:5000"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func loginToken(t *testing.T, h http.Handler, user, password string, want int) string {
	t.Helper()
	w := call(t, h, "POST", "/api/v1/auth/login", `{"username":"`+user+`","password":"`+password+`"}`, "")
	if w.Code != want {
		t.Fatalf("login %s: %d want %d: %s", user, w.Code, want, w.Body.String())
	}
	var v struct {
		Token string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return v.Token
}

func TestChangeUsernameAndPassword(t *testing.T) {
	s, _, dir := credServer(t, "admin", "old-password-1")
	h := s.Handler()
	tok := loginToken(t, h, "admin", "old-password-1", 200)

	if w := call(t, h, "GET", "/api/v1/auth/me", "", tok); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"username": "admin"`)) {
		t.Fatalf("me: %d %s", w.Code, w.Body.String())
	}
	for name, body := range map[string]string{
		"wrong current":  `{"current_password":"nope","new_username":"boss"}`,
		"bad username":   `{"current_password":"old-password-1","new_username":"bad name!"}`,
		"short password": `{"current_password":"old-password-1","new_password":"short"}`,
		"bootstrap pw":   `{"current_password":"old-password-1","new_password":"admin"}`,
		"nothing":        `{"current_password":"old-password-1"}`,
		"unknown field":  `{"current_password":"old-password-1","role":"root"}`,
	} {
		if w := call(t, h, "POST", "/api/v1/auth/credentials", body, tok); w.Code < 400 {
			t.Fatalf("%s accepted: %d", name, w.Code)
		}
	}
	w := call(t, h, "POST", "/api/v1/auth/credentials", `{"current_password":"old-password-1","new_username":"boss","new_password":"new-password-2"}`, tok)
	if w.Code != 200 {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if call(t, h, "GET", "/api/v1/auth/me", "", tok).Code != 401 {
		t.Fatal("old token still valid after credential change")
	}
	loginToken(t, h, "admin", "new-password-2", 401)
	loginToken(t, h, "boss", "old-password-1", 401)
	tok = loginToken(t, h, "boss", "new-password-2", 200)

	// Username-only change keeps the password and still revokes tokens.
	if w := call(t, h, "POST", "/api/v1/auth/credentials", `{"current_password":"new-password-2","new_username":"boss2"}`, tok); w.Code != 200 {
		t.Fatalf("username-only change: %d %s", w.Code, w.Body.String())
	}
	if call(t, h, "GET", "/api/v1/auth/me", "", tok).Code != 401 {
		t.Fatal("token survived username change")
	}
	loginToken(t, h, "boss2", "new-password-2", 200)

	// Persisted and reloadable with secure permissions.
	for _, f := range []string{adminUserFile, adminPasswordFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s not persisted 0600: %v %v", f, err, fi)
		}
	}
	if u, err := LoadAdminUser(dir, "admin"); err != nil || u != "boss2" {
		t.Fatalf("reload user = %q %v", u, err)
	}
}

func TestBootstrapMustChangePasswordViaCredentials(t *testing.T) {
	s, a, _ := credServer(t, "admin", "admin")
	h := s.Handler()
	tok := loginToken(t, h, "admin", "admin", 200)
	if call(t, h, "GET", "/api/v1/sites", "", tok).Code != 403 {
		t.Fatal("bootstrap token reached management API")
	}
	if call(t, h, "GET", "/api/v1/auth/me", "", tok).Code != 200 {
		t.Fatal("bootstrap token cannot read account")
	}
	if w := call(t, h, "POST", "/api/v1/auth/credentials", `{"current_password":"admin","new_username":"boss"}`, tok); w.Code != 422 {
		t.Fatalf("username-only change kept bootstrap password: %d", w.Code)
	}
	if w := call(t, h, "POST", "/api/v1/auth/credentials", `{"current_password":"admin","new_username":"boss","new_password":"strong-pass-9"}`, tok); w.Code != 200 {
		t.Fatalf("bootstrap credential change: %d %s", w.Code, w.Body.String())
	}
	if a.RequiresPasswordChange() {
		t.Fatal("still gated after change")
	}
	tok = loginToken(t, h, "boss", "strong-pass-9", 200)
	if call(t, h, "GET", "/api/v1/auth/me", "", tok).Code != 200 {
		t.Fatal("new login rejected")
	}
}

func TestResetAdminRestoresBootstrap(t *testing.T) {
	dir := t.TempDir()
	if err := writePrivate(dir, adminUserFile, "boss"); err != nil {
		t.Fatal(err)
	}
	if err := ResetAdmin(dir); err != nil {
		t.Fatal(err)
	}
	user, err := LoadAdminUser(dir, "ignored")
	if err != nil || user != "admin" {
		t.Fatalf("user after reset = %q %v", user, err)
	}
	hash, err := LoadPasswordHash(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth(user, hash, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !a.RequiresPasswordChange() {
		t.Fatal("reset login does not force a change")
	}
	if _, _, err := a.Login("admin", "admin", "192.0.2.1"); err != nil {
		t.Fatalf("admin/admin rejected after reset: %v", err)
	}
}

func TestLoadAdminUserRejectsInsecureFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, adminUserFile)
	if err := os.WriteFile(p, []byte("boss"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdminUser(dir, "admin"); err == nil {
		t.Fatal("world-readable admin user file accepted")
	}
	if err := os.WriteFile(p, []byte("bad name"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdminUser(dir, "admin"); err == nil {
		t.Fatal("invalid username accepted")
	}
}
