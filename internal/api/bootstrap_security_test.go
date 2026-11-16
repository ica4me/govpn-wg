package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBootstrapPasswordGateLifecycle(t *testing.T) {
	hash, _ := HashInitialPassword("admin")
	a, err := NewAuth("admin", hash, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a.SetPasswordDir(dir)
	s := New(nil, a, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	request := func(h http.Handler, method, path, body, token string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d want %d: %s", path, w.Code, want, w.Body.String())
		}
		return w
	}
	login := func(password string, required bool) string {
		t.Helper()
		w := request(s.Handler(), "POST", "/api/v1/auth/login", `{"username":"admin","password":"`+password+`"}`, "", 200)
		var v struct {
			Token    string `json:"access_token"`
			Required *bool  `json:"requires_password_change"`
		}
		json.Unmarshal(w.Body.Bytes(), &v)
		if v.Required == nil || *v.Required != required {
			t.Fatalf("requires_password_change: %s", w.Body.String())
		}
		return v.Token
	}
	tok := login("admin", true)
	for _, path := range []string{"/api/v1/sites", "/api/v1/clients", "/api/v1/groups", "/api/v1/system/tune", "/api/v1/system/reconcile"} {
		request(s.Handler(), "POST", path, `{}`, tok, 403)
	}
	called := false
	status := a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	request(status, "GET", "/api/v1/system/status", "", tok, 200)
	if !called {
		t.Fatal("status blocked")
	}
	request(s.Handler(), "POST", "/api/v1/auth/password", `{"current_password":"admin","new_password":"changed-password"}`, tok, 204)
	if _, err := a.Verify(tok); err == nil {
		t.Fatal("bootstrap JWT not revoked")
	}
	tok = login("changed-password", false)
	request(status, "GET", "/api/v1/sites", "", tok, 200)
	stored, err := LoadPasswordHash(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewAuth("admin", stored, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Verify(tok); err != nil {
		t.Fatal(err)
	}
}
