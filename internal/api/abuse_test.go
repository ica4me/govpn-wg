package api

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/ica4me/govpn-wg/internal/config"
	"github.com/ica4me/govpn-wg/internal/sysopt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func normalServer(t *testing.T, tune func() sysopt.Report) (*Server, string) {
	t.Helper()
	hash, _ := HashPassword("normal-password")
	a, err := NewAuth("admin", hash, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := a.Login("admin", "normal-password", "local")
	if err != nil {
		t.Fatal(err)
	}
	return New(nil, a, slog.New(slog.NewTextHandler(io.Discard, nil)), tune), tok
}
func abuseRequest(h http.Handler, method, path, tok string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAdmissionConcurrencyAndHealth(t *testing.T) {
	for _, global := range []bool{true, false} {
		t.Run(fmt.Sprint(global), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			s, tok := normalServer(t, func() sysopt.Report { close(entered); <-release; return sysopt.Report{} })
			limits := config.DefaultRequestLimits()
			if global {
				limits.Concurrent = 1
			}
			s.SetRequestLimits(limits)
			h := s.Handler()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- abuseRequest(h, "POST", "/api/v1/system/tune", tok) }()
			<-entered
			func() {
				defer close(release)
				path := "/api/v1/system/reconcile"
				if global {
					path = "/api/v1/sites"
				}
				w := abuseRequest(h, "POST", path, tok)
				if w.Code != 429 || w.Header().Get("Retry-After") == "" {
					t.Errorf("concurrent response %d %s", w.Code, w.Body.String())
				}
				if w := abuseRequest(h, "GET", "/api/v1/health", ""); w.Code != 200 {
					t.Error("health blocked")
				}
			}()
			if w := <-done; w.Code != 200 {
				t.Fatal(w.Code)
			}
			if w := abuseRequest(h, "GET", "/api/v1/unknown", tok); w.Code != 404 {
				t.Fatalf("slot not released: %d", w.Code)
			}
		})
	}
}

func TestTokenBudgetBoundedAndExpires(t *testing.T) {
	b := newRequestBudget()
	now := time.Now()
	b.now = func() time.Time { return now }
	l := config.DefaultRequestLimits()
	l.PerMinute = 2
	key := sha256.Sum256([]byte("token"))
	for i := 0; i < 3; i++ {
		ok, retry := b.allow(key, false, l)
		if ok != (i < 2) {
			t.Fatal("rate budget")
		}
		if !ok && retry < 1 {
			t.Fatal("retry")
		}
	}
	other := sha256.Sum256([]byte("other"))
	if ok, _ := b.allow(other, false, l); !ok {
		t.Fatal("tokens not independent")
	}
	for i := 0; i < 11000; i++ {
		b.allow(sha256.Sum256([]byte(fmt.Sprint(i))), false, l)
	}
	if len(b.entries) != 10000 {
		t.Fatalf("table size %d", len(b.entries))
	}
	if ok, _ := b.allow(sha256.Sum256([]byte("new")), false, l); ok {
		t.Fatal("table saturation bypass")
	}
	now = now.Add(time.Minute)
	if ok, _ := b.allow(sha256.Sum256([]byte("new")), false, l); !ok {
		t.Fatal("expired table not reclaimed")
	}
	if len(b.entries) != 1 {
		t.Fatal("expired entries retained")
	}
}

func TestRemoteIPIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set("X-Real-IP", "203.0.113.1")
	if remoteIP(r) != "192.0.2.1" {
		t.Fatal("trusted forwarded headers")
	}
}

func TestMaintenanceDefaultRate(t *testing.T) {
	s, tok := normalServer(t, func() sysopt.Report { return sysopt.Report{} })
	h := s.Handler()
	for i := 0; i < 3; i++ {
		w := abuseRequest(h, "POST", "/api/v1/system/tune", tok)
		want := 200
		if i == 2 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: got %d want %d", i, w.Code, want)
		}
		if want == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing retry")
		}
	}
	if w := abuseRequest(h, "GET", "/api/v1/health", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
