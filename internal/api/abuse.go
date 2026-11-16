package api

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ica4me/govpn-wg/internal/config"
)

// requestBudget is a fixed-window, bounded table keyed by SHA-256 of verified JWTs.
// Saturation rejects new identities rather than evicting active rate limits.
type requestBudget struct {
	mu      sync.Mutex
	entries map[[32]byte]budgetEntry
	now     func() time.Time
}
type budgetEntry struct {
	start                 time.Time
	requests, maintenance int
}

func newRequestBudget() *requestBudget {
	return &requestBudget{entries: make(map[[32]byte]budgetEntry), now: time.Now}
}
func (b *requestBudget) allow(key [32]byte, maintenance bool, limits config.RequestLimits) (bool, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	entry, exists := b.entries[key]
	if !exists && len(b.entries) >= 10000 {
		for k, v := range b.entries {
			if now.Sub(v.start) >= time.Minute {
				delete(b.entries, k)
			}
		}
		if len(b.entries) >= 10000 {
			return false, 60
		}
	}
	if !exists || now.Sub(entry.start) >= time.Minute {
		entry = budgetEntry{start: now}
	}
	retry := int(entry.start.Add(time.Minute).Sub(now).Seconds()) + 1
	if retry < 1 {
		retry = 1
	}
	if entry.requests >= limits.PerMinute || (maintenance && entry.maintenance >= limits.MaintenancePerMinute) {
		return false, retry
	}
	entry.requests++
	if maintenance {
		entry.maintenance++
	}
	b.entries[key] = entry
	return true, 0
}
func tooMany(w http.ResponseWriter, retry int) {
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	writeError(w, http.StatusTooManyRequests, "request limit exceeded; retry later")
}
func acquire(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) protectRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maintenance := r.Method == "POST" && (r.URL.Path == "/api/v1/system/tune" || r.URL.Path == "/api/v1/system/reconcile")
		_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if ok, retry := s.budget.allow(sha256.Sum256([]byte(strings.TrimSpace(token))), maintenance, s.limits); !ok {
			tooMany(w, retry)
			return
		}
		if maintenance {
			if !acquire(s.maintenanceSlots) {
				tooMany(w, 1)
				return
			}
			defer func() { <-s.maintenanceSlots }()
		}
		next.ServeHTTP(w, r)
	})
}

// The public health route never consumes a slot. All other requests, including
// bcrypt login attempts and unauthenticated traffic, share a nonblocking cap.
func (s *Server) boundRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		if !acquire(s.requestSlots) {
			tooMany(w, 1)
			return
		}
		defer func() { <-s.requestSlots }()
		next.ServeHTTP(w, r)
	})
}

// SetRequestLimits configures admission before Handler is called. Zero values
// retain safe defaults, preserving callers that construct a Server directly.
func (s *Server) SetRequestLimits(l config.RequestLimits) {
	d := config.DefaultRequestLimits()
	if l.Concurrent > 0 {
		d.Concurrent = l.Concurrent
	}
	if l.PerMinute > 0 {
		d.PerMinute = l.PerMinute
	}
	if l.MaintenanceConcurrent > 0 {
		d.MaintenanceConcurrent = l.MaintenanceConcurrent
	}
	if l.MaintenancePerMinute > 0 {
		d.MaintenancePerMinute = l.MaintenancePerMinute
	}
	s.limits = d
	s.requestSlots = make(chan struct{}, d.Concurrent)
	s.maintenanceSlots = make(chan struct{}, d.MaintenanceConcurrent)
	s.budget = newRequestBudget()
}
