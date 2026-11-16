package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const issuer = "govpn-wg"

func passwordVersion(hash []byte) string {
	v := sha256.Sum256(hash)
	return fmt.Sprintf("%x", v[:])
}

// Auth issues and verifies HS256 JWTs for the single admin account.
type Auth struct {
	mu                     sync.RWMutex
	passwordDir            string
	user                   string
	hash                   []byte
	key                    []byte
	ttl                    time.Duration
	limiter                *limiter
	requiresPasswordChange bool
}

// LoadSigningKey reads or creates a 64-byte HMAC key (mode 0600).
// Deleting the file invalidates every issued token.
func LoadSigningKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "jwt.key")
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by group/others (chmod 600 it)", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(b) < 32 {
			return nil, fmt.Errorf("%s is shorter than 32 bytes; delete it to generate a new key", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

func NewAuth(user, bcryptHash string, key []byte, ttl time.Duration) (*Auth, error) {
	if len(key) < 32 || ttl <= 0 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes and token TTL positive")
	}
	if user == "" || bcryptHash == "" {
		return nil, fmt.Errorf("admin user/password hash not configured (GOVPN_ADMIN_USER, GOVPN_ADMIN_PASSWORD_HASH)")
	}
	if _, err := bcrypt.Cost([]byte(bcryptHash)); err != nil {
		return nil, fmt.Errorf("GOVPN_ADMIN_PASSWORD_HASH is not a bcrypt hash: %w", err)
	}
	return &Auth{user: user, hash: []byte(bcryptHash), key: key, ttl: ttl, limiter: newLimiter(10, time.Minute), requiresPasswordChange: bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte("admin")) == nil}, nil
}

// HashInitialPassword permits the explicitly requested bootstrap default only.
// Normal password changes must use HashPassword.
func HashInitialPassword(pw string) (string, error) {
	if pw != "admin" {
		return HashPassword(pw)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

// HashPassword is used by `govpn-wg hash-password` and password changes.
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

// Login checks credentials and returns a signed token.
func (a *Auth) Login(user, password, remote string) (string, time.Time, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.limiter.allow(remote) {
		return "", time.Time{}, errRateLimited
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) == 1
	// Always run bcrypt so timing does not reveal whether the user exists.
	pwErr := bcrypt.CompareHashAndPassword(a.hash, []byte(password))
	if !userOK || pwErr != nil {
		return "", time.Time{}, errBadCredentials
	}
	a.limiter.reset(remote)
	exp := time.Now().Add(a.ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: issuer, Subject: a.user, ID: passwordVersion(a.hash), IssuedAt: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	s, err := tok.SignedString(a.key)
	return s, exp, err
}

// Verify validates a bearer token.
func (a *Auth) Verify(token string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return a.key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(issuer), jwt.WithExpirationRequired(), jwt.WithStrictDecoding())
	if err != nil {
		return "", err
	}
	if claims.Subject != a.user || claims.ID != passwordVersion(a.hash) {
		return "", errors.New("unknown subject")
	}
	return claims.Subject, nil
}

func (a *Auth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		scheme, token, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="govpn-wg"`)
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if _, err := a.Verify(strings.TrimSpace(token)); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="govpn-wg", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		if a.RequiresPasswordChange() && !bootstrapAllowed(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "requires_password_change": true})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) RequiresPasswordChange() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.requiresPasswordChange
}

var (
	errRateLimited    = errors.New("too many login attempts, retry later")
	errBadCredentials = errors.New("invalid username or password")
)

// limiter allows n failed attempts per window per remote IP.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if _, exists := l.hits[key]; !exists && len(l.hits) >= 10000 {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
		if len(l.hits) >= 10000 {
			return false
		}
	}
	var kept []time.Time
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.n {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 10000 { // bound memory: drop only expired entries
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
	return true
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

// bootstrapAllowed lists the only calls a bootstrap (admin/admin) token may make.
func bootstrapAllowed(r *http.Request) bool {
	switch {
	case r.Method == "POST" && (r.URL.Path == "/api/v1/auth/password" || r.URL.Path == "/api/v1/auth/credentials"):
		return true
	case r.Method == "GET" && (r.URL.Path == "/api/v1/system/status" || r.URL.Path == "/api/v1/auth/me"):
		return true
	}
	return false
}
