package api

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"path/filepath"
)

// LoadPasswordHash prefers a password changed through the API over the initial
// installer hash. A malformed or insecure override fails startup closed.
func LoadPasswordHash(dir, fallback string) (string, error) {
	p := filepath.Join(dir, "admin-password.hash")
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("admin password file must be regular and mode 0600")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	if _, err = bcrypt.Cost(b); err != nil {
		return "", fmt.Errorf("invalid stored password hash: %w", err)
	}
	return string(b), nil
}

// SetPasswordDir enables durable password changes. Call before serving requests.
func (a *Auth) SetPasswordDir(dir string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.passwordDir = dir
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	a := s.auth
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.limiter.allow(remoteIP(r)) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, errRateLimited.Error())
		return
	}
	if bcrypt.CompareHashAndPassword(a.hash, []byte(in.Current)) != nil {
		writeError(w, 401, errBadCredentials.Error())
		return
	}
	hash, err := HashPassword(in.New)
	if err != nil {
		writeError(w, 422, "new password must be 8..72 bytes")
		return
	}
	if a.passwordDir == "" {
		writeError(w, 503, "password changes not configured")
		return
	}
	if err = savePassword(a.passwordDir, hash); err != nil {
		writeError(w, 500, "could not persist password")
		return
	}
	a.hash = []byte(hash)
	a.requiresPasswordChange = false
	a.limiter.reset(remoteIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func savePassword(dir, hash string) error {
	f, err := os.CreateTemp(dir, ".password-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(hash); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "admin-password.hash"))
}
