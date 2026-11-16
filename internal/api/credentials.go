package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	adminUserFile     = "admin-user"
	adminPasswordFile = "admin-password.hash"
	// DefaultAdminUser and DefaultAdminPassword are the bootstrap credentials
	// restored by `govpn-wg reset-admin`. Logging in with them always forces a
	// credential change before any management call is allowed.
	DefaultAdminUser     = "admin"
	DefaultAdminPassword = "admin"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)

// ValidUsername reports whether name is an acceptable single-admin login.
func ValidUsername(name string) bool { return usernamePattern.MatchString(name) }

// LoadAdminUser prefers a username changed through the API over the env value.
// A malformed or insecure override fails startup closed.
func LoadAdminUser(dir, fallback string) (string, error) {
	p := filepath.Join(dir, adminUserFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("admin user file must be regular and mode 0600")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(b))
	if !ValidUsername(name) {
		return "", fmt.Errorf("invalid stored admin username")
	}
	return name, nil
}

// ResetAdmin restores the bootstrap admin/admin login in dir. The running
// service must be restarted to load it; the next login is forced to change
// the password before management is possible again.
func ResetAdmin(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	hash, err := HashInitialPassword(DefaultAdminPassword)
	if err != nil {
		return err
	}
	if err := writePrivate(dir, adminPasswordFile, hash); err != nil {
		return err
	}
	return writePrivate(dir, adminUserFile, DefaultAdminUser)
}

// writePrivate atomically replaces dir/name with mode 0600 content.
func writePrivate(dir, name, content string) error {
	f, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.WriteString(content); err != nil {
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
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

// Username returns the current admin login name.
func (a *Auth) Username() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.user
}

// changeCredentials updates the single admin's username and/or password.
// Every issued JWT is revoked because tokens are bound to both.
func (s *Server) changeCredentials(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current     string `json:"current_password"`
		NewUsername string `json:"new_username"`
		NewPassword string `json:"new_password"`
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
	user := strings.TrimSpace(in.NewUsername)
	if user == "" {
		user = a.user
	}
	if !ValidUsername(user) {
		writeError(w, 422, "username must be 1..64 characters: letters, digits, _ . @ -")
		return
	}
	if in.NewPassword == "" && a.requiresPasswordChange {
		writeError(w, 422, "the bootstrap password must be changed")
		return
	}
	if in.NewPassword == DefaultAdminPassword {
		writeError(w, 422, "new password must not be the bootstrap default")
		return
	}
	if user == a.user && in.NewPassword == "" {
		writeError(w, 422, "nothing to change")
		return
	}
	hash := string(a.hash)
	if in.NewPassword != "" {
		if len(in.NewPassword) > 72 {
			writeError(w, 422, "new password must be 8..72 bytes")
			return
		}
		h, err := HashPassword(in.NewPassword)
		if err != nil {
			writeError(w, 422, "new password must be 8..72 bytes")
			return
		}
		hash = h
	}
	if a.passwordDir == "" {
		writeError(w, 503, "credential changes not configured")
		return
	}
	// Password first: a crash between the writes leaves the old username with
	// the new password, which the operator still knows.
	if hash != string(a.hash) {
		if err := writePrivate(a.passwordDir, adminPasswordFile, hash); err != nil {
			writeError(w, 500, "could not persist credentials")
			return
		}
	}
	if user != a.user {
		if err := writePrivate(a.passwordDir, adminUserFile, user); err != nil {
			writeError(w, 500, "could not persist credentials")
			return
		}
	}
	a.user = user
	a.hash = []byte(hash)
	a.requiresPasswordChange = bcrypt.CompareHashAndPassword(a.hash, []byte(DefaultAdminPassword)) == nil
	a.limiter.reset(remoteIP(r))
	s.log.Info("admin credentials changed", "username_changed", in.NewUsername != "", "password_changed", in.NewPassword != "")
	writeJSON(w, 200, map[string]any{"username": user, "relogin_required": true})
}

// me returns the current admin login name for the console account page.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"username": s.auth.Username(), "requires_password_change": s.auth.RequiresPasswordChange()})
}
