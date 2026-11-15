package api

import (
	"bytes"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPasswordChangePersistsAndRevokes(t *testing.T) {
	h, _ := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	dir := t.TempDir()
	a, err := NewAuth("admin", string(h), bytes.Repeat([]byte{1}, 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a.SetPasswordDir(dir)
	tok, _, err := a.Login("admin", "old-password", "local")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{auth: a}
	request := func(current, next string) int {
		r := httptest.NewRequest("POST", "/api/v1/auth/password", bytes.NewBufferString(`{"current_password":"`+current+`","new_password":"`+next+`"}`))
		w := httptest.NewRecorder()
		s.changePassword(w, r)
		return w.Code
	}
	if got := request("wrong", "new-password"); got != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", got)
	}
	if got := request("old-password", "short"); got != http.StatusUnprocessableEntity {
		t.Fatalf("short password: %d", got)
	}
	if got := request("old-password", "new-password"); got != http.StatusNoContent {
		t.Fatalf("change: %d", got)
	}
	if _, err := a.Verify(tok); err == nil {
		t.Fatal("old token valid")
	}
	if _, _, err := a.Login("admin", "new-password", "local"); err != nil {
		t.Fatal(err)
	}
	hash, err := LoadPasswordHash(dir, string(h))
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("new-password")) != nil {
		t.Fatal("password not persisted")
	}
	a.SetPasswordDir(filepath.Join(dir, "missing", "unwritable"))
	if got := request("new-password", "other-password"); got != 500 {
		t.Fatalf("persistence failure: %d", got)
	}
	if _, _, err := a.Login("admin", "new-password", "local"); err != nil {
		t.Fatal("failed write changed password")
	}
}
