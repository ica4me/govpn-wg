package api

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestBootstrapDefaultIsExplicit(t *testing.T) {
	hash, err := HashInitialPassword("admin")
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("admin")) != nil {
		t.Fatal("bad bootstrap hash")
	}
	if _, err := HashPassword("admin"); err == nil {
		t.Fatal("password change permits default")
	}
	if _, err := HashInitialPassword("short"); err == nil {
		t.Fatal("arbitrary short password accepted")
	}
}
