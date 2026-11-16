package api

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthRejectsNoncanonicalSignatureEncodings(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth("admin", string(hash), bytes.Repeat([]byte{1}, 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Use the real issuer, including the bootstrap password-change flow.
	token, _, err := a.Login("admin", "admin", "test-client")
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := a.Verify(token); err != nil || subject != "admin" {
		t.Fatalf("legitimate issued token rejected: subject=%q err=%v", subject, err)
	}
	parts := strings.Split(token, ".")
	signature := parts[2]
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, signature[len(signature)-1])
	if len(signature) != 43 || last < 0 || last&3 != 0 {
		t.Fatal("expected canonical HS256 signature with two unused trailing bits")
	}
	for bits := 1; bits <= 3; bits++ {
		t.Run(string(alphabet[last|bits]), func(t *testing.T) {
			alternative := signature[:len(signature)-1] + string(alphabet[last|bits])
			other, err := base64.RawURLEncoding.DecodeString(alternative)
			if err != nil || !bytes.Equal(other, decoded) {
				t.Fatalf("test variant must decode to the same signature: %v", err)
			}
			if _, err := a.Verify(parts[0] + "." + parts[1] + "." + alternative); err == nil {
				t.Error("accepted noncanonical signature encoding (distinct raw-token rate key)")
			}
		})
	}
}

func TestAuthRejectsWeakSigningKey(t *testing.T) {
	h, _ := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if _, err := NewAuth("admin", string(h), []byte("short"), time.Hour); err == nil {
		t.Fatal("accepted weak signing key")
	}
}

func TestLimiterHardBound(t *testing.T) {
	l := newLimiter(2, time.Hour)
	for i := 0; i < 10000; i++ {
		l.hits[time.Unix(int64(i), 0).String()] = []time.Time{time.Now()}
	}
	if l.allow("new-client") {
		t.Fatal("accepted new identity at capacity")
	}
	if len(l.hits) > 10000 {
		t.Fatal("limiter grew beyond capacity")
	}
}
