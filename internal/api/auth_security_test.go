package api

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

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
