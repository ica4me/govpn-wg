package main

import (
	"github.com/ica4me/govpn-wg/internal/config"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
)

func TestServeFailsBeforeListenOnInitialApplyFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOVPN_DATA_DIR", dir)
	t.Setenv("GOVPN_DRY_RUN", "1")
	t.Setenv("GOVPN_TUNE_ON_START", "0")
	t.Setenv("GOVPN_LISTEN", "invalid-listen-address")
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOVPN_ADMIN_PASSWORD_HASH", string(hash))
	st, err := config.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = st.Replace(&config.State{Groups: []*config.Group{
		{ID: "a", Iface: "wg-c1", Subnet: "172.31.201.1/24", Port: 3478, MTU: 1360},
		{ID: "b", Iface: "wg-c2", Subnet: "172.31.201.1/24", Port: 3479, MTU: 1360},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := serve(""); err == nil || !strings.Contains(err.Error(), "initial apply failed") {
		t.Fatalf("expected startup failure before listen, got %v", err)
	}
}
