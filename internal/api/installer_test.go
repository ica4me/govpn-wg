package api

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Execute only credential selection, never installer networking/deployment.
func TestInstallerCredentialDefaults(t *testing.T) {
	b, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "HASH=$(old GOVPN_ADMIN_PASSWORD_HASH '')")
	end := strings.Index(text, "tune_default=")
	if start < 0 || end < start {
		t.Fatal("credential block missing")
	}
	for _, tc := range []struct{ name, old, pass, want string }{
		{"fresh", "", "", "admin"},
		{"existing", "existing-hash", "", ""},
		{"explicit", "existing-hash", "new-password", "new-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "set -eu\nYES=1\nold() { printf '%s' \"$OLD_HASH\"; }\nwarn() { :; }\ndie() { exit 1; }\n" + text[start:end] + "\n[ \"$ADMIN_PASS\" = \"$EXPECTED\" ]\n[ \"$HASH\" = \"$OLD_HASH\" ]\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "OLD_HASH="+tc.old, "A_PASS="+tc.pass, "EXPECTED="+tc.want)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("selection failed: %v %s", err, out)
			}
		})
	}
}
