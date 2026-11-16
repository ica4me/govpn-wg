package config

import "testing"

func TestRequestLimitsEnvironment(t *testing.T) {
	t.Setenv("GOVPN_API_MAX_CONCURRENT", "3")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.RequestLimits.Concurrent != 3 || c.RequestLimits.PerMinute != 300 || c.RequestLimits.MaintenancePerMinute != 2 || c.RequestLimits.MaintenanceConcurrent != 1 {
		t.Fatalf("limits: %+v", c.RequestLimits)
	}
	for _, bad := range []string{"0", "-1", "garbage", "100001"} {
		t.Setenv("GOVPN_API_MAX_CONCURRENT", bad)
		if _, err := Load(""); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
