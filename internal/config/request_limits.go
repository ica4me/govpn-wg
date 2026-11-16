package config

import (
	"fmt"
	"strconv"
)

type RequestLimits struct {
	Concurrent            int
	PerMinute             int
	MaintenanceConcurrent int
	MaintenancePerMinute  int
}

func DefaultRequestLimits() RequestLimits {
	return RequestLimits{Concurrent: 32, PerMinute: 300, MaintenanceConcurrent: 1, MaintenancePerMinute: 2}
}
func loadRequestLimits(get func(string, string) string) (RequestLimits, error) {
	l := DefaultRequestLimits()
	for _, v := range []struct {
		name string
		dest *int
		max  int
	}{
		{"GOVPN_API_MAX_CONCURRENT", &l.Concurrent, 1024},
		{"GOVPN_API_REQUESTS_PER_MINUTE", &l.PerMinute, 100000},
		{"GOVPN_API_MAINTENANCE_MAX_CONCURRENT", &l.MaintenanceConcurrent, 32},
		{"GOVPN_API_MAINTENANCE_PER_MINUTE", &l.MaintenancePerMinute, 1000},
	} {
		n, err := strconv.Atoi(get(v.name, strconv.Itoa(*v.dest)))
		if err != nil || n < 1 || n > v.max {
			return l, fmt.Errorf("%s must be an integer in 1..%d", v.name, v.max)
		}
		*v.dest = n
	}
	return l, nil
}
