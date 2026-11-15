package config

import "testing"

func TestCheckRejectsUnsafeState(t *testing.T) {
	base := func() *State {
		return &State{Version: StateVersion, Groups: []*Group{{ID: "g", Iface: "wg-c1", Subnet: "172.31.201.1/24", Port: 3478, MTU: 1360}}}
	}
	tests := map[string]func(*State){
		"foreign interface": func(s *State) { s.Groups[0].Iface = "eth0" },
		"outside pool":      func(s *State) { s.Groups[0].Subnet = "10.0.0.1/24" },
		"unparsable subnet": func(s *State) { s.Groups[0].Subnet = "garbage" },
		"host bits set":     func(s *State) { s.Groups[0].Subnet = "172.31.201.9/24" },
		"bad port":          func(s *State) { s.Groups[0].Port = 0 },
		"bad mtu":           func(s *State) { s.Groups[0].MTU = 1 },
		"duplicate id":      func(s *State) { g := *s.Groups[0]; g.Iface = "wg-c2"; s.Groups = append(s.Groups, &g) },
		"orphan client": func(s *State) {
			s.Clients = []*Client{{ID: "c", GroupID: "missing", Address: "172.31.201.2", TunnelMode: ModeSplit}}
		},
		"hub impersonation": func(s *State) {
			s.Clients = []*Client{{ID: "c", GroupID: "g", Address: "172.31.201.1", TunnelMode: ModeSplit}}
		},
		"outside client": func(s *State) {
			s.Clients = []*Client{{ID: "c", GroupID: "g", Address: "192.168.0.2", TunnelMode: ModeSplit}}
		},
		"bad mode": func(s *State) {
			s.Clients = []*Client{{ID: "c", GroupID: "g", Address: "172.31.201.2", TunnelMode: "oops"}}
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s := base()
			change(s)
			if err := s.Check(); err == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}

func TestCheckAcceptsValidState(t *testing.T) {
	s := &State{Version: StateVersion,
		Sites:   []*Site{{ID: "s", Iface: "wg-s1", Subnet: "172.31.201.1/24", Port: 3478, MTU: 1360, TunnelMode: ModeSplit, LocalSubnets: []string{"192.168.10.0/24"}}},
		Groups:  []*Group{{ID: "g", Iface: "wg-c1", Subnet: "172.31.202.1/24", Port: 3479, MTU: 1360}},
		Clients: []*Client{{ID: "c", GroupID: "g", Address: "172.31.202.2", TunnelMode: ModeFull}},
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceRejectsNullBeforeSort(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(&State{Sites: []*Site{nil, nil}}); err == nil {
		t.Fatal("null persisted")
	}
}
