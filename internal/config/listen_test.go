package config

import "testing"

func TestValidListen(t *testing.T) {
	ok := []string{"127.0.0.1:8080", "localhost:8080", "127.0.0.1:8080,172.18.0.1:8080", " 127.0.0.1:8080 , 10.0.0.10:8080 "}
	for _, s := range ok {
		if err := ValidListen(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{"", ",", "0.0.0.0:8080", "127.0.0.1:8080,0.0.0.0:8080", "[::1]:8080", "127.0.0.1", "127.0.0.1:0",
		"127.0.0.1:8080,127.0.0.1:8080", "a:1,b:2", "1.1.1.1:1,1.1.1.2:1,1.1.1.3:1,1.1.1.4:1,1.1.1.5:1", "invalid-listen-address"}
	for _, s := range bad {
		if err := ValidListen(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if got := SplitListen(" a , ,b "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("split: %v", got)
	}
}
