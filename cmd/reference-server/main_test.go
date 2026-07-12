package main

import "testing"

func TestReferenceServerListenDefaultsToLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8090", "[::1]:8090", "localhost:8090"} {
		if err := validateListenAddress(address, false); err != nil {
			t.Fatalf("rejected loopback %s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8090", ":8090", "192.0.2.1:8090"} {
		if err := validateListenAddress(address, false); err == nil {
			t.Fatalf("accepted non-loopback %s without explicit opt-in", address)
		}
	}
}
