package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
)

func TestVersionReportsExactBuildIdentity(t *testing.T) {
	var output bytes.Buffer
	if err := writeVersion(&output); err != nil {
		t.Fatal(err)
	}
	var got buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != buildinfo.Current() {
		t.Fatalf("version = %+v, want %+v", got, buildinfo.Current())
	}
}

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
