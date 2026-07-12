package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
)

func TestVersionReportsExactBuildIdentity(t *testing.T) {
	var output bytes.Buffer
	if err := writeVersion(nil, &output); err != nil {
		t.Fatal(err)
	}
	var got buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != buildinfo.Current() {
		t.Fatalf("version = %+v, want %+v", got, buildinfo.Current())
	}
	if err := writeVersion([]string{"unexpected"}, io.Discard); err == nil {
		t.Fatal("version accepted an argument")
	}
}

func TestValidateListenAddressDefaultsToLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if err := validateListenAddress(address, false); err != nil {
			t.Fatalf("rejected loopback %s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", ":8080", "192.0.2.10:8080"} {
		if err := validateListenAddress(address, false); err == nil {
			t.Fatalf("accepted non-loopback %s without explicit acknowledgement", address)
		}
	}
	if err := validateListenAddress("0.0.0.0:8080", true); err != nil {
		t.Fatalf("explicit non-loopback acknowledgement rejected: %v", err)
	}
}

func TestParseServerOptionsRequiresExplicitStorageMode(t *testing.T) {
	if _, err := parseServerOptions(nil, io.Discard); err == nil {
		t.Fatal("accepted an implicit storage mode")
	}

	ephemeral, err := parseServerOptions([]string{"-allow-ephemeral"}, io.Discard)
	if err != nil {
		t.Fatalf("parse explicit ephemeral mode: %v", err)
	}
	if !ephemeral.allowEphemeral || ephemeral.database != "" {
		t.Fatalf("unexpected ephemeral options: %+v", ephemeral)
	}

	database, err := parseServerOptions([]string{"-database", "registry.db"}, io.Discard)
	if err != nil {
		t.Fatalf("parse durable mode: %v", err)
	}
	if !filepath.IsAbs(database.database) || filepath.Base(database.database) != "registry.db" {
		t.Fatalf("database was not normalized to an absolute path: %q", database.database)
	}

	if _, err := parseServerOptions([]string{"-database", "registry.db", "-allow-ephemeral"}, io.Discard); err == nil {
		t.Fatal("accepted mutually exclusive storage modes")
	}
}

func TestParseServerOptionsRejectsInvalidOperationalValues(t *testing.T) {
	cases := [][]string{
		{"-allow-ephemeral", "-rate-limit", "0"},
		{"-allow-ephemeral", "-token-ttl", "0s"},
		{"-allow-ephemeral", "-token-env", "BAD=NAME"},
		{"-allow-ephemeral", "unexpected"},
	}
	for _, arguments := range cases {
		if _, err := parseServerOptions(arguments, io.Discard); err == nil {
			t.Fatalf("accepted invalid arguments: %v", arguments)
		}
	}
}

func TestValidateStorageModeDoesNotCreateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "registry.db")
	resolved, err := validateStorageMode(path, false)
	if err != nil {
		t.Fatalf("validate durable storage: %v", err)
	}
	if resolved != path {
		t.Fatalf("unexpected resolved path: got %q want %q", resolved, path)
	}
	if _, err := filepath.Glob(path); err != nil {
		t.Fatalf("glob path: %v", err)
	}
	if matches, _ := filepath.Glob(path); len(matches) != 0 {
		t.Fatal("validation unexpectedly created the database")
	}
}
