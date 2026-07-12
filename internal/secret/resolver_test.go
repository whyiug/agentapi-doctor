package secret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestEnvironmentResolutionAndWipe(t *testing.T) {
	resolver := Resolver{LookupEnv: func(name string) (string, bool) {
		if name != "TOKEN" {
			return "", false
		}
		return "synthetic-secret", true
	}}
	value, err := resolver.Resolve(context.Background(), "env://TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "synthetic-secret" {
		t.Fatal("wrong value")
	}
	Wipe(value)
	for _, item := range value {
		if item != 0 {
			t.Fatal("buffer was not overwritten")
		}
	}
	if _, err := resolver.Resolve(context.Background(), "env://MISSING"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestFileResolutionRequiresPrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte("synthetic-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := Resolver{}
	value, err := resolver.Resolve(context.Background(), "file://"+path)
	if err != nil {
		t.Fatal(err)
	}
	Wipe(value)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "file://"+path); err == nil {
		t.Fatal("accepted broadly readable secret file")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "file://"+link); err == nil {
		t.Fatal("accepted symlink secret file")
	}
}

func TestExecIsDisabledByDefault(t *testing.T) {
	resolver := Resolver{}
	if _, err := resolver.Resolve(context.Background(), "exec:///bin/false"); !errors.Is(err, ErrExecDisabled) {
		t.Fatalf("expected disabled error, got %v", err)
	}
}

func TestExecRequiresDigestDirectoryAndBoundArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper fixture")
	}
	directory := t.TempDir()
	helper := filepath.Join(directory, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s' \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(helper)
	if err != nil {
		t.Fatal(err)
	}
	resolver := Resolver{ExecEnabled: true, ExecDigests: map[string]schema.Digest{helper: digest}, ExecDirectory: directory, ExecArguments: map[string][]string{helper: {"synthetic-secret"}}, ExecEnvironment: []string{"PATH=/usr/bin:/bin"}}
	value, err := resolver.Resolve(context.Background(), "exec://"+helper)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "synthetic-secret" {
		t.Fatalf("value=%q", value)
	}
	Wipe(value)
	resolver.ExecDirectory = ""
	if _, err := resolver.Resolve(context.Background(), "exec://"+helper); err == nil {
		t.Fatal("accepted inherited working directory")
	}
}
