package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestResolveFallsBackToModuleAndVCSBuildInfo(t *testing.T) {
	build := &debug.BuildInfo{
		Main: debug.Module{Path: "github.com/whyiug/agentapi-doctor", Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.time", Value: "2026-07-13T00:00:00Z"},
		},
	}
	want := Info{Version: "0.1.0", Commit: "0123456789abcdef", BuiltAt: "2026-07-13T00:00:00Z"}
	if got := resolve(Info{Version: defaultVersion, Commit: defaultCommit, BuiltAt: defaultBuiltAt}, build); got != want {
		t.Fatalf("module fallback = %+v, want %+v", got, want)
	}
}

func TestResolveKeepsLDFlagsAheadOfConflictingBuildInfo(t *testing.T) {
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9-mutant"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "mutant-commit"},
			{Key: "vcs.time", Value: "2099-01-01T00:00:00Z"},
		},
	}
	want := Info{Version: "0.1.0", Commit: "release-commit", BuiltAt: "2026-07-13T00:00:00Z"}
	if got := resolve(want, build); got != want {
		t.Fatalf("build info overrode ldflags: got %+v, want %+v", got, want)
	}
}

func TestResolveRejectsDevelopmentAndEmptyFallbackMutants(t *testing.T) {
	configured := Info{Version: defaultVersion, Commit: defaultCommit, BuiltAt: defaultBuiltAt}
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: ""},
			{Key: "vcs.time", Value: ""},
		},
	}
	if got := resolve(configured, build); got != configured {
		t.Fatalf("invalid build metadata replaced explicit development defaults: %+v", got)
	}
}
