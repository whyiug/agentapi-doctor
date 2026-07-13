package buildinfo

import (
	"runtime/debug"
	"strings"
)

const (
	defaultVersion = "0.0.0-dev"
	defaultCommit  = "unknown"
	defaultBuiltAt = "unknown"
)

var (
	Version = defaultVersion
	Commit  = defaultCommit
	BuiltAt = defaultBuiltAt
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
}

func Current() Info {
	info, _ := debug.ReadBuildInfo()
	return resolve(Info{Version: Version, Commit: Commit, BuiltAt: BuiltAt}, info)
}

func resolve(configured Info, build *debug.BuildInfo) Info {
	if build == nil {
		return configured
	}
	if configured.Version == defaultVersion && build.Main.Version != "" && build.Main.Version != "(devel)" {
		configured.Version = strings.TrimPrefix(build.Main.Version, "v")
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if configured.Commit == defaultCommit && setting.Value != "" {
				configured.Commit = setting.Value
			}
		case "vcs.time":
			if configured.BuiltAt == defaultBuiltAt && setting.Value != "" {
				configured.BuiltAt = setting.Value
			}
		}
	}
	return configured
}
