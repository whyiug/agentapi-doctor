package buildinfo

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
}

func Current() Info { return Info{Version: Version, Commit: Commit, BuiltAt: BuiltAt} }
