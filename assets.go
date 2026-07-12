// Package agentapidoctor exposes the versioned public contracts bundled into
// release binaries.
package agentapidoctor

import (
	"embed"
	"errors"
	"io/fs"
	"path"
)

// embedded contains only public, synthetic repository assets. Secrets, local
// run evidence, execution state, and generated release credentials are never
// part of this filesystem.
//
//go:embed all:adapters all:packs all:profiles all:runners all:schemas all:specs all:support cli/spec.yaml
var embedded embed.FS

// Assets returns a read-only filesystem rooted at the repository-style asset
// paths (for example packs/openai-chat/pack.yaml).
func Assets() fs.FS { return embedded }

// ReadAsset reads one canonical slash-separated asset path. Traversal,
// absolute paths, backslashes, and directories are rejected.
func ReadAsset(name string) ([]byte, error) {
	if !fs.ValidPath(name) || name == "." || path.Clean(name) != name {
		return nil, errors.New("invalid embedded asset path")
	}
	info, err := fs.Stat(embedded, name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("embedded asset must be a regular file")
	}
	return embedded.ReadFile(name)
}
