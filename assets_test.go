package agentapidoctor

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestEmbeddedCandidateAssetsAreReadableAndTraversalIsRejected(t *testing.T) {
	for _, name := range []string{
		"cli/spec.yaml",
		"packs/openai-chat/pack.yaml",
		"profiles/clients/codex/profile.yaml",
		"schemas/index.yaml",
		"specs/requirement-catalog.json",
		"support/support-manifest.yaml",
	} {
		data, err := ReadAsset(name)
		if err != nil || len(data) == 0 {
			t.Fatalf("ReadAsset(%q) = %d bytes, %v", name, len(data), err)
		}
	}
	for _, name := range []string{".", "../go.mod", "/etc/passwd", `packs\\openai-chat\\pack.yaml`, "packs"} {
		if _, err := ReadAsset(name); err == nil {
			t.Fatalf("accepted unsafe or non-file asset %q", name)
		}
	}

	walked := 0
	err := fs.WalkDir(Assets(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			walked++
			data, readErr := fs.ReadFile(Assets(), name)
			if readErr != nil || bytes.Contains(data, []byte("github_pat_")) {
				t.Fatalf("unsafe embedded file %q: %v", name, readErr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if walked < 100 {
		t.Fatalf("unexpectedly small embedded contract set: %d files", walked)
	}
}
