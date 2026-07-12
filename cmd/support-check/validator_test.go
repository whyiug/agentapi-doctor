package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRepositoryCandidateIsInternallyConsistent(t *testing.T) {
	summary, err := ValidateRepository(repositoryRoot(t))
	if err != nil {
		t.Fatalf("ValidateRepository() error = %v", err)
	}
	want := Summary{
		Cells:            21,
		Profiles:         8,
		Drivers:          4,
		RuntimeAdapters:  5,
		ExternalAdapters: 1,
		PassedClaims:     0,
	}
	if summary != want {
		t.Fatalf("ValidateRepository() summary = %#v, want %#v", summary, want)
	}
}

func TestRepositoryRejectsContractMutants(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*testing.T, string)
		wantErrors []string
	}{
		{
			name: "duplicate JSON member",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, "support", "support-manifest.yaml")
				raw := mustReadFile(t, path)
				mustWriteFile(t, path, append([]byte(`{"kind":"SupportManifest",`), raw[1:]...))
			},
			wantErrors: []string{"strict JSON", "duplicate"},
		},
		{
			name: "unknown manifest member",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					document["handEnteredPass"] = true
				})
			},
			wantErrors: []string{"schema validation"},
		},
		{
			name: "missing required SLA",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "id", "t1.protocol.anthropic-messages")
					delete(cell, "updateSLA")
				})
			},
			wantErrors: []string{"schema validation"},
		},
		{
			name: "missing required cell",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					cells := objectSlice(t, document, "cells")
					document["cells"] = cells[:len(cells)-1]
				})
			},
			wantErrors: []string{"missing required cell"},
		},
		{
			name: "kind path tier mismatch",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "id", "t1.profile.openai-python")
					objectMap(t, cell, "artifact")["path"] = "profiles/sdk/openai-python/renamed.profile.yaml"
				})
			},
			wantErrors: []string{"kind/path/tier mismatch"},
		},
		{
			name: "missing kind-applicable tier gate",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "id", "t1.runtime.vllm")
					delete(objectMap(t, cell, "tierGates"), "protocolLabelForbidden")
				})
			},
			wantErrors: []string{"tier gates do not match applicability policy"},
		},
		{
			name: "undeclared profile manifest",
			mutate: func(t *testing.T, root string) {
				source := filepath.Join(root, "profiles", "sdk", "openai-python", "profile.yaml")
				target := filepath.Join(root, "profiles", "sdk", "undeclared", "profile.yaml")
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				mustWriteFile(t, target, mustReadFile(t, source))
			},
			wantErrors: []string{"manifest is not declared in the v1.0 artifact inventory"},
		},
		{
			name: "passed gate over unresolved lock",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-manifest.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "id", "t1.protocol.openai-chat")
					objectMap(t, cell, "tierGates")["requirements"] = "passed"
				})
			},
			wantErrors: []string{"has passed gate without resolved evidenced lock"},
		},
		{
			name: "resolved lock with floating version",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-lock.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "cellId", "t1.protocol.openai-chat")
					cell["status"] = "resolved"
					cell["artifactVersion"] = "latest"
					cell["artifactDigest"] = testDigest("1")
					cell["denominatorDigest"] = testDigest("2")
					cell["gateStatus"] = "passed"
					cell["evidenceRefs"] = []any{"evidence/support/openai-chat.json"}
				})
			},
			wantErrors: []string{"exact non-floating artifact identity"},
		},
		{
			name: "unresolved slot claims exact version",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/support-lock.yaml", func(document map[string]any) {
					cell := findObject(t, objectSlice(t, document, "cells"), "cellId", "t1.profile.openai-python")
					slot := findObject(t, objectSlice(t, cell, "versionSlots"), "slot", "current")
					slot["exactVersion"] = "1.2.3"
				})
			},
			wantErrors: []string{"must contain no claimed exact facts"},
		},
		{
			name: "unresolved profile claims exact version",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "profiles/sdk/openai-python/profile.yaml", func(document map[string]any) {
					consumer := objectMap(t, objectMap(t, document, "spec"), "consumer")
					consumer["exactVersions"] = []any{"1.2.3"}
				})
			},
			wantErrors: []string{"unresolved consumer cannot claim exact versions"},
		},
		{
			name: "profile invents evidenced pass over pending matrix",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "profiles/sdk/openai-node/profile.yaml", func(document map[string]any) {
					gate := objectMap(t, objectMap(t, document, "spec"), "supportGate")
					gate["status"] = "passed"
					gate["evidenceRefs"] = []any{"evidence/not-actually-created.json"}
				})
			},
			wantErrors: []string{"requires all manifest gates and its support-lock cell to be resolved with evidence"},
		},
		{
			name: "Codex permits Chat fallback",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "profiles/clients/codex/profile.yaml", func(document map[string]any) {
					spec := objectMap(t, document, "spec")
					spec["forbiddenFallbacks"] = []any{}
				})
			},
			wantErrors: []string{"Codex must remain Responses-only"},
		},
		{
			name: "valid runtime fixture contains secret field",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "adapters/runtime-metadata/vllm/fixtures/valid.json", func(document map[string]any) {
					objectMap(t, document, "configuration")["token"] = "synthetic-but-forbidden"
				})
			},
			wantErrors: []string{"declared valid synthetic fixture fails its contract"},
		},
		{
			name: "runtime fixture contract drops forbidden fields",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "adapters/runtime-metadata/sglang/adapter.yaml", func(document map[string]any) {
					contract := objectMap(t, objectMap(t, document, "spec"), "fixtureContract")
					contract["forbiddenFields"] = []any{"authorization"}
				})
			},
			wantErrors: []string{"fixture contract paths or required/forbidden fields were weakened"},
		},
		{
			name: "invalid runtime fixture becomes valid",
			mutate: func(t *testing.T, root string) {
				valid := filepath.Join(root, "adapters/runtime-metadata/ollama/fixtures/valid.json")
				invalid := filepath.Join(root, "adapters/runtime-metadata/ollama/fixtures/invalid.json")
				mustWriteFile(t, invalid, mustReadFile(t, valid))
			},
			wantErrors: []string{"declared invalid synthetic fixture unexpectedly passes"},
		},
		{
			name: "external suite invents run without pinned upstream",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "adapters/external-suites/open-responses/adapter.yaml", func(document map[string]any) {
					objectMap(t, objectMap(t, document, "spec"), "runEvidence")["status"] = "verified"
				})
			},
			wantErrors: []string{"verified run requires resolved upstream"},
		},
		{
			name: "external suite changes fixed output interface",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "adapters/external-suites/open-responses/adapter.yaml", func(document map[string]any) {
					objectMap(t, objectMap(t, document, "spec"), "interface")["outputSchema"] = "urn:unreviewed:output"
				})
			},
			wantErrors: []string{"input/output interface identifiers must remain fixed"},
		},
		{
			name: "release component invents pass",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/release-components.yaml", func(document map[string]any) {
					component := findObject(t, objectSlice(t, document, "components"), "id", "core-cli")
					component["status"] = "passed"
				})
			},
			wantErrors: []string{"passed release claim has no evidence"},
		},
		{
			name: "release component changes maturity",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "support/release-components.yaml", func(document map[string]any) {
					component := findObject(t, objectSlice(t, document, "components"), "id", "required-tier2-set")
					component["targetMaturity"] = "stable"
				})
			},
			wantErrors: []string{"kind or target maturity does not match release scope"},
		},
		{
			name: "resolved driver omits pinned identity",
			mutate: func(t *testing.T, root string) {
				mutateJSONObject(t, root, "runners/node/driver.yaml", func(document map[string]any) {
					objectMap(t, objectMap(t, document, "spec"), "execution")["resolutionStatus"] = "resolved"
				})
			},
			wantErrors: []string{"resolved driver requires exact runtime"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := copyValidationFixture(t)
			test.mutate(t, root)
			_, err := ValidateRepository(root)
			if err == nil {
				t.Fatal("ValidateRepository() unexpectedly accepted mutant")
			}
			for _, want := range test.wantErrors {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("ValidateRepository() error = %v, want substring %q", err, want)
				}
			}
		})
	}
}

func TestRuntimeMetadataSyntheticFixtureContracts(t *testing.T) {
	root := repositoryRoot(t)
	for adapterPath, expectedID := range expectedRuntimeAdapters {
		t.Run(expectedID, func(t *testing.T) {
			var adapter RuntimeAdapter
			loader := &validator{root: root, schemas: make(map[string]*jsonschema.Schema)}
			if !loader.decode(adapterPath, "schemas/support/runtime-metadata-adapter.schema.json", &adapter) {
				t.Fatalf("decode(%s) failed: %v", adapterPath, loader.errors.err())
			}
			if !loader.runtimeFixturePasses(adapter.Spec.FixtureContract.Valid, &adapter) {
				t.Fatalf("valid fixture %s failed", adapter.Spec.FixtureContract.Valid)
			}
			if loader.runtimeFixturePasses(adapter.Spec.FixtureContract.Invalid, &adapter) {
				t.Fatalf("invalid fixture %s passed", adapter.Spec.FixtureContract.Invalid)
			}
		})
	}
}

func TestFloatingReferenceDetection(t *testing.T) {
	for _, value := range []string{"latest", "HEAD", "main", "v1.*", "v1.x", ">=1.2.3", "candidate", "nightly"} {
		if !isFloating(value) {
			t.Errorf("isFloating(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"1.2.3", "v1.2.3-rc.1", "2025-11-25", "3f4a9d1"} {
		if isFloating(value) {
			t.Errorf("isFloating(%q) = true, want false", value)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func copyValidationFixture(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	destination := t.TempDir()
	for _, relative := range []string{
		"support",
		"profiles",
		"adapters",
		"runners",
		"schemas/profile",
		"schemas/support",
	} {
		copyTree(t, filepath.Join(source, filepath.FromSlash(relative)), filepath.Join(destination, filepath.FromSlash(relative)))
	}
	return destination
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, mustReadFile(t, path), info.Mode().Perm())
	})
	if err != nil {
		t.Fatalf("copy %s: %v", source, err)
	}
}

func mutateJSONObject(t *testing.T, root, relative string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	var document map[string]any
	if err := json.Unmarshal(mustReadFile(t, path), &document); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	mutate(document)
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", relative, err)
	}
	mustWriteFile(t, path, append(raw, '\n'))
}

func objectMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%q is %T, want object", key, object[key])
	}
	return value
}

func objectSlice(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok {
		t.Fatalf("%q is %T, want array", key, object[key])
	}
	return value
}

func findObject(t *testing.T, values []any, key, want string) map[string]any {
	t.Helper()
	for _, value := range values {
		object, ok := value.(map[string]any)
		if ok && object[key] == want {
			return object
		}
	}
	t.Fatalf("object with %s=%q not found", key, want)
	return nil
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func mustWriteFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testDigest(nibble string) string {
	return "sha256:" + strings.Repeat(nibble, 64)
}
