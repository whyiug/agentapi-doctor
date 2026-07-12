package conformance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/whyiug/agentapi-doctor/internal/catalog"
)

func TestCheckedInCatalogAndAllPacksCompileWithZeroDiff(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate conformance test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	statistics, err := catalog.Check(root)
	if err != nil {
		t.Fatal(err)
	}
	if statistics.ScenarioCount != 260 || statistics.NormativeDenominatorCount != 260 || statistics.AliasCount != 0 {
		t.Fatalf("unexpected checked-in denominator: %+v", statistics)
	}
}

func TestPublishedSchemasValidateCheckedInCatalogArtifacts(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate conformance test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	tests := []struct {
		name       string
		schemaPath string
		schemaID   string
		artifacts  []string
	}{
		{name: "source locks", schemaPath: "schemas/pack/source-lock.schema.json", schemaID: "urn:agentapi-doctor:schema:source-lock-set:v1", artifacts: []string{"specs/sources.lock.json"}},
		{name: "requirements", schemaPath: "schemas/pack/requirement-catalog.schema.json", schemaID: "urn:agentapi-doctor:schema:requirement-catalog:v1", artifacts: []string{"specs/requirement-catalog.json"}},
		{name: "statistics", schemaPath: "schemas/result/catalog-statistics.schema.json", schemaID: "urn:agentapi-doctor:schema:catalog-statistics:v1", artifacts: []string{"specs/catalog-statistics.json"}},
		{name: "candidate status", schemaPath: "schemas/pack/candidate-status.schema.json", schemaID: "urn:agentapi-doctor:schema:pack-candidate-status:v1", artifacts: []string{
			"packs/openai-chat/candidate.json", "packs/openai-responses-http/candidate.json", "packs/anthropic-messages/candidate.json",
			"packs/extensions/google-generate-content/candidate.json", "packs/extensions/google-interactions/candidate.json",
			"packs/extensions/mcp-2025-11-25/candidate.json", "packs/extensions/ollama-native/candidate.json",
		}},
		{name: "protocol snapshots", schemaPath: "schemas/pack/protocol-snapshot.schema.json", schemaID: "urn:agentapi-doctor:schema:protocol-snapshot:v1", artifacts: []string{
			"specs/protocol-snapshots/openai-chat-2026-07-11.json", "specs/protocol-snapshots/openai-responses-http-2026-07-11.json",
			"specs/protocol-snapshots/anthropic-messages-2026-07-11.json", "specs/protocol-snapshots/google-generate-content-2026-07-11.json",
			"specs/protocol-snapshots/google-interactions-2026-07-11.json", "specs/protocol-snapshots/mcp-2025-11-25.json",
			"specs/protocol-snapshots/ollama-native-2026-07-11.json",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(test.schemaPath)))
			if err != nil {
				t.Fatal(err)
			}
			document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			compiler := jsonschema.NewCompiler()
			compiler.DefaultDraft(jsonschema.Draft2020)
			compiler.AssertFormat()
			if err := compiler.AddResource(test.schemaID, document); err != nil {
				t.Fatal(err)
			}
			compiled, err := compiler.Compile(test.schemaID)
			if err != nil {
				t.Fatal(err)
			}
			for _, artifact := range test.artifacts {
				artifactRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(artifact)))
				if err != nil {
					t.Fatal(err)
				}
				var value any
				decoder := json.NewDecoder(bytes.NewReader(artifactRaw))
				decoder.UseNumber()
				if err := decoder.Decode(&value); err != nil {
					t.Fatal(err)
				}
				if err := compiled.Validate(value); err != nil {
					t.Errorf("%s: %v", artifact, err)
				}
			}
		})
	}
}
