package cli

import (
	"slices"
	"testing"

	agentapidoctor "github.com/whyiug/agentapi-doctor"
	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/productrun"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
	"gopkg.in/yaml.v3"
)

func TestPublishedMigrationFloorMatchesReadersAndWriters(t *testing.T) {
	raw, err := agentapidoctor.ReadAsset("schemas/migration-floor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var floor struct {
		SchemaVersion string `yaml:"schemaVersion"`
		Release       string `yaml:"release"`
		Status        string `yaml:"status"`
		SupportedRead []struct {
			Artifact       string   `yaml:"artifact"`
			SchemaVersions []string `yaml:"schemaVersions"`
			WriteVersion   string   `yaml:"writeVersion"`
		} `yaml:"supportedRead"`
		CurrentWrite map[string]string `yaml:"currentWrite"`
	}
	if err := yaml.Unmarshal(raw, &floor); err != nil {
		t.Fatal(err)
	}
	if floor.SchemaVersion != "urn:agentapi-doctor:migration-floor:v1" || floor.Release != "v0.1.0" || floor.Status != "supported" {
		t.Fatalf("unexpected migration floor header: %#v", floor)
	}
	writes := map[string]string{
		"local-run-record": runstore.RecordSchema,
		"report-bundle":    report.SchemaVersion,
		"persisted-plan":   productrun.PersistedPlanSchema,
		"baseline":         report.BaselineSchemaVersion,
		"cli-result":       resultSchema,
	}
	reads := map[string][]string{
		"local-run-record": {"urn:agentapi-doctor:local-run-record:v1alpha1", runstore.RecordSchema},
		"report-bundle":    {"urn:agentapi-doctor:report-bundle:v1alpha1", report.SchemaVersion},
		"persisted-plan":   {productrun.PersistedPlanSchema},
		"baseline":         {"unversioned-v0.1.0-rc", report.BaselineSchemaVersion},
		"cli-result":       {resultSchema},
	}
	if len(floor.SupportedRead) != len(writes) {
		t.Fatalf("migration floor has %d read entries, want %d", len(floor.SupportedRead), len(writes))
	}
	for _, entry := range floor.SupportedRead {
		if entry.WriteVersion != writes[entry.Artifact] || !slices.Equal(entry.SchemaVersions, reads[entry.Artifact]) {
			t.Fatalf("migration entry drifted: %#v", entry)
		}
		delete(writes, entry.Artifact)
	}
	if len(writes) != 0 {
		t.Fatalf("migration floor omitted artifacts: %v", writes)
	}
	if floor.CurrentWrite["config"] != config.APIVersion {
		t.Fatalf("migration floor config=%q, implementation=%q", floor.CurrentWrite["config"], config.APIVersion)
	}
}
