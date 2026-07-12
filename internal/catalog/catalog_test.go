package catalog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/whyiug/agentapi-doctor/pkg/packapi"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

func repositoryRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate catalog test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func TestLogicalFixtureRefUsesPortableSlashSemantics(t *testing.T) {
	for _, value := range []string{
		"canonical/openai-chat-001.json",
		"nested/canonical/fixture.json",
	} {
		if err := validateLogicalFixtureRef(value); err != nil {
			t.Fatalf("portable fixture ref %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"canonical\\fixture.json",
		"/canonical/fixture.json",
		"canonical//fixture.json",
		"canonical/../fixture.json",
	} {
		if err := validateLogicalFixtureRef(value); err == nil {
			t.Fatalf("accepted unsafe fixture ref %q", value)
		}
	}
}

func TestGenerateDeterministicCandidateMatrix(t *testing.T) {
	root := repositoryRoot(t)
	sources, err := LoadSourceLocks(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Generate(sources)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(sources)
	if err != nil {
		t.Fatal(err)
	}
	if first.Statistics.ScenarioCount != 260 || first.Statistics.NormativeDenominatorCount != 260 {
		t.Fatalf("unexpected candidate denominator: %+v", first.Statistics)
	}
	if first.Statistics.ReferenceFixtureMetadataCount != 260 || first.Statistics.TargetedMutantMetadataCount != 260 {
		t.Fatalf("unexpected fixture metadata inventory: %+v", first.Statistics)
	}
	if first.Statistics.FixtureRecordsExecutable || first.Statistics.ExecutableMutationGateSatisfied {
		t.Fatal("fixture metadata was misrepresented as executable mutation-gate evidence")
	}
	if first.Statistics.AliasCount != 0 || first.Statistics.Claims.Tier1 || first.Statistics.Claims.IndependentReview || first.Statistics.Claims.RealSDKValidation || first.Statistics.Claims.LiveProviderVerified {
		t.Fatal("candidate statistics contain a forbidden claim")
	}
	if first.Statistics.DenominatorDigest != second.Statistics.DenominatorDigest {
		t.Fatal("deterministic generation changed denominator digest")
	}
	if len(first.Files) != len(second.Files) {
		t.Fatal("deterministic generation changed the file set")
	}
	for path, want := range first.Files {
		if got, exists := second.Files[path]; !exists || !bytes.Equal(got, want) {
			t.Fatalf("deterministic generation changed %s", path)
		}
	}
}

func TestCatalogStatisticsRejectExecutableMetadataClaims(t *testing.T) {
	root := repositoryRoot(t)
	repository, err := LoadRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Generate(repository.Sources)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CatalogStatistics){
		"executable fixture records": func(statistics *CatalogStatistics) { statistics.FixtureRecordsExecutable = true },
		"satisfied mutation gate":    func(statistics *CatalogStatistics) { statistics.ExecutableMutationGateSatisfied = true },
		"inflated reference metadata": func(statistics *CatalogStatistics) {
			statistics.ReferenceFixtureMetadataCount++
		},
		"inflated mutant metadata": func(statistics *CatalogStatistics) {
			statistics.TargetedMutantMetadataCount++
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutant := generated.Statistics
			mutate(&mutant)
			if err := validateCatalogStatistics(mutant, len(repository.Requirements.Requirements), len(repository.ReferenceFixtures.Fixtures), len(repository.MutationFixtures.Fixtures)); err == nil {
				t.Fatal("accepted misleading catalog statistics")
			}
		})
	}
}

func TestCatalogStatisticsSchemaRejectsLegacyAndExecutableClaims(t *testing.T) {
	root := repositoryRoot(t)
	schemaRaw, err := os.ReadFile(filepath.Join(root, "schemas", "result", "catalog-statistics.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("urn:agentapi-doctor:schema:catalog-statistics:v1", document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:agentapi-doctor:schema:catalog-statistics:v1")
	if err != nil {
		t.Fatal(err)
	}
	statisticsRaw, err := os.ReadFile(filepath.Join(root, "specs", "catalog-statistics.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertValid := func(t *testing.T, raw []byte, wantValid bool) {
		t.Helper()
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		err = compiled.Validate(value)
		if wantValid && err != nil {
			t.Fatalf("reference catalog statistics rejected: %v", err)
		}
		if !wantValid && err == nil {
			t.Fatal("misleading catalog statistics accepted")
		}
	}
	assertValid(t, statisticsRaw, true)
	for name, mutant := range map[string][]byte{
		"legacy fixture count": bytes.Replace(statisticsRaw, []byte(`"reference_fixture_metadata_count"`), []byte(`"reference_pass_fixture_count"`), 1),
		"executable records":   bytes.Replace(statisticsRaw, []byte(`"fixture_records_executable": false`), []byte(`"fixture_records_executable": true`), 1),
		"satisfied gate":       bytes.Replace(statisticsRaw, []byte(`"executable_mutation_gate_satisfied": false`), []byte(`"executable_mutation_gate_satisfied": true`), 1),
	} {
		t.Run(name, func(t *testing.T) { assertValid(t, mutant, false) })
	}
}

func TestStrictJSONRejectsDuplicateUnknownAndTrailingValues(t *testing.T) {
	type small struct {
		Status string `json:"status"`
	}
	for name, raw := range map[string][]byte{
		"duplicate": []byte(`{"status":"candidate","status":"stable"}`),
		"unknown":   []byte(`{"status":"candidate","extra":true}`),
		"trailing":  []byte(`{"status":"candidate"} []`),
	} {
		t.Run(name, func(t *testing.T) {
			var destination small
			if err := decodeStrictJSON(raw, &destination); err == nil {
				t.Fatal("accepted malformed strict JSON")
			}
		})
	}
	var destination small
	if err := decodeStrictJSON([]byte(`{"status":"candidate"}`), &destination); err != nil || destination.Status != StatusCandidate {
		t.Fatalf("rejected strict reference JSON: %v", err)
	}
}

func TestSourceLocksRejectFloatingUnofficialAndMismatchedContent(t *testing.T) {
	locks, err := LoadSourceLocks(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*SourceLock)
	}{
		{name: "floating", mutate: func(source *SourceLock) { source.Revision = "latest" }},
		{name: "unofficial", mutate: func(source *SourceLock) { source.ResolvedURL = "https://example.com/spec" }},
		{name: "digest mismatch", mutate: func(source *SourceLock) {
			source.ContentSHA256 = publicschema.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutant := locks
			mutant.Sources = slices.Clone(locks.Sources)
			test.mutate(&mutant.Sources[0])
			if err := validateSourceLocks(mutant); err == nil {
				t.Fatal("accepted invalid source lock")
			}
		})
	}
}

func TestDenominatorRejectsAliasesRenamesAndUnknownSource(t *testing.T) {
	repository, err := LoadRepository(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]Requirement)
	}{
		{name: "semantic alias", mutate: func(requirements []Requirement) { requirements[1].SemanticKey = requirements[0].SemanticKey }},
		{name: "renamed assertion", mutate: func(requirements []Requirement) {
			requirements[1].AssertionFingerprint = requirements[0].AssertionFingerprint
		}},
		{name: "unknown source", mutate: func(requirements []Requirement) { requirements[0].Source.SourceID = "missing-source" }},
		{name: "floating-like missing scenario", mutate: func(requirements []Requirement) { requirements[0].ScenarioID = "latest" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutant := repository.Requirements
			mutant.Requirements = slices.Clone(repository.Requirements.Requirements)
			test.mutate(mutant.Requirements)
			if err := validateRequirementCatalog(mutant, repository.Sources); err == nil {
				t.Fatal("accepted invalid denominator mutation")
			}
		})
	}
}

func TestFixtureAndCandidateClaimMutantsFailClosed(t *testing.T) {
	repository, err := LoadRepository(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	mutants := repository.MutationFixtures
	mutants.Fixtures = slices.Clone(mutants.Fixtures)
	mutants.Fixtures[0].KillsRequirement = ""
	if err := validateFixtureSet(mutants, "targeted_mutant", repository.Requirements); err == nil {
		t.Fatal("accepted untargeted mutant fixture")
	}
	references := repository.ReferenceFixtures
	references.Fixtures = slices.Clone(references.Fixtures)
	references.Fixtures[0].ExpectedVerdict = "fail"
	if err := validateFixtureSet(references, "reference_pass", repository.Requirements); err == nil {
		t.Fatal("accepted failing reference-pass fixture")
	}
	status := repository.PackStatuses["openai-chat"]
	status.ClaimedTier = "tier1"
	if err := validatePackStatus(status, "openai-chat"); err == nil {
		t.Fatal("accepted a Tier 1 claim on a pending candidate")
	}
}

func TestFeatureSelectionHasNoRenameDuplicates(t *testing.T) {
	total := 0
	global := make(map[string]struct{})
	for _, pack := range packDefinitions {
		features := featuresForPack(pack)
		if len(features) != pack.ScenarioCount {
			t.Fatalf("pack %s selected %d features, expected %d", pack.Name, len(features), pack.ScenarioCount)
		}
		local := make(map[string]struct{}, len(features))
		taxonomy := make(map[string]struct{})
		for _, feature := range features {
			if _, duplicate := local[feature.Slug]; duplicate {
				t.Fatalf("pack %s repeats feature %s", pack.Name, feature.Slug)
			}
			local[feature.Slug] = struct{}{}
			taxonomy[feature.Taxonomy] = struct{}{}
			key := pack.Protocol + "/" + feature.Taxonomy + "/" + feature.Slug
			if _, duplicate := global[key]; duplicate {
				t.Fatalf("global semantic duplicate %s", key)
			}
			global[key] = struct{}{}
		}
		if len(taxonomy) < 8 {
			t.Fatalf("pack %s has inadequate taxonomy spread: %d", pack.Name, len(taxonomy))
		}
		total += len(features)
	}
	if total != 260 || len(global) != 260 {
		t.Fatalf("semantic matrix total=%d unique=%d", total, len(global))
	}
}

func TestGeneratedScenarioTargetedRequirementMutantIsRejected(t *testing.T) {
	root := repositoryRoot(t)
	repository, err := LoadRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Generate(repository.Sources)
	if err != nil {
		t.Fatal(err)
	}
	var scenarioPath string
	for path := range generated.Files {
		if strings.HasPrefix(path, "packs/openai-chat/scenarios/") {
			scenarioPath = path
			break
		}
	}
	if scenarioPath == "" {
		t.Fatal("no generated scenario found")
	}
	raw := generated.Files[scenarioPath]
	mutant := bytes.Replace(raw, []byte("OAI-CHAT-REQ-"), []byte("MISSING-REQ-"), 1)
	_, err = packapi.CompileScenarioYAML(mutant, packapi.CompileOptions{
		Requirements: repository.CompileRequirements, Fixtures: repository.CompileFixtures,
	})
	if err == nil || !packapi.IsCompileStage(err, packapi.StageRequirement) {
		t.Fatalf("targeted unknown-requirement mutant was not rejected at requirement stage: %v", err)
	}
}

func TestCompiledScenarioRejectsFloatingSnapshotAndFixtureIDSubstitution(t *testing.T) {
	root := repositoryRoot(t)
	repository, err := LoadRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := definitionByName("openai-chat")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "packs", "openai-chat", "scenarios", "openai-chat-001-endpoint-method.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := packapi.CompileScenarioYAML(raw, packapi.CompileOptions{
		Requirements: repository.CompileRequirements, Fixtures: repository.CompileFixtures,
	})
	if err != nil {
		t.Fatal(err)
	}
	var requirement Requirement
	for _, candidate := range repository.Requirements.Requirements {
		if candidate.ScenarioID == compiled.Authored.Metadata.ID {
			requirement = candidate
			break
		}
	}
	if requirement.ID == "" {
		t.Fatal("scenario requirement not found")
	}
	references := make(map[string]FixtureRecord)
	for _, fixture := range repository.ReferenceFixtures.Fixtures {
		references[fixture.ID] = fixture
	}
	mutants := make(map[string]FixtureRecord)
	for _, fixture := range repository.MutationFixtures.Fixtures {
		mutants[fixture.ID] = fixture
	}
	snapshotRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pack.SnapshotPath)))
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest := publicschema.NewDigest(snapshotRaw)
	if err := validateCompiledDenominatorScenario(compiled, pack, requirement, references, mutants, snapshotDigest); err != nil {
		t.Fatalf("reference scenario rejected: %v", err)
	}
	floating := *compiled
	floating.Authored = compiled.Authored
	floating.Authored.Spec.Protocol.Snapshot = "latest"
	if err := validateCompiledDenominatorScenario(&floating, pack, requirement, references, mutants, snapshotDigest); err == nil {
		t.Fatal("accepted floating scenario snapshot")
	}
	substituted := *compiled
	substituted.Authored = compiled.Authored
	substituted.Authored.Metadata.Labels = mapsClone(compiled.Authored.Metadata.Labels)
	substituted.Authored.Metadata.Labels["mutant"] = requirement.ReferencePassID
	if err := validateCompiledDenominatorScenario(&substituted, pack, requirement, references, mutants, snapshotDigest); err == nil {
		t.Fatal("accepted substituted mutant fixture ID")
	}
}

func mapsClone[K comparable, V any](source map[K]V) map[K]V {
	clone := make(map[K]V, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func TestPublishedCatalogSchemasAreStrictJSON(t *testing.T) {
	root := repositoryRoot(t)
	paths := []string{
		"schemas/pack/source-lock.schema.json",
		"schemas/pack/requirement-catalog.schema.json",
		"schemas/pack/candidate-status.schema.json",
		"schemas/pack/protocol-snapshot.schema.json",
		"schemas/result/catalog-statistics.schema.json",
	}
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publicschema.CanonicalizeJSON(raw); err != nil {
			t.Errorf("%s is not strict JSON: %v", path, err)
		}
	}
}

func FuzzDecodeStrictJSONNeverPanics(fuzz *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"status":"candidate"}`),
		[]byte(`{"status":"candidate","status":"stable"}`),
		[]byte(`{} []`),
		{0xff, 0xfe},
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		var destination struct {
			Status string `json:"status"`
		}
		_ = decodeStrictJSON(raw, &destination)
	})
}

func TestStrictJSONDuplicateErrorIdentity(t *testing.T) {
	var destination map[string]any
	err := decodeStrictJSON([]byte(`{"a":1,"a":2}`), &destination)
	if !errors.Is(err, publicschema.ErrDuplicateJSONKey) {
		t.Fatalf("duplicate-key identity was lost: %v", err)
	}
}
