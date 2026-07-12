package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/packapi"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	requirementCatalogPath = "specs/requirement-catalog.json"
	referenceFixturePath   = "fixtures/canonical/reference-pass.json"
	mutationFixturePath    = "fixtures/mutation/targeted-mutants.json"
	boundaryFixturePath    = "fixtures/boundary/catalog-boundaries.json"
	negativeFixturePath    = "fixtures/negative/catalog-mutants.json"
	statisticsPath         = "specs/catalog-statistics.json"
)

type GeneratedRepository struct {
	Files      map[string][]byte
	Statistics CatalogStatistics
}

type generatedScenario struct {
	Pack         packDefinition
	Requirement  Requirement
	RelativePath string
	OutputPath   string
	YAML         []byte
}

// Generate builds all deterministic candidate artifacts in memory and
// compiles every scenario and pack through packapi before returning bytes.
func Generate(sources SourceLockSet) (*GeneratedRepository, error) {
	if err := validateSourceLocks(sources); err != nil {
		return nil, err
	}
	sourceByID := make(map[string]SourceLock, len(sources.Sources))
	for _, source := range sources.Sources {
		sourceByID[source.ID] = source
	}

	files := make(map[string][]byte)
	snapshotDigestByPack := make(map[string]publicschema.Digest, len(packDefinitions))
	for _, pack := range packDefinitions {
		snapshot := ProtocolSnapshot{
			SchemaVersion: SnapshotSchema,
			Protocol:      pack.Protocol,
			Revision:      pack.SnapshotRevision,
			Status:        StatusCandidate,
			ReviewStatus:  ReviewPending,
			Sources:       make([]SnapshotSourceLock, 0, len(pack.Sources)),
		}
		for _, sourceID := range pack.Sources {
			source, exists := sourceByID[sourceID]
			if !exists {
				return nil, fmt.Errorf("pack %s references unknown source %q", pack.Name, sourceID)
			}
			snapshot.Sources = append(snapshot.Sources, SnapshotSourceLock{SourceID: source.ID, ContentSHA256: source.ContentSHA256})
		}
		slices.SortFunc(snapshot.Sources, func(left, right SnapshotSourceLock) int { return strings.Compare(left.SourceID, right.SourceID) })
		if err := validateSnapshot(snapshot, sources); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", pack.Name, err)
		}
		raw, err := prettyJSON(snapshot)
		if err != nil {
			return nil, err
		}
		files[pack.SnapshotPath] = raw
		snapshotDigestByPack[pack.Name] = publicschema.NewDigest(raw)
	}

	catalog := RequirementCatalog{
		SchemaVersion:   CatalogSchema,
		Generator:       generatorIdentity(),
		Status:          StatusCandidate,
		ReviewStatus:    ReviewPending,
		DenominatorRule: "unique-semantic-key-and-assertion-fingerprint-v1",
	}
	referenceSet := FixtureSet{SchemaVersion: FixtureSetSchema, Generator: generatorIdentity(), Kind: "reference_pass"}
	mutantSet := FixtureSet{SchemaVersion: FixtureSetSchema, Generator: generatorIdentity(), Kind: "targeted_mutant"}
	var scenarios []generatedScenario
	for _, pack := range packDefinitions {
		features := featuresForPack(pack)
		if len(features) != pack.ScenarioCount {
			return nil, fmt.Errorf("pack %s selects %d features, expected %d", pack.Name, len(features), pack.ScenarioCount)
		}
		for index, feature := range features {
			number := index + 1
			requirementID := fmt.Sprintf("%s-%03d", pack.RequirementPrefix, number)
			scenarioID := fmt.Sprintf("%s-%03d-%s", pack.Name, number, feature.Slug)
			referenceID := fmt.Sprintf("ref-%s-%03d", pack.Name, number)
			mutantID := fmt.Sprintf("mut-%s-%03d", pack.Name, number)
			referenceRef := fmt.Sprintf("canonical/%s-%03d.json", pack.Name, number)
			mutantRef := fmt.Sprintf("mutation/%s-%03d.json", pack.Name, number)
			semanticKey := fmt.Sprintf("%s/%s/%s", pack.Protocol, feature.Taxonomy, feature.Slug)
			sourceID := pack.SourceByRole[feature.SourceRole]
			if sourceID == "" {
				sourceID = pack.SourceByRole["general"]
			}
			source, exists := sourceByID[sourceID]
			if !exists {
				return nil, fmt.Errorf("pack %s feature %s has unknown source role %q", pack.Name, feature.Slug, feature.SourceRole)
			}
			interpretation := fmt.Sprintf("Candidate interpretation pending independent source review: %s %s.", pack.DisplayName, feature.Summary)
			locator := "heading-or-field: " + feature.Locator
			fingerprint, err := publicschema.CanonicalDigest(struct {
				Protocol       string              `json:"protocol"`
				Taxonomy       string              `json:"taxonomy"`
				Feature        string              `json:"feature"`
				SourceDigest   publicschema.Digest `json:"source_digest"`
				Locator        string              `json:"locator"`
				Interpretation string              `json:"interpretation"`
				Mutation       string              `json:"mutation"`
			}{pack.Protocol, feature.Taxonomy, feature.Slug, source.ContentSHA256, locator, interpretation, feature.Mutation})
			if err != nil {
				return nil, err
			}
			requirement := Requirement{
				ID: requirementID, Protocol: pack.Protocol, Pack: pack.Name,
				Level: packapi.LevelMust, Category: packapi.ClassNormative,
				Taxonomy: feature.Taxonomy, AssertionRole: packapi.RoleNormative,
				Source:         RequirementSource{SourceID: source.ID, Locator: locator},
				Interpretation: interpretation, SemanticKey: semanticKey, AssertionFingerprint: fingerprint,
				ScenarioID: scenarioID, ReferencePassID: referenceID, TargetedMutantID: mutantID,
				Budget: RequirementBudget{
					Timeout: publicschema.NewDuration(30 * time.Second), MaxRequests: 2,
					MaxInputTokens: 128, MaxOutputTokens: 128, MaxResponseBytes: 64 << 10, MaxArtifactBytes: 1 << 20,
				},
				Status: StatusCandidate, ReviewStatus: ReviewPending,
			}
			catalog.Requirements = append(catalog.Requirements, requirement)
			referenceSet.Fixtures = append(referenceSet.Fixtures, FixtureRecord{
				ID: referenceID, Ref: referenceRef, Kind: "reference_pass", Protocol: pack.Protocol,
				ScenarioID: scenarioID, RequirementID: requirementID, SemanticKey: semanticKey,
				AssertionRole: packapi.RoleNormative, ExpectedVerdict: "pass",
				SyntheticEvidence: SyntheticEvidence{Transport: pack.Transport, Observation: "minimal canonical observation satisfying " + semanticKey, DataClass: "synthetic-only"},
			})
			mutantSet.Fixtures = append(mutantSet.Fixtures, FixtureRecord{
				ID: mutantID, Ref: mutantRef, Kind: "targeted_mutant", Protocol: pack.Protocol,
				ScenarioID: scenarioID, RequirementID: requirementID, SemanticKey: semanticKey,
				AssertionRole: packapi.RoleNormative, ExpectedVerdict: "fail",
				MutationOperator: feature.Mutation, KillsRequirement: requirementID,
				SyntheticEvidence: SyntheticEvidence{Transport: pack.Transport, Observation: "single targeted semantic mutation " + feature.Mutation, DataClass: "synthetic-only"},
			})
			relativePath := filepath.ToSlash(filepath.Join("scenarios", scenarioID+".yaml"))
			outputPath := filepath.ToSlash(filepath.Join(pack.Path, relativePath))
			scenarioYAML, err := renderScenario(pack, requirement, feature, referenceRef, mutantRef, snapshotDigestByPack[pack.Name])
			if err != nil {
				return nil, err
			}
			scenarios = append(scenarios, generatedScenario{Pack: pack, Requirement: requirement, RelativePath: relativePath, OutputPath: outputPath, YAML: scenarioYAML})
			files[outputPath] = scenarioYAML
		}
	}

	if err := validateRequirementCatalog(catalog, sources); err != nil {
		return nil, err
	}
	if err := validateFixtureSet(referenceSet, "reference_pass", catalog); err != nil {
		return nil, err
	}
	if err := validateFixtureSet(mutantSet, "targeted_mutant", catalog); err != nil {
		return nil, err
	}
	catalogRaw, err := prettyJSON(catalog)
	if err != nil {
		return nil, err
	}
	referenceRaw, err := prettyJSON(referenceSet)
	if err != nil {
		return nil, err
	}
	mutantRaw, err := prettyJSON(mutantSet)
	if err != nil {
		return nil, err
	}
	files[requirementCatalogPath] = catalogRaw
	files[referenceFixturePath] = referenceRaw
	files[mutationFixturePath] = mutantRaw

	compileRequirements := make(map[string]packapi.RequirementRecord, len(catalog.Requirements))
	for _, requirement := range catalog.Requirements {
		compileRequirements[requirement.ID] = packapi.RequirementRecord{
			ID: requirement.ID, Level: requirement.Level, Category: requirement.Category,
			SourceDigest: sourceByID[requirement.Source.SourceID].ContentSHA256,
		}
	}
	compileFixtures := make(map[string]publicschema.Digest, len(referenceSet.Fixtures)+len(mutantSet.Fixtures))
	for _, set := range []FixtureSet{referenceSet, mutantSet} {
		for _, fixture := range set.Fixtures {
			digest, err := publicschema.CanonicalDigest(fixture)
			if err != nil {
				return nil, err
			}
			if _, duplicate := compileFixtures[fixture.Ref]; duplicate {
				return nil, fmt.Errorf("duplicate compile fixture ref %q", fixture.Ref)
			}
			compileFixtures[fixture.Ref] = digest
		}
	}

	compiledByPack := make(map[string]map[string]publicschema.Digest, len(packDefinitions))
	for _, scenario := range scenarios {
		compiled, err := packapi.CompileScenarioYAML(scenario.YAML, packapi.CompileOptions{
			Requirements: compileRequirements,
			Fixtures:     compileFixtures,
		})
		if err != nil {
			return nil, fmt.Errorf("compile generated scenario %s: %w", scenario.OutputPath, err)
		}
		if compiled.Authored.Metadata.ID != scenario.Requirement.ScenarioID || len(compiled.IR.RequirementLinks) != 1 || len(compiled.IR.FixturePins) != 2 {
			return nil, fmt.Errorf("scenario %s did not preserve its one requirement/two fixture contract", scenario.OutputPath)
		}
		if compiledByPack[scenario.Pack.Name] == nil {
			compiledByPack[scenario.Pack.Name] = make(map[string]publicschema.Digest)
		}
		compiledByPack[scenario.Pack.Name][scenario.RelativePath] = compiled.Digest
	}

	statistics := CatalogStatistics{
		SchemaVersion: StatisticsSchema, Generator: generatorIdentity(), Status: StatusCandidate, ReviewStatus: ReviewPending,
		ScenarioCount: len(scenarios), RequirementCount: len(catalog.Requirements), NormativeDenominatorCount: len(catalog.Requirements),
		UniqueSemanticCount: len(catalog.Requirements), ReferenceFixtureMetadataCount: len(referenceSet.Fixtures),
		TargetedMutantMetadataCount: len(mutantSet.Fixtures), FixtureRecordsExecutable: false,
		ExecutableMutationGateSatisfied: false, AliasCount: 0,
		Claims: CandidateClaims{},
	}
	statistics.CatalogDigest, err = publicschema.CanonicalDigest(catalog)
	if err != nil {
		return nil, err
	}
	members := make([]DenominatorMember, 0, len(catalog.Requirements))
	for _, requirement := range catalog.Requirements {
		members = append(members, DenominatorMember{
			RequirementID: requirement.ID, ScenarioID: requirement.ScenarioID, Pack: requirement.Pack,
			Taxonomy: requirement.Taxonomy, SemanticKey: requirement.SemanticKey,
			AssertionFingerprint: requirement.AssertionFingerprint,
			ReferencePassID:      requirement.ReferencePassID, TargetedMutantID: requirement.TargetedMutantID,
		})
	}
	slices.SortFunc(members, func(left, right DenominatorMember) int {
		return strings.Compare(left.RequirementID, right.RequirementID)
	})
	statistics.DenominatorDigest, err = publicschema.CanonicalDigest(members)
	if err != nil {
		return nil, err
	}

	for _, pack := range packDefinitions {
		packRaw := renderPack(pack)
		compiledPack, err := packapi.CompileProtocolPackYAML(packRaw, packapi.PackCompileOptions{
			ProtocolSnapshots: map[string]publicschema.Digest{pack.SnapshotPath: snapshotDigestByPack[pack.Name]},
			ScenarioFiles:     compiledByPack[pack.Name],
		})
		if err != nil {
			return nil, fmt.Errorf("compile generated pack %s: %w", pack.Name, err)
		}
		if len(compiledPack.IR.ScenarioPins) != pack.ScenarioCount {
			return nil, fmt.Errorf("pack %s compiled %d scenarios, expected %d", pack.Name, len(compiledPack.IR.ScenarioPins), pack.ScenarioCount)
		}
		files[filepath.ToSlash(filepath.Join(pack.Path, "pack.yaml"))] = packRaw
		status := packStatus(pack)
		if err := validatePackStatus(status, pack.Name); err != nil {
			return nil, err
		}
		statusRaw, err := prettyJSON(status)
		if err != nil {
			return nil, err
		}
		files[filepath.ToSlash(filepath.Join(pack.Path, "candidate.json"))] = statusRaw
		statistics.Packs = append(statistics.Packs, PackStatistics{
			Pack: pack.Name, Protocol: pack.Protocol, ReleaseTrack: pack.ReleaseTrack,
			ScenarioCount: pack.ScenarioCount, RequirementCount: pack.ScenarioCount,
			SnapshotDigest: snapshotDigestByPack[pack.Name], CompiledPackDigest: compiledPack.Digest,
		})
	}

	boundaryRaw, err := prettyJSON(boundaryFixtures())
	if err != nil {
		return nil, err
	}
	negativeRaw, err := prettyJSON(negativeFixtures())
	if err != nil {
		return nil, err
	}
	files[boundaryFixturePath] = boundaryRaw
	files[negativeFixturePath] = negativeRaw
	if err := validateCatalogStatistics(statistics, len(catalog.Requirements), len(referenceSet.Fixtures), len(mutantSet.Fixtures)); err != nil {
		return nil, err
	}
	statisticsRaw, err := prettyJSON(statistics)
	if err != nil {
		return nil, err
	}
	files[statisticsPath] = statisticsRaw
	return &GeneratedRepository{Files: files, Statistics: statistics}, nil
}

func renderScenario(pack packDefinition, requirement Requirement, feature featureDefinition, referenceRef, mutantRef string, snapshotDigest publicschema.Digest) ([]byte, error) {
	if err := snapshotDigest.Validate(); err != nil {
		return nil, err
	}
	quote := func(value string) string {
		raw, _ := json.Marshal(value)
		return string(raw)
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "apiVersion: %s\n", packapi.ScenarioAPIVersion)
	fmt.Fprintf(&output, "kind: %s\n", packapi.ScenarioKind)
	fmt.Fprintln(&output, "metadata:")
	fmt.Fprintf(&output, "  id: %s\n", requirement.ScenarioID)
	fmt.Fprintln(&output, "  version: 0.1.0")
	fmt.Fprintf(&output, "  title: %s\n", quote("Candidate: "+pack.DisplayName+" / "+feature.Slug))
	fmt.Fprintln(&output, "  labels:")
	fmt.Fprintln(&output, "    generator: catalog-v1")
	fmt.Fprintf(&output, "    protocol: %s\n", pack.Protocol)
	fmt.Fprintf(&output, "    taxonomy: %s\n", feature.Taxonomy)
	fmt.Fprintln(&output, "    review: pending-review")
	fmt.Fprintf(&output, "    reference: %s\n", requirement.ReferencePassID)
	fmt.Fprintf(&output, "    mutant: %s\n", requirement.TargetedMutantID)
	fmt.Fprintln(&output, "spec:")
	fmt.Fprintln(&output, "  protocol:")
	fmt.Fprintf(&output, "    family: %s\n", pack.Protocol)
	fmt.Fprintf(&output, "    snapshot: %s\n", quote(pack.SnapshotRevision))
	fmt.Fprintf(&output, "    digest: %s\n", snapshotDigest)
	fmt.Fprintln(&output, "  classification:")
	fmt.Fprintln(&output, "    type: normative")
	fmt.Fprintf(&output, "    stability: %s\n", pack.Stability)
	fmt.Fprintln(&output, "    sideEffects: none")
	fmt.Fprintln(&output, "    idempotent: true")
	fmt.Fprintln(&output, "  requirements:")
	fmt.Fprintf(&output, "    - id: %s\n", requirement.ID)
	fmt.Fprintln(&output, "      level: MUST")
	fmt.Fprintln(&output, "  requires:")
	fmt.Fprintln(&output, "    all:")
	fmt.Fprintln(&output, "      - offline-fixture")
	fmt.Fprintln(&output, "  budgets:")
	fmt.Fprintln(&output, "    timeout: 30s")
	fmt.Fprintln(&output, "    maxRequests: 2")
	fmt.Fprintln(&output, "    maxInputTokens: 128")
	fmt.Fprintln(&output, "    maxOutputTokens: 128")
	fmt.Fprintln(&output, "    maxResponseBytes: 64KiB")
	fmt.Fprintln(&output, "    maxArtifactBytes: 1MiB")
	fmt.Fprintln(&output, "  steps:")
	fmt.Fprintln(&output, "    - id: reference")
	fmt.Fprintln(&output, "      replay:")
	fmt.Fprintf(&output, "        fixture: %s\n", referenceRef)
	fmt.Fprintln(&output, "        as: reference-pass")
	fmt.Fprintln(&output, "    - id: mutant")
	fmt.Fprintln(&output, "      replay:")
	fmt.Fprintf(&output, "        fixture: %s\n", mutantRef)
	fmt.Fprintln(&output, "        as: targeted-mutant")
	fmt.Fprintln(&output, "    - id: assertion")
	fmt.Fprintln(&output, "      assert:")
	fmt.Fprintf(&output, "        - use: catalog.%s\n", feature.Slug)
	fmt.Fprintln(&output, "          equals: true")
	fmt.Fprintln(&output, "          assertionRole: normative")
	fmt.Fprintf(&output, "          requirement: %s\n", requirement.ID)
	fmt.Fprintln(&output, "  repetition:")
	fmt.Fprintln(&output, "    count: 1")
	fmt.Fprintln(&output, "    policy: all")
	fmt.Fprintln(&output, "  publication:")
	fmt.Fprintln(&output, "    dataClass: synthetic-only")
	return output.Bytes(), nil
}

func renderPack(pack packDefinition) []byte {
	var output bytes.Buffer
	fmt.Fprintf(&output, "apiVersion: %s\n", packapi.PackAPIVersion)
	fmt.Fprintf(&output, "kind: %s\n", packapi.PackKind)
	fmt.Fprintln(&output, "metadata:")
	fmt.Fprintf(&output, "  name: %s\n", pack.Name)
	fmt.Fprintln(&output, "  version: 2026.07.0")
	fmt.Fprintln(&output, "spec:")
	fmt.Fprintln(&output, "  engine:")
	fmt.Fprintln(&output, "    minVersion: 0.1.0")
	fmt.Fprintln(&output, "    maxMajor: 1")
	fmt.Fprintln(&output, "  protocolSnapshot:")
	fmt.Fprintf(&output, "    ref: %s\n", pack.SnapshotPath)
	fmt.Fprintln(&output, "  scenarios:")
	fmt.Fprintln(&output, "    include:")
	fmt.Fprintln(&output, "      - scenarios/*.yaml")
	fmt.Fprintln(&output, "  conformanceSuites:")
	fmt.Fprintln(&output, "    candidate-normative:")
	fmt.Fprintln(&output, "      requirements:")
	fmt.Fprintln(&output, "        - catalog-normative")
	fmt.Fprintln(&output, "  defaultBudget:")
	fmt.Fprintf(&output, "    maxRequests: %d\n", pack.ScenarioCount*2)
	fmt.Fprintln(&output, "    maxDuration: 15m0s")
	return output.Bytes()
}

func packStatus(pack packDefinition) PackCandidateStatus {
	return PackCandidateStatus{
		SchemaVersion: PackStatusSchema, Pack: pack.Name, Protocol: pack.Protocol,
		ReleaseTrack: pack.ReleaseTrack, Status: StatusCandidate, ReviewStatus: ReviewPending,
		ClaimedTier: ClaimedTierNone, Publication: PublicationBlocked,
		IndependentReview: false, RealSDKValidation: false, LiveProviderVerified: false,
		KnownGaps: []string{
			"Candidate source interpretations require independent protocol-maintainer review.",
			"Only deterministic synthetic fixtures have been compiled; no live provider was contacted.",
			"No real SDK or consumer compatibility result is claimed.",
		},
	}
}

func boundaryFixtures() BoundarySet {
	return BoundarySet{
		SchemaVersion: BoundarySetSchema, Generator: generatorIdentity(),
		Cases: []BoundaryCase{
			{ID: "minimum-denominator", Boundary: "scenario_count", Input: json.RawMessage(`249`), Expectation: "reject below 250"},
			{ID: "exact-denominator", Boundary: "scenario_count", Input: json.RawMessage(`250`), Expectation: "accept when all other invariants hold"},
			{ID: "maximum-source-locator", Boundary: "source_locator_bytes", Input: json.RawMessage(`512`), Expectation: "accept exact bound"},
			{ID: "oversized-source-locator", Boundary: "source_locator_bytes", Input: json.RawMessage(`513`), Expectation: "reject above bound"},
			{ID: "fixture-path-depth", Boundary: "fixture_ref", Input: json.RawMessage(`"canonical/a.json"`), Expectation: "accept canonical relative path"},
			{ID: "fixture-path-traversal", Boundary: "fixture_ref", Input: json.RawMessage(`"../a.json"`), Expectation: "reject traversal"},
		},
	}
}

func negativeFixtures() NegativeSet {
	return NegativeSet{
		SchemaVersion: NegativeSetSchema, Generator: generatorIdentity(),
		Cases: []NegativeCase{
			{ID: "duplicate-json-key", Mutation: "duplicate a top-level JSON member", Input: json.RawMessage(`"{\"status\":\"candidate\",\"status\":\"stable\"}"`), RejectStage: "strict-json"},
			{ID: "unknown-json-field", Mutation: "add an unrecognized contract member", Input: json.RawMessage(`{"unknown":true}`), RejectStage: "strict-json"},
			{ID: "floating-source-revision", Mutation: "replace exact revision with latest", Input: json.RawMessage(`"latest"`), RejectStage: "source-lock"},
			{ID: "unknown-requirement-source", Mutation: "bind requirement to absent source ID", Input: json.RawMessage(`"missing-source"`), RejectStage: "requirement-link"},
			{ID: "duplicate-semantic-key", Mutation: "rename a scenario without changing its semantic key", Input: json.RawMessage(`"duplicate/semantic/key"`), RejectStage: "denominator"},
			{ID: "untargeted-mutant", Mutation: "remove kills_requirement", Input: json.RawMessage(`null`), RejectStage: "fixture-link"},
			{ID: "tier-one-claim", Mutation: "mark candidate as Tier 1", Input: json.RawMessage(`"tier1"`), RejectStage: "candidate-status"},
		},
	}
}

func prettyJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := publicschema.CanonicalizeJSON(raw); err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func definitionByName(name string) (packDefinition, error) {
	for _, pack := range packDefinitions {
		if pack.Name == name {
			return pack, nil
		}
	}
	return packDefinition{}, errors.New("unknown pack " + name)
}
