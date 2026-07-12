package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/packapi"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const sourceLocksPath = "specs/sources.lock.json"

func LoadSourceLocks(root string) (SourceLockSet, error) {
	var locks SourceLockSet
	if err := readStrictFile(root, sourceLocksPath, &locks); err != nil {
		return SourceLockSet{}, err
	}
	if err := validateSourceLocks(locks); err != nil {
		return SourceLockSet{}, fmt.Errorf("validate %s: %w", sourceLocksPath, err)
	}
	return locks, nil
}

func LoadRepository(root string) (*Repository, error) {
	sources, err := LoadSourceLocks(root)
	if err != nil {
		return nil, err
	}
	var requirements RequirementCatalog
	if err := readStrictFile(root, requirementCatalogPath, &requirements); err != nil {
		return nil, err
	}
	if err := validateRequirementCatalog(requirements, sources); err != nil {
		return nil, fmt.Errorf("validate %s: %w", requirementCatalogPath, err)
	}
	var references FixtureSet
	if err := readStrictFile(root, referenceFixturePath, &references); err != nil {
		return nil, err
	}
	if err := validateFixtureSet(references, "reference_pass", requirements); err != nil {
		return nil, fmt.Errorf("validate %s: %w", referenceFixturePath, err)
	}
	var mutants FixtureSet
	if err := readStrictFile(root, mutationFixturePath, &mutants); err != nil {
		return nil, err
	}
	if err := validateFixtureSet(mutants, "targeted_mutant", requirements); err != nil {
		return nil, fmt.Errorf("validate %s: %w", mutationFixturePath, err)
	}

	repository := &Repository{
		Sources: sources, Requirements: requirements, ReferenceFixtures: references, MutationFixtures: mutants,
		PackStatuses: make(map[string]PackCandidateStatus), Snapshots: make(map[string]ProtocolSnapshot),
		CompileRequirements: make(map[string]packapi.RequirementRecord, len(requirements.Requirements)),
		CompileFixtures:     make(map[string]publicschema.Digest, len(references.Fixtures)+len(mutants.Fixtures)),
	}
	sourceByID := make(map[string]SourceLock, len(sources.Sources))
	for _, source := range sources.Sources {
		sourceByID[source.ID] = source
	}
	knownPacks := make(map[string]struct{}, len(packDefinitions))
	for _, pack := range packDefinitions {
		knownPacks[pack.Name] = struct{}{}
		var status PackCandidateStatus
		statusPath := filepath.ToSlash(filepath.Join(pack.Path, "candidate.json"))
		if err := readStrictFile(root, statusPath, &status); err != nil {
			return nil, err
		}
		if err := validatePackStatus(status, pack.Name); err != nil {
			return nil, fmt.Errorf("validate %s: %w", statusPath, err)
		}
		if status.Protocol != pack.Protocol || status.ReleaseTrack != pack.ReleaseTrack {
			return nil, fmt.Errorf("validate %s: protocol or release track does not match the pack definition", statusPath)
		}
		repository.PackStatuses[pack.Name] = status
		var snapshot ProtocolSnapshot
		if err := readStrictFile(root, pack.SnapshotPath, &snapshot); err != nil {
			return nil, err
		}
		if err := validateSnapshot(snapshot, sources); err != nil {
			return nil, fmt.Errorf("validate %s: %w", pack.SnapshotPath, err)
		}
		if snapshot.Protocol != pack.Protocol || snapshot.Revision != pack.SnapshotRevision {
			return nil, fmt.Errorf("validate %s: protocol or revision does not match the pack definition", pack.SnapshotPath)
		}
		repository.Snapshots[pack.SnapshotPath] = snapshot
	}
	for _, requirement := range requirements.Requirements {
		if _, exists := knownPacks[requirement.Pack]; !exists {
			return nil, fmt.Errorf("requirement %s references unknown pack %q", requirement.ID, requirement.Pack)
		}
		definition, err := definitionByName(requirement.Pack)
		if err != nil || definition.Protocol != requirement.Protocol {
			return nil, fmt.Errorf("requirement %s protocol does not match pack %q", requirement.ID, requirement.Pack)
		}
		source := sourceByID[requirement.Source.SourceID]
		repository.CompileRequirements[requirement.ID] = packapi.RequirementRecord{
			ID: requirement.ID, Level: requirement.Level, Category: requirement.Category, SourceDigest: source.ContentSHA256,
		}
	}
	for _, set := range []FixtureSet{references, mutants} {
		for _, fixture := range set.Fixtures {
			digest, err := publicschema.CanonicalDigest(fixture)
			if err != nil {
				return nil, err
			}
			if _, duplicate := repository.CompileFixtures[fixture.Ref]; duplicate {
				return nil, fmt.Errorf("duplicate fixture ref %q", fixture.Ref)
			}
			repository.CompileFixtures[fixture.Ref] = digest
		}
	}
	return repository, nil
}

func WriteGenerated(root string) (*CatalogStatistics, error) {
	sources, err := LoadSourceLocks(root)
	if err != nil {
		return nil, err
	}
	generated, err := Generate(sources)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(generated.Files))
	for path := range generated.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := ensureWithinRoot(root, path); err != nil {
			return nil, fmt.Errorf("generated path %s: %w", path, err)
		}
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(absolute, generated.Files[path], 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return &generated.Statistics, nil
}

func Check(root string) (*CatalogStatistics, error) {
	repository, err := LoadRepository(root)
	if err != nil {
		return nil, err
	}
	generated, err := Generate(repository.Sources)
	if err != nil {
		return nil, err
	}
	var boundary BoundarySet
	if err := readStrictFile(root, boundaryFixturePath, &boundary); err != nil {
		return nil, err
	}
	if boundary.SchemaVersion != BoundarySetSchema || boundary.Generator != generatorIdentity() || len(boundary.Cases) == 0 {
		return nil, errors.New("boundary fixture set identity mismatch")
	}
	var negative NegativeSet
	if err := readStrictFile(root, negativeFixturePath, &negative); err != nil {
		return nil, err
	}
	if negative.SchemaVersion != NegativeSetSchema || negative.Generator != generatorIdentity() || len(negative.Cases) == 0 {
		return nil, errors.New("negative fixture set identity mismatch")
	}
	var checkedStatistics CatalogStatistics
	if err := readStrictFile(root, statisticsPath, &checkedStatistics); err != nil {
		return nil, err
	}
	if err := validateCatalogStatistics(checkedStatistics, len(repository.Requirements.Requirements), len(repository.ReferenceFixtures.Fixtures), len(repository.MutationFixtures.Fixtures)); err != nil {
		return nil, fmt.Errorf("catalog statistics: %w", err)
	}
	paths := make([]string, 0, len(generated.Files))
	for path := range generated.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return nil, fmt.Errorf("read generated artifact %s: %w", path, err)
		}
		if !bytes.Equal(actual, generated.Files[path]) {
			return nil, fmt.Errorf("generated artifact %s is stale; run catalog-check --write", path)
		}
	}
	if err := rejectUnexpectedGeneratedFiles(root, generated.Files); err != nil {
		return nil, err
	}
	if err := compileCheckedIn(root, repository); err != nil {
		return nil, err
	}
	return &generated.Statistics, nil
}

func compileCheckedIn(root string, repository *Repository) error {
	requirementByScenario := make(map[string]Requirement, len(repository.Requirements.Requirements))
	for _, requirement := range repository.Requirements.Requirements {
		requirementByScenario[requirement.ScenarioID] = requirement
	}
	referenceByID := make(map[string]FixtureRecord, len(repository.ReferenceFixtures.Fixtures))
	for _, fixture := range repository.ReferenceFixtures.Fixtures {
		referenceByID[fixture.ID] = fixture
	}
	mutantByID := make(map[string]FixtureRecord, len(repository.MutationFixtures.Fixtures))
	for _, fixture := range repository.MutationFixtures.Fixtures {
		mutantByID[fixture.ID] = fixture
	}
	for _, pack := range packDefinitions {
		directory := filepath.Join(root, filepath.FromSlash(pack.Path), "scenarios")
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		snapshotRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pack.SnapshotPath)))
		if err != nil {
			return err
		}
		snapshotDigest := publicschema.NewDigest(snapshotRaw)
		scenarioFiles := make(map[string]publicschema.Digest, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				return fmt.Errorf("unexpected non-scenario entry %s", filepath.Join(directory, entry.Name()))
			}
			raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				return err
			}
			compiled, err := packapi.CompileScenarioYAML(raw, packapi.CompileOptions{
				Requirements: repository.CompileRequirements, Fixtures: repository.CompileFixtures,
			})
			if err != nil {
				return fmt.Errorf("compile checked-in scenario %s/%s: %w", pack.Name, entry.Name(), err)
			}
			requirement, exists := requirementByScenario[compiled.Authored.Metadata.ID]
			if !exists || requirement.Pack != pack.Name {
				return fmt.Errorf("scenario %s is not a one-requirement/reference/mutant denominator member", entry.Name())
			}
			if err := validateCompiledDenominatorScenario(compiled, pack, requirement, referenceByID, mutantByID, snapshotDigest); err != nil {
				return fmt.Errorf("scenario %s: %w", entry.Name(), err)
			}
			scenarioFiles["scenarios/"+entry.Name()] = compiled.Digest
		}
		if len(scenarioFiles) != pack.ScenarioCount {
			return fmt.Errorf("pack %s has %d scenario files, expected %d", pack.Name, len(scenarioFiles), pack.ScenarioCount)
		}
		packRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pack.Path), "pack.yaml"))
		if err != nil {
			return err
		}
		compiledPack, err := packapi.CompileProtocolPackYAML(packRaw, packapi.PackCompileOptions{
			ProtocolSnapshots: map[string]publicschema.Digest{pack.SnapshotPath: snapshotDigest},
			ScenarioFiles:     scenarioFiles,
		})
		if err != nil {
			return fmt.Errorf("compile checked-in pack %s: %w", pack.Name, err)
		}
		if compiledPack.Authored.Metadata.Name != pack.Name || compiledPack.Authored.Spec.ProtocolSnapshot.Ref != pack.SnapshotPath || len(compiledPack.IR.ScenarioPins) != pack.ScenarioCount {
			return fmt.Errorf("compiled pack %s does not preserve its exact name, snapshot, and scenario denominator", pack.Name)
		}
	}
	return nil
}

func validateCompiledDenominatorScenario(compiled *packapi.CompiledScenario, pack packDefinition, requirement Requirement, references, mutants map[string]FixtureRecord, snapshotDigest publicschema.Digest) error {
	if compiled.Authored.Metadata.ID != requirement.ScenarioID || compiled.Authored.Spec.Protocol.Family != pack.Protocol ||
		compiled.Authored.Spec.Protocol.Snapshot != pack.SnapshotRevision || compiled.Authored.Spec.Protocol.Digest != snapshotDigest ||
		isFloatingReference(compiled.Authored.Spec.Protocol.Snapshot) {
		return errors.New("scenario protocol identity or exact snapshot lock mismatch")
	}
	if compiled.Authored.Spec.Classification.Type != packapi.ClassNormative || string(compiled.Authored.Spec.Classification.Stability) != pack.Stability {
		return errors.New("scenario classification does not match candidate pack status")
	}
	if len(compiled.IR.RequirementLinks) != 1 || compiled.IR.RequirementLinks[0].ID != requirement.ID || len(compiled.Authored.Spec.Requirements) != 1 {
		return errors.New("scenario must bind exactly one denominator requirement")
	}
	if compiled.Authored.Metadata.Labels["reference"] != requirement.ReferencePassID || compiled.Authored.Metadata.Labels["mutant"] != requirement.TargetedMutantID || compiled.Authored.Metadata.Labels["review"] != "pending-review" {
		return errors.New("scenario does not expose its exact reference-pass, mutant-kill, and review IDs")
	}
	reference, referenceExists := references[requirement.ReferencePassID]
	mutant, mutantExists := mutants[requirement.TargetedMutantID]
	if !referenceExists || !mutantExists {
		return errors.New("scenario fixture IDs are unresolved")
	}
	wantPins := map[string]struct{}{reference.Ref: {}, mutant.Ref: {}}
	if len(compiled.IR.FixturePins) != len(wantPins) {
		return errors.New("scenario must pin exactly its reference-pass and targeted mutant")
	}
	for _, pin := range compiled.IR.FixturePins {
		if _, exists := wantPins[pin.Ref]; !exists {
			return fmt.Errorf("scenario pins unexpected fixture %q", pin.Ref)
		}
	}
	normativeAssertions := 0
	for _, step := range compiled.Authored.Spec.Steps {
		if step.Assert == nil {
			continue
		}
		for _, assertion := range *step.Assert {
			if assertion.AssertionRole == packapi.RoleNormative {
				normativeAssertions++
				if assertion.Requirement != requirement.ID {
					return errors.New("normative assertion targets the wrong requirement")
				}
			}
		}
	}
	if normativeAssertions != 1 {
		return fmt.Errorf("scenario has %d normative assertions, expected one", normativeAssertions)
	}
	return nil
}

func rejectUnexpectedGeneratedFiles(root string, expected map[string][]byte) error {
	for _, pack := range packDefinitions {
		directory := filepath.Join(root, filepath.FromSlash(pack.Path), "scenarios")
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			relative := filepath.ToSlash(filepath.Join(pack.Path, "scenarios", entry.Name()))
			if entry.IsDir() {
				return fmt.Errorf("unexpected generated scenario directory %s", relative)
			}
			if _, exists := expected[relative]; !exists {
				return fmt.Errorf("unexpected generated scenario %s", relative)
			}
		}
	}
	return nil
}

func readStrictFile(root, relative string, destination any) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return fmt.Errorf("read %s: %w", relative, err)
	}
	if err := decodeStrictJSON(raw, destination); err != nil {
		return fmt.Errorf("decode %s: %w", relative, err)
	}
	return nil
}

func ensureWithinRoot(root, relative string) error {
	if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "..") {
		return errors.New("unsafe repository-relative path")
	}
	absolute, err := filepath.Abs(filepath.Join(root, relative))
	if err != nil {
		return err
	}
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if absolute != rootAbsolute && !strings.HasPrefix(absolute, rootAbsolute+string(filepath.Separator)) {
		return errors.New("path escapes repository root")
	}
	return nil
}
