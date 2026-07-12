package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/packapi"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

var (
	lowerIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,127}$`)
	requirementIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9._-]{2,127}$`)
	semanticKeyPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{2,255}$`)
	pinnedContentPattern = regexp.MustCompile(`^content-sha256:[0-9a-f]{64}$`)
	exactDatePattern     = regexp.MustCompile(`^20[0-9]{2}-[0-9]{2}-[0-9]{2}$`)

	officialHosts = map[string]struct{}{
		"developers.openai.com":   {},
		"platform.claude.com":     {},
		"ai.google.dev":           {},
		"modelcontextprotocol.io": {},
		"docs.ollama.com":         {},
	}
)

func decodeStrictJSON(raw []byte, destination any) error {
	if len(raw) == 0 {
		return errors.New("JSON document is empty")
	}
	if _, err := publicschema.CanonicalizeJSON(raw); err != nil {
		return fmt.Errorf("strict JSON validation: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode strict JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return fmt.Errorf("read trailing JSON: %w", err)
	}
	return nil
}

func validateSourceLocks(locks SourceLockSet) error {
	if locks.SchemaVersion != SourceLockSchema || locks.Status != StatusCandidate || locks.ReviewStatus != ReviewPending {
		return errors.New("source lock set must be candidate/pending_review with the current schema")
	}
	if len(locks.Sources) == 0 {
		return errors.New("source lock set is empty")
	}
	seen := make(map[string]struct{}, len(locks.Sources))
	for index, source := range locks.Sources {
		path := fmt.Sprintf("sources[%d]", index)
		if !lowerIDPattern.MatchString(source.ID) {
			return fmt.Errorf("%s.id is invalid", path)
		}
		if _, duplicate := seen[source.ID]; duplicate {
			return fmt.Errorf("duplicate source ID %q", source.ID)
		}
		seen[source.ID] = struct{}{}
		if !semanticKeyPattern.MatchString(source.Protocol) {
			return fmt.Errorf("%s.protocol is invalid", path)
		}
		if source.SourceType != "official_documentation" {
			return fmt.Errorf("%s.source_type must be official_documentation", path)
		}
		for field, value := range map[string]string{"original_url": source.OriginalURL, "resolved_url": source.ResolvedURL} {
			parsed, err := url.Parse(value)
			if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("%s.%s must be a clean HTTPS URL", path, field)
			}
			if _, official := officialHosts[strings.ToLower(parsed.Hostname())]; !official {
				return fmt.Errorf("%s.%s host %q is not an allowed first-party host", path, field, parsed.Hostname())
			}
		}
		if source.RetrievedAt.IsZero() {
			return fmt.Errorf("%s.retrieved_at is invalid", path)
		}
		if isFloatingReference(source.Revision) || (!pinnedContentPattern.MatchString(source.Revision) && !exactDatePattern.MatchString(source.Revision)) {
			return fmt.Errorf("%s.revision %q is not an exact content or dated revision", path, source.Revision)
		}
		if err := source.ContentSHA256.Validate(); err != nil {
			return fmt.Errorf("%s.content_sha256: %w", path, err)
		}
		if strings.HasPrefix(source.Revision, "content-sha256:") && strings.TrimPrefix(source.Revision, "content-") != string(source.ContentSHA256) {
			return fmt.Errorf("%s.revision does not match content_sha256", path)
		}
		if strings.TrimSpace(source.License) == "" || source.ReuseStatus != "metadata-only-no-mirroring" {
			return fmt.Errorf("%s must record license status and metadata-only reuse", path)
		}
	}
	return nil
}

func isFloatingReference(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return true
	}
	for _, floating := range []string{"latest", "main", "master", "head", "trunk", "current"} {
		if value == floating || strings.Contains(value, "/"+floating+"/") || strings.HasSuffix(value, "/"+floating) {
			return true
		}
	}
	return false
}

func validateRequirementCatalog(catalog RequirementCatalog, sources SourceLockSet) error {
	if catalog.SchemaVersion != CatalogSchema || catalog.Generator != generatorIdentity() {
		return errors.New("requirement catalog schema or generator identity mismatch")
	}
	if catalog.Status != StatusCandidate || catalog.ReviewStatus != ReviewPending {
		return errors.New("requirement catalog must remain candidate/pending_review")
	}
	if catalog.DenominatorRule != "unique-semantic-key-and-assertion-fingerprint-v1" {
		return errors.New("unknown denominator rule")
	}
	sourceByID := make(map[string]SourceLock, len(sources.Sources))
	for _, source := range sources.Sources {
		sourceByID[source.ID] = source
	}
	ids := make(map[string]struct{}, len(catalog.Requirements))
	semanticKeys := make(map[string]string, len(catalog.Requirements))
	fingerprints := make(map[publicschema.Digest]string, len(catalog.Requirements))
	scenarios := make(map[string]struct{}, len(catalog.Requirements))
	references := make(map[string]struct{}, len(catalog.Requirements))
	mutants := make(map[string]struct{}, len(catalog.Requirements))
	for index, requirement := range catalog.Requirements {
		field := fmt.Sprintf("requirements[%d]", index)
		if !requirementIDPattern.MatchString(requirement.ID) {
			return fmt.Errorf("%s.id is invalid", field)
		}
		if _, duplicate := ids[requirement.ID]; duplicate {
			return fmt.Errorf("duplicate requirement ID %q", requirement.ID)
		}
		ids[requirement.ID] = struct{}{}
		if !semanticKeyPattern.MatchString(requirement.Protocol) || !semanticKeyPattern.MatchString(requirement.Pack) {
			return fmt.Errorf("%s protocol or pack is invalid", field)
		}
		if requirement.Level != packapi.LevelMust || requirement.Category != packapi.ClassNormative || requirement.AssertionRole != packapi.RoleNormative {
			return fmt.Errorf("%s must be a normative MUST candidate with normative assertion role", field)
		}
		if !validTaxonomy(requirement.Taxonomy) {
			return fmt.Errorf("%s.taxonomy %q is unknown", field, requirement.Taxonomy)
		}
		source, exists := sourceByID[requirement.Source.SourceID]
		if !exists {
			return fmt.Errorf("%s references unknown source %q", field, requirement.Source.SourceID)
		}
		if source.Protocol != requirement.Protocol {
			return fmt.Errorf("%s source protocol %q does not match %q", field, source.Protocol, requirement.Protocol)
		}
		if strings.TrimSpace(requirement.Source.Locator) == "" || len(requirement.Source.Locator) > 512 {
			return fmt.Errorf("%s source locator is missing or oversized", field)
		}
		if strings.TrimSpace(requirement.Interpretation) == "" || len(requirement.Interpretation) > 1024 {
			return fmt.Errorf("%s interpretation is missing or oversized", field)
		}
		if !strings.Contains(requirement.Interpretation, "Candidate interpretation") {
			return fmt.Errorf("%s interpretation must disclose candidate status", field)
		}
		if !semanticKeyPattern.MatchString(requirement.SemanticKey) {
			return fmt.Errorf("%s semantic key is invalid", field)
		}
		if previous, duplicate := semanticKeys[requirement.SemanticKey]; duplicate {
			return fmt.Errorf("duplicate/alias semantic key %q used by %s and %s", requirement.SemanticKey, previous, requirement.ID)
		}
		semanticKeys[requirement.SemanticKey] = requirement.ID
		if err := requirement.AssertionFingerprint.Validate(); err != nil {
			return fmt.Errorf("%s assertion fingerprint: %w", field, err)
		}
		if previous, duplicate := fingerprints[requirement.AssertionFingerprint]; duplicate {
			return fmt.Errorf("duplicate/renamed assertion fingerprint %s used by %s and %s", requirement.AssertionFingerprint, previous, requirement.ID)
		}
		fingerprints[requirement.AssertionFingerprint] = requirement.ID
		for name, value := range map[string]struct {
			value string
			set   map[string]struct{}
		}{
			"scenario_id":        {requirement.ScenarioID, scenarios},
			"reference_pass_id":  {requirement.ReferencePassID, references},
			"targeted_mutant_id": {requirement.TargetedMutantID, mutants},
		} {
			if !lowerIDPattern.MatchString(value.value) || isFloatingReference(value.value) {
				return fmt.Errorf("%s.%s is invalid", field, name)
			}
			if _, duplicate := value.set[value.value]; duplicate {
				return fmt.Errorf("duplicate %s %q", name, value.value)
			}
			value.set[value.value] = struct{}{}
		}
		if err := validateBudget(requirement.Budget); err != nil {
			return fmt.Errorf("%s budget: %w", field, err)
		}
		if requirement.Status != StatusCandidate || requirement.ReviewStatus != ReviewPending {
			return fmt.Errorf("%s must remain candidate/pending_review", field)
		}
	}
	if len(catalog.Requirements) < 250 {
		return fmt.Errorf("catalog has %d requirements; at least 250 are required", len(catalog.Requirements))
	}
	return nil
}

func validateBudget(budget RequirementBudget) error {
	if err := budget.Timeout.Validate(); err != nil {
		return err
	}
	if budget.MaxRequests <= 0 || budget.MaxInputTokens < 0 || budget.MaxOutputTokens < 0 || budget.MaxResponseBytes <= 0 || budget.MaxArtifactBytes <= 0 {
		return errors.New("all byte/request budgets must be positive and token budgets nonnegative")
	}
	return nil
}

func validateFixtureSet(set FixtureSet, expectedKind string, requirements RequirementCatalog) error {
	if set.SchemaVersion != FixtureSetSchema || set.Generator != generatorIdentity() || set.Kind != expectedKind {
		return fmt.Errorf("%s fixture set identity mismatch", expectedKind)
	}
	requirementByID := make(map[string]Requirement, len(requirements.Requirements))
	for _, requirement := range requirements.Requirements {
		requirementByID[requirement.ID] = requirement
	}
	ids := make(map[string]struct{}, len(set.Fixtures))
	refs := make(map[string]struct{}, len(set.Fixtures))
	for index, fixture := range set.Fixtures {
		path := fmt.Sprintf("fixtures[%d]", index)
		if !lowerIDPattern.MatchString(fixture.ID) || fixture.Kind != expectedKind {
			return fmt.Errorf("%s fixture identity is invalid", path)
		}
		if _, duplicate := ids[fixture.ID]; duplicate {
			return fmt.Errorf("duplicate fixture ID %q", fixture.ID)
		}
		ids[fixture.ID] = struct{}{}
		if err := validateLogicalFixtureRef(fixture.Ref); err != nil {
			return fmt.Errorf("%s.ref: %w", path, err)
		}
		if _, duplicate := refs[fixture.Ref]; duplicate {
			return fmt.Errorf("duplicate fixture ref %q", fixture.Ref)
		}
		refs[fixture.Ref] = struct{}{}
		requirement, exists := requirementByID[fixture.RequirementID]
		if !exists {
			return fmt.Errorf("%s references unknown requirement %q", path, fixture.RequirementID)
		}
		if fixture.Protocol != requirement.Protocol || fixture.ScenarioID != requirement.ScenarioID || fixture.SemanticKey != requirement.SemanticKey || fixture.AssertionRole != packapi.RoleNormative {
			return fmt.Errorf("%s does not bind the requirement/scenario semantic identity", path)
		}
		if fixture.SyntheticEvidence.DataClass != "synthetic-only" || strings.TrimSpace(fixture.SyntheticEvidence.Transport) == "" || strings.TrimSpace(fixture.SyntheticEvidence.Observation) == "" {
			return fmt.Errorf("%s synthetic evidence is incomplete", path)
		}
		switch expectedKind {
		case "reference_pass":
			if fixture.ID != requirement.ReferencePassID || fixture.ExpectedVerdict != "pass" || fixture.MutationOperator != "" || fixture.KillsRequirement != "" {
				return fmt.Errorf("%s is not the requirement's exact reference-pass fixture", path)
			}
		case "targeted_mutant":
			if fixture.ID != requirement.TargetedMutantID || fixture.ExpectedVerdict != "fail" || fixture.KillsRequirement != requirement.ID || strings.TrimSpace(fixture.MutationOperator) == "" {
				return fmt.Errorf("%s is not an exact targeted mutant-kill fixture", path)
			}
		default:
			return fmt.Errorf("unknown fixture kind %q", expectedKind)
		}
	}
	if len(set.Fixtures) != len(requirements.Requirements) {
		return fmt.Errorf("%s fixture count %d does not match requirement denominator %d", expectedKind, len(set.Fixtures), len(requirements.Requirements))
	}
	return nil
}

func validateLogicalFixtureRef(value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || filepath.Clean(value) != value {
		return fmt.Errorf("unsafe fixture ref %q", value)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "*?[]") {
			return fmt.Errorf("unsafe fixture ref %q", value)
		}
	}
	return nil
}

func validatePackStatus(status PackCandidateStatus, expectedPack string) error {
	if status.SchemaVersion != PackStatusSchema || status.Pack != expectedPack || status.Status != StatusCandidate || status.ReviewStatus != ReviewPending {
		return errors.New("pack status must be exact candidate/pending_review metadata")
	}
	if status.ClaimedTier != ClaimedTierNone || status.Publication != PublicationBlocked || status.IndependentReview || status.RealSDKValidation || status.LiveProviderVerified {
		return errors.New("candidate pack must not claim a tier, publication, review, SDK, or live-provider validation")
	}
	if status.ReleaseTrack != "core-candidate" && status.ReleaseTrack != "required-experimental" {
		return fmt.Errorf("unknown release track %q", status.ReleaseTrack)
	}
	if len(status.KnownGaps) == 0 {
		return errors.New("candidate pack must disclose known gaps")
	}
	return nil
}

func validateCatalogStatistics(statistics CatalogStatistics, requirementCount, referenceMetadataCount, mutantMetadataCount int) error {
	if statistics.SchemaVersion != StatisticsSchema || statistics.Generator != generatorIdentity() ||
		statistics.Status != StatusCandidate || statistics.ReviewStatus != ReviewPending {
		return errors.New("statistics must have the current candidate/pending_review identity")
	}
	if statistics.ScenarioCount != requirementCount || statistics.RequirementCount != requirementCount ||
		statistics.NormativeDenominatorCount != requirementCount || statistics.UniqueSemanticCount != requirementCount {
		return errors.New("statistics requirement denominator counts do not match the catalog")
	}
	if statistics.ReferenceFixtureMetadataCount != referenceMetadataCount || statistics.TargetedMutantMetadataCount != mutantMetadataCount {
		return errors.New("statistics fixture metadata counts do not match the metadata sets")
	}
	if statistics.FixtureRecordsExecutable || statistics.ExecutableMutationGateSatisfied {
		return errors.New("candidate fixture metadata must not satisfy executable fixture or mutation gates")
	}
	if statistics.AliasCount != 0 || statistics.Claims.Tier1 || statistics.Claims.IndependentReview ||
		statistics.Claims.RealSDKValidation || statistics.Claims.LiveProviderVerified {
		return errors.New("statistics contain a forbidden validation claim")
	}
	if err := statistics.DenominatorDigest.Validate(); err != nil {
		return fmt.Errorf("denominator digest: %w", err)
	}
	if err := statistics.CatalogDigest.Validate(); err != nil {
		return fmt.Errorf("catalog digest: %w", err)
	}
	if len(statistics.Packs) != len(packDefinitions) {
		return fmt.Errorf("statistics contain %d packs, expected %d", len(statistics.Packs), len(packDefinitions))
	}
	return nil
}

func validateSnapshot(snapshot ProtocolSnapshot, sources SourceLockSet) error {
	if snapshot.SchemaVersion != SnapshotSchema || snapshot.Status != StatusCandidate || snapshot.ReviewStatus != ReviewPending {
		return errors.New("snapshot must remain candidate/pending_review")
	}
	if !semanticKeyPattern.MatchString(snapshot.Protocol) || isFloatingReference(snapshot.Revision) {
		return errors.New("snapshot protocol or revision is invalid/floating")
	}
	if len(snapshot.Sources) == 0 {
		return errors.New("snapshot has no source locks")
	}
	sourceByID := make(map[string]SourceLock, len(sources.Sources))
	for _, source := range sources.Sources {
		sourceByID[source.ID] = source
	}
	seen := make(map[string]struct{}, len(snapshot.Sources))
	for _, lock := range snapshot.Sources {
		source, exists := sourceByID[lock.SourceID]
		if !exists || source.Protocol != snapshot.Protocol || source.ContentSHA256 != lock.ContentSHA256 {
			return fmt.Errorf("snapshot source lock %q is unknown or digest-mismatched", lock.SourceID)
		}
		if _, duplicate := seen[lock.SourceID]; duplicate {
			return fmt.Errorf("duplicate snapshot source lock %q", lock.SourceID)
		}
		seen[lock.SourceID] = struct{}{}
	}
	return nil
}

func generatorIdentity() Generator {
	return Generator{Name: GeneratorName, Version: GeneratorVersion}
}

var taxonomies = []string{
	"endpoint-discovery", "authentication-versioning", "http-json-forward-compatibility",
	"messages-roles", "nonstream-output", "streaming", "tool-function-calling",
	"structured-output", "state-multiturn", "errors-retry", "usage", "multimodal",
	"reasoning-thinking", "cancellation-resources",
}

func validTaxonomy(value string) bool { return slices.Contains(taxonomies, value) }
