// Package catalog owns the offline, content-addressed Requirement Catalog and
// ProtocolPack candidate generator. It never fetches sources or calls a model
// provider: source bytes are retrieved out of band and represented only by
// their first-party URL, locator, retrieval time, and SHA-256 lock.
package catalog

import (
	"encoding/json"

	"github.com/whyiug/agentapi-doctor/pkg/packapi"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	GeneratorName    = "agentapi-doctor-catalog-generator"
	GeneratorVersion = "1.0.0"

	SourceLockSchema  = "urn:agentapi-doctor:source-lock-set:v1"
	CatalogSchema     = "urn:agentapi-doctor:requirement-catalog:v1"
	FixtureSetSchema  = "urn:agentapi-doctor:catalog-fixture-set:v1"
	PackStatusSchema  = "urn:agentapi-doctor:pack-candidate-status:v1"
	SnapshotSchema    = "urn:agentapi-doctor:protocol-snapshot:v1"
	StatisticsSchema  = "urn:agentapi-doctor:catalog-statistics:v1"
	BoundarySetSchema = "urn:agentapi-doctor:catalog-boundary-set:v1"
	NegativeSetSchema = "urn:agentapi-doctor:catalog-negative-set:v1"

	StatusCandidate    = "candidate"
	ReviewPending      = "pending_review"
	ClaimedTierNone    = "none"
	PublicationBlocked = "blocked_pending_review"
)

type SourceLockSet struct {
	SchemaVersion string       `json:"schema_version"`
	Status        string       `json:"status"`
	ReviewStatus  string       `json:"review_status"`
	Sources       []SourceLock `json:"sources"`
}

// SourceLock deliberately contains metadata only. Restricted documentation is
// never mirrored into this repository.
type SourceLock struct {
	ID            string               `json:"id"`
	Protocol      string               `json:"protocol"`
	SourceType    string               `json:"source_type"`
	OriginalURL   string               `json:"original_url"`
	ResolvedURL   string               `json:"resolved_url"`
	RetrievedAt   publicschema.UTCTime `json:"retrieved_at"`
	Revision      string               `json:"revision"`
	ContentSHA256 publicschema.Digest  `json:"content_sha256"`
	License       string               `json:"license"`
	ReuseStatus   string               `json:"reuse_status"`
}

type RequirementCatalog struct {
	SchemaVersion   string        `json:"schema_version"`
	Generator       Generator     `json:"generator"`
	Status          string        `json:"status"`
	ReviewStatus    string        `json:"review_status"`
	DenominatorRule string        `json:"denominator_rule"`
	Requirements    []Requirement `json:"requirements"`
}

type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Requirement struct {
	ID                   string                   `json:"id"`
	Protocol             string                   `json:"protocol"`
	Pack                 string                   `json:"pack"`
	Level                packapi.RequirementLevel `json:"level"`
	Category             packapi.ScenarioClass    `json:"category"`
	Taxonomy             string                   `json:"taxonomy"`
	AssertionRole        packapi.AssertionRole    `json:"assertion_role"`
	Source               RequirementSource        `json:"source"`
	Interpretation       string                   `json:"interpretation"`
	SemanticKey          string                   `json:"semantic_key"`
	AssertionFingerprint publicschema.Digest      `json:"assertion_fingerprint"`
	ScenarioID           string                   `json:"scenario_id"`
	ReferencePassID      string                   `json:"reference_pass_id"`
	TargetedMutantID     string                   `json:"targeted_mutant_id"`
	Budget               RequirementBudget        `json:"budget"`
	Status               string                   `json:"status"`
	ReviewStatus         string                   `json:"review_status"`
}

type RequirementSource struct {
	SourceID string `json:"source_id"`
	Locator  string `json:"locator"`
}

type RequirementBudget struct {
	Timeout          publicschema.Duration `json:"timeout"`
	MaxRequests      int64                 `json:"max_requests"`
	MaxInputTokens   int64                 `json:"max_input_tokens"`
	MaxOutputTokens  int64                 `json:"max_output_tokens"`
	MaxResponseBytes int64                 `json:"max_response_bytes"`
	MaxArtifactBytes int64                 `json:"max_artifact_bytes"`
}

type FixtureSet struct {
	SchemaVersion string          `json:"schema_version"`
	Generator     Generator       `json:"generator"`
	Kind          string          `json:"kind"`
	Fixtures      []FixtureRecord `json:"fixtures"`
}

// FixtureRecord describes a candidate fixture identity and its expected
// semantics. It is metadata, not an executable fixture payload or evidence
// that the reference/mutation gates have run.
type FixtureRecord struct {
	ID                string                `json:"id"`
	Ref               string                `json:"ref"`
	Kind              string                `json:"kind"`
	Protocol          string                `json:"protocol"`
	ScenarioID        string                `json:"scenario_id"`
	RequirementID     string                `json:"requirement_id"`
	SemanticKey       string                `json:"semantic_key"`
	AssertionRole     packapi.AssertionRole `json:"assertion_role"`
	ExpectedVerdict   string                `json:"expected_verdict"`
	MutationOperator  string                `json:"mutation_operator,omitempty"`
	KillsRequirement  string                `json:"kills_requirement,omitempty"`
	SyntheticEvidence SyntheticEvidence     `json:"synthetic_evidence"`
}

type SyntheticEvidence struct {
	Transport   string `json:"transport"`
	Observation string `json:"observation"`
	DataClass   string `json:"data_class"`
}

type PackCandidateStatus struct {
	SchemaVersion        string   `json:"schema_version"`
	Pack                 string   `json:"pack"`
	Protocol             string   `json:"protocol"`
	ReleaseTrack         string   `json:"release_track"`
	Status               string   `json:"status"`
	ReviewStatus         string   `json:"review_status"`
	ClaimedTier          string   `json:"claimed_tier"`
	Publication          string   `json:"publication"`
	IndependentReview    bool     `json:"independent_review"`
	RealSDKValidation    bool     `json:"real_sdk_validation"`
	LiveProviderVerified bool     `json:"live_provider_verified"`
	KnownGaps            []string `json:"known_gaps"`
}

type ProtocolSnapshot struct {
	SchemaVersion string               `json:"schema_version"`
	Protocol      string               `json:"protocol"`
	Revision      string               `json:"revision"`
	Status        string               `json:"status"`
	ReviewStatus  string               `json:"review_status"`
	Sources       []SnapshotSourceLock `json:"sources"`
}

type SnapshotSourceLock struct {
	SourceID      string              `json:"source_id"`
	ContentSHA256 publicschema.Digest `json:"content_sha256"`
}

type CatalogStatistics struct {
	SchemaVersion                   string              `json:"schema_version"`
	Generator                       Generator           `json:"generator"`
	Status                          string              `json:"status"`
	ReviewStatus                    string              `json:"review_status"`
	ScenarioCount                   int                 `json:"scenario_count"`
	RequirementCount                int                 `json:"requirement_count"`
	NormativeDenominatorCount       int                 `json:"normative_denominator_count"`
	UniqueSemanticCount             int                 `json:"unique_semantic_count"`
	ReferenceFixtureMetadataCount   int                 `json:"reference_fixture_metadata_count"`
	TargetedMutantMetadataCount     int                 `json:"targeted_mutant_metadata_count"`
	FixtureRecordsExecutable        bool                `json:"fixture_records_executable"`
	ExecutableMutationGateSatisfied bool                `json:"executable_mutation_gate_satisfied"`
	AliasCount                      int                 `json:"alias_count"`
	DenominatorDigest               publicschema.Digest `json:"denominator_digest"`
	CatalogDigest                   publicschema.Digest `json:"catalog_digest"`
	Packs                           []PackStatistics    `json:"packs"`
	Claims                          CandidateClaims     `json:"claims"`
}

type PackStatistics struct {
	Pack               string              `json:"pack"`
	Protocol           string              `json:"protocol"`
	ReleaseTrack       string              `json:"release_track"`
	ScenarioCount      int                 `json:"scenario_count"`
	RequirementCount   int                 `json:"requirement_count"`
	SnapshotDigest     publicschema.Digest `json:"snapshot_digest"`
	CompiledPackDigest publicschema.Digest `json:"compiled_pack_digest"`
}

type CandidateClaims struct {
	Tier1                bool `json:"tier1"`
	IndependentReview    bool `json:"independent_review"`
	RealSDKValidation    bool `json:"real_sdk_validation"`
	LiveProviderVerified bool `json:"live_provider_verified"`
}

type DenominatorMember struct {
	RequirementID        string              `json:"requirement_id"`
	ScenarioID           string              `json:"scenario_id"`
	Pack                 string              `json:"pack"`
	Taxonomy             string              `json:"taxonomy"`
	SemanticKey          string              `json:"semantic_key"`
	AssertionFingerprint publicschema.Digest `json:"assertion_fingerprint"`
	ReferencePassID      string              `json:"reference_pass_id"`
	TargetedMutantID     string              `json:"targeted_mutant_id"`
}

type BoundarySet struct {
	SchemaVersion string         `json:"schema_version"`
	Generator     Generator      `json:"generator"`
	Cases         []BoundaryCase `json:"cases"`
}

type BoundaryCase struct {
	ID          string          `json:"id"`
	Boundary    string          `json:"boundary"`
	Input       json.RawMessage `json:"input"`
	Expectation string          `json:"expectation"`
}

type NegativeSet struct {
	SchemaVersion string         `json:"schema_version"`
	Generator     Generator      `json:"generator"`
	Cases         []NegativeCase `json:"cases"`
}

type NegativeCase struct {
	ID          string          `json:"id"`
	Mutation    string          `json:"mutation"`
	Input       json.RawMessage `json:"input"`
	RejectStage string          `json:"reject_stage"`
}

// Repository is the fully resolved, strictly loaded checked-in catalog.
type Repository struct {
	Sources             SourceLockSet
	Requirements        RequirementCatalog
	ReferenceFixtures   FixtureSet
	MutationFixtures    FixtureSet
	PackStatuses        map[string]PackCandidateStatus
	Snapshots           map[string]ProtocolSnapshot
	CompileRequirements map[string]packapi.RequirementRecord
	CompileFixtures     map[string]publicschema.Digest
}
