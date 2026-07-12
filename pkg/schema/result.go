package schema

import (
	"errors"
	"fmt"
	"slices"
)

type ExecutionStatus string

const (
	ExecutionPlanned   ExecutionStatus = "planned"
	ExecutionRunning   ExecutionStatus = "running"
	ExecutionCompleted ExecutionStatus = "completed"
	ExecutionSkipped   ExecutionStatus = "skipped"
	ExecutionCancelled ExecutionStatus = "cancelled"
	ExecutionErrored   ExecutionStatus = "errored"
)

type Verdict string

const (
	VerdictPass         Verdict = "pass"
	VerdictFail         Verdict = "fail"
	VerdictWarn         Verdict = "warn"
	VerdictInconclusive Verdict = "inconclusive"
)

type ReasonCode string

const (
	ReasonUnsupportedCapability ReasonCode = "unsupported_capability"
	ReasonAuthenticationFailed  ReasonCode = "authentication_failed"
	ReasonPermissionDenied      ReasonCode = "permission_denied"
	ReasonTransientError        ReasonCode = "transient_error"
	ReasonSpecAmbiguity         ReasonCode = "spec_ambiguity"
	ReasonBudgetExhausted       ReasonCode = "budget_exhausted"
	ReasonCostLimit             ReasonCode = "cost_limit"
	ReasonUnsafeOperation       ReasonCode = "unsafe_operation"
	ReasonHarnessError          ReasonCode = "harness_error"
	ReasonDriverError           ReasonCode = "driver_error"
	ReasonCancelledByUser       ReasonCode = "cancelled_by_user"
	ReasonFlakyDetected         ReasonCode = "flaky_detected"
	ReasonInsufficientSamples   ReasonCode = "insufficient_samples"
	ReasonNotObserved           ReasonCode = "not_observed"
)

type AssertionRole string

const (
	AssertionPrecondition    AssertionRole = "precondition"
	AssertionNormative       AssertionRole = "normative"
	AssertionConsumerProfile AssertionRole = "consumer_profile"
	AssertionBehavioral      AssertionRole = "behavioral"
	AssertionAdvisory        AssertionRole = "advisory"
)

type ProfileOutcome string

const (
	ProfileCompatible   ProfileOutcome = "compatible"
	ProfileDegraded     ProfileOutcome = "degraded"
	ProfileIncompatible ProfileOutcome = "incompatible"
	ProfileInconclusive ProfileOutcome = "inconclusive"
)

type DimensionOutcome string

const (
	DimensionPass         DimensionOutcome = "pass"
	DimensionFail         DimensionOutcome = "fail"
	DimensionDegraded     DimensionOutcome = "degraded"
	DimensionInconclusive DimensionOutcome = "inconclusive"
	DimensionNotRun       DimensionOutcome = "not_run"
)

type Attempt struct {
	AttemptID             InstanceID        `json:"attempt_id"`
	InvocationID          InstanceID        `json:"invocation_id"`
	ExecutionStatus       ExecutionStatus   `json:"execution_status"`
	ReasonCode            ReasonCode        `json:"reason_code,omitempty"`
	RequestRef            *ObjectRef        `json:"request_ref,omitempty"`
	EvidenceRefs          []ObjectRef       `json:"evidence_refs,omitempty"`
	Driver                ArtifactPin       `json:"driver"`
	ClientObservationRefs []ObjectRef       `json:"client_observation_refs,omitempty"`
	ConsumedBudget        BudgetConsumption `json:"consumed_budget"`
	ResidualLeaseRefs     []ObjectRef       `json:"residual_lease_refs,omitempty"`
}

type BudgetConsumption struct {
	Requests      int64    `json:"requests"`
	RequestBytes  int64    `json:"request_bytes"`
	ResponseBytes int64    `json:"response_bytes"`
	ArtifactBytes int64    `json:"artifact_bytes"`
	InputTokens   *int64   `json:"input_tokens,omitempty"`
	OutputTokens  *int64   `json:"output_tokens,omitempty"`
	Unknown       []string `json:"unknown,omitempty"`
}

type StatisticalEstimate struct {
	SampleCount int64   `json:"sample_count"`
	Estimate    float64 `json:"estimate"`
	LowerBound  float64 `json:"lower_bound"`
	UpperBound  float64 `json:"upper_bound"`
	Method      string  `json:"method"`
}

type AssertionResult struct {
	AssertionResultID InstanceID           `json:"assertion_result_id"`
	AssertionID       string               `json:"assertion_id"`
	RequirementID     string               `json:"requirement_id,omitempty"`
	Role              AssertionRole        `json:"assertion_role"`
	Oracle            ArtifactPin          `json:"oracle"`
	Verdict           Verdict              `json:"verdict"`
	ReasonCode        ReasonCode           `json:"reason_code,omitempty"`
	Expected          any                  `json:"expected,omitempty"`
	Observed          any                  `json:"observed,omitempty"`
	EvidenceRefs      []ObjectRef          `json:"evidence_refs"`
	Deterministic     bool                 `json:"deterministic"`
	Statistical       *StatisticalEstimate `json:"statistical,omitempty"`
	EvaluatorDigest   Digest               `json:"evaluator_digest"`
}

func (result AssertionResult) Validate() error {
	if err := result.AssertionResultID.Validate(); err != nil {
		return err
	}
	if result.AssertionID == "" || !slices.Contains([]AssertionRole{AssertionPrecondition, AssertionNormative, AssertionConsumerProfile, AssertionBehavioral, AssertionAdvisory}, result.Role) {
		return errors.New("assertion ID and valid role are required")
	}
	if result.Role == AssertionNormative && result.RequirementID == "" {
		return errors.New("normative assertion requires a Requirement ID")
	}
	if !slices.Contains([]Verdict{VerdictPass, VerdictFail, VerdictWarn, VerdictInconclusive}, result.Verdict) {
		return fmt.Errorf("invalid verdict %q", result.Verdict)
	}
	if err := result.Oracle.Validate(); err != nil {
		return fmt.Errorf("oracle: %w", err)
	}
	if err := result.EvaluatorDigest.Validate(); err != nil {
		return fmt.Errorf("evaluator: %w", err)
	}
	if len(result.EvidenceRefs) == 0 {
		return errors.New("assertion result requires evidence")
	}
	if result.Deterministic && result.Statistical != nil || !result.Deterministic && result.Statistical == nil {
		return errors.New("statistical metadata must be present exactly for nondeterministic assertions")
	}
	return nil
}

type FaultFamily string

const (
	FaultTransport FaultFamily = "transport"
	FaultWire      FaultFamily = "wire"
	FaultProtocol  FaultFamily = "protocol"
	FaultModel     FaultFamily = "model"
	FaultClient    FaultFamily = "client"
	FaultHarness   FaultFamily = "harness"
	FaultUnknown   FaultFamily = "unknown"
)

type Finding struct {
	FindingID           InstanceID  `json:"finding_id"`
	AssertionResultID   InstanceID  `json:"assertion_result_id"`
	FaultDomain         string      `json:"fault_domain"`
	FaultFamily         FaultFamily `json:"fault_family"`
	Category            string      `json:"category"`
	Severity            string      `json:"severity"`
	Confidence          float64     `json:"confidence"`
	CalibrationVersion  string      `json:"calibration_version"`
	AlternativeDomains  []string    `json:"alternative_domains,omitempty"`
	MinimalEvidenceRefs []ObjectRef `json:"minimal_evidence_refs"`
	ReproRefs           []ObjectRef `json:"repro_refs,omitempty"`
	RequirementID       string      `json:"requirement_id,omitempty"`
	AmbiguityID         string      `json:"ambiguity_id,omitempty"`
	RemediationHint     string      `json:"remediation_hint"`
	UpstreamRoutingHint string      `json:"upstream_routing_hint,omitempty"`
	FingerprintVersion  string      `json:"fingerprint_version"`
	Fingerprint         Digest      `json:"fingerprint"`
}

type CaseResult struct {
	ScenarioID         string            `json:"scenario_id"`
	PlanDisposition    PlanDisposition   `json:"plan_disposition"`
	AttemptIDs         []InstanceID      `json:"attempt_ids,omitempty"`
	ExecutionStatus    ExecutionStatus   `json:"execution_status,omitempty"`
	Verdict            *Verdict          `json:"verdict,omitempty"`
	ReasonCode         ReasonCode        `json:"reason_code,omitempty"`
	EvidenceRefs       []ObjectRef       `json:"evidence_refs,omitempty"`
	AssertionResults   []AssertionResult `json:"assertion_results,omitempty"`
	Findings           []Finding         `json:"findings,omitempty"`
	CandidateMember    bool              `json:"candidate_member"`
	ApplicableMember   bool              `json:"applicable_member"`
	ExecutedMember     bool              `json:"executed_member"`
	AttemptAggregation string            `json:"attempt_aggregation"`
}

func (result CaseResult) Validate() error {
	if result.ScenarioID == "" {
		return errors.New("scenario ID is required")
	}
	if result.PlanDisposition == DispositionExecute {
		if len(result.AttemptIDs) == 0 {
			return errors.New("executed disposition requires at least one attempt")
		}
		if result.ExecutionStatus == ExecutionCompleted && result.Verdict == nil {
			return errors.New("completed case requires a verdict")
		}
		if result.ExecutionStatus != ExecutionCompleted && result.Verdict != nil {
			return errors.New("non-completed case cannot have a verdict")
		}
	} else {
		if len(result.AttemptIDs) != 0 || result.Verdict != nil || len(result.EvidenceRefs) != 0 {
			return errors.New("skip/not_applicable cannot create target attempts, verdicts, or evidence")
		}
		if result.ReasonCode == "" {
			return errors.New("skip/not_applicable requires a reason code")
		}
	}
	for index, ref := range result.EvidenceRefs {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("case evidence ref %d: %w", index, err)
		}
	}
	return nil
}

type DenominatorSummary struct {
	CandidateDigest  Digest `json:"candidate_digest"`
	CandidateCount   int64  `json:"candidate_count"`
	ApplicableDigest Digest `json:"applicable_digest"`
	ApplicableCount  int64  `json:"applicable_count"`
	ExecutedDigest   Digest `json:"executed_digest"`
	ExecutedCount    int64  `json:"executed_count"`
}

type ProfileResult struct {
	EnvelopeMeta
	ProfileResultID   InstanceID                  `json:"profile_result_id"`
	Profile           ArtifactPin                 `json:"profile"`
	SupportLockDigest Digest                      `json:"support_lock_digest"`
	Denominators      DenominatorSummary          `json:"denominators"`
	Outcome           ProfileOutcome              `json:"profile_outcome"`
	Dimensions        map[string]DimensionOutcome `json:"dimension_outcomes"`
	Cases             []CaseResult                `json:"cases"`
	HardGates         []AssertionResult           `json:"hard_gates"`
	KnownGaps         []string                    `json:"known_gaps,omitempty"`
	Waivers           []ObjectRef                 `json:"waivers,omitempty"`
	SampleMetadata    map[string]any              `json:"sample_metadata,omitempty"`
}
