package schema

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
)

type PlanDisposition string

const (
	DispositionExecute       PlanDisposition = "execute"
	DispositionSkip          PlanDisposition = "skip"
	DispositionNotApplicable PlanDisposition = "not_applicable"
)

type CaptureMode string

const (
	CaptureMetadataOnly CaptureMode = "metadata_only"
	CaptureSynthetic    CaptureMode = "synthetic_content"
	CaptureStandard     CaptureMode = "standard_fixture_only"
	CaptureLocalPrivate CaptureMode = "local_private_encrypted"
)

type NetworkPolicy string

const (
	NetworkOffline    NetworkPolicy = "offline"
	NetworkTargetOnly NetworkPolicy = "target_only"
)

type SideEffectPolicy string

const (
	SideEffectsNone       SideEffectPolicy = "none"
	SideEffectsReversible SideEffectPolicy = "reversible_only"
)

// ArtifactPin identifies an exact executable or declarative artifact.  Tags
// and floating versions are discovery aids and never satisfy a run lock.
type ArtifactPin struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  Digest `json:"digest"`
}

func (pin ArtifactPin) Validate() error {
	if !kindPattern.MatchString(pin.Kind) {
		return fmt.Errorf("invalid artifact kind %q", pin.Kind)
	}
	if !namePattern.MatchString(pin.Name) {
		return fmt.Errorf("invalid artifact name %q", pin.Name)
	}
	if pin.Version == "" || pin.Version == "latest" {
		return errors.New("artifact version must be exact and cannot be latest")
	}
	if err := pin.Digest.Validate(); err != nil {
		return fmt.Errorf("artifact %s digest: %w", pin.Name, err)
	}
	return nil
}

type HardBudget struct {
	MaxRequests      int64    `json:"max_requests"`
	MaxRequestBytes  int64    `json:"max_request_bytes"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
	MaxArtifactBytes int64    `json:"max_artifact_bytes"`
	MaxProcesses     int64    `json:"max_processes"`
	MaxDuration      Duration `json:"max_duration"`
}

func (budget HardBudget) Validate() error {
	if budget.MaxRequests <= 0 || budget.MaxRequestBytes <= 0 || budget.MaxResponseBytes <= 0 || budget.MaxArtifactBytes <= 0 || budget.MaxProcesses <= 0 {
		return errors.New("all hard budget limits must be positive")
	}
	return budget.MaxDuration.Validate()
}

type TokenBudget struct {
	MaxInputTokens  int64 `json:"max_input_tokens"`
	MaxOutputTokens int64 `json:"max_output_tokens"`
}

func (budget TokenBudget) Validate() error {
	if budget.MaxInputTokens < 0 || budget.MaxOutputTokens < 0 {
		return errors.New("token budgets cannot be negative")
	}
	return nil
}

type BudgetPolicy struct {
	Hard        HardBudget  `json:"hard"`
	Reservation TokenBudget `json:"reservation"`
	Cleanup     HardBudget  `json:"cleanup"`
}

func (budget BudgetPolicy) Validate() error {
	if err := budget.Hard.Validate(); err != nil {
		return fmt.Errorf("hard budget: %w", err)
	}
	if err := budget.Reservation.Validate(); err != nil {
		return fmt.Errorf("reservation budget: %w", err)
	}
	if err := budget.Cleanup.Validate(); err != nil {
		return fmt.Errorf("cleanup budget: %w", err)
	}
	return nil
}

type TargetIntent struct {
	LogicalRef          string `json:"logical_ref"`
	ProtocolFamily      string `json:"protocol_family"`
	IdentityExpectation string `json:"identity_expectation"`
	AllowedOrigin       string `json:"allowed_origin"`
}

func (target TargetIntent) Validate() error {
	if !namePattern.MatchString(target.LogicalRef) {
		return fmt.Errorf("invalid target logical reference %q", target.LogicalRef)
	}
	if !namePattern.MatchString(target.ProtocolFamily) {
		return fmt.Errorf("invalid protocol family %q", target.ProtocolFamily)
	}
	if target.IdentityExpectation == "" {
		return errors.New("target identity expectation is required")
	}
	origin, err := url.Parse(target.AllowedOrigin)
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.Path != "" && origin.Path != "/" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		return fmt.Errorf("allowed origin %q must contain only scheme and host", target.AllowedOrigin)
	}
	if origin.Scheme != "http" && origin.Scheme != "https" {
		return errors.New("target origin scheme must be http or https")
	}
	return nil
}

type ArtifactSelector struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Constraint string   `json:"constraint"`
	Allowed    []Digest `json:"allowed_digests"`
}

type ProbePolicy struct {
	Operations []string      `json:"operations"`
	Budget     HardBudget    `json:"budget"`
	Network    NetworkPolicy `json:"network"`
}

type ConditionalBranch struct {
	Capability string   `json:"capability"`
	Scenarios  []string `json:"scenarios"`
}

type EvidencePolicy struct {
	Capture     CaptureMode `json:"capture"`
	Redaction   string      `json:"redaction"`
	Publication string      `json:"publication"`
}

type SafetyPolicy struct {
	Network           NetworkPolicy    `json:"network"`
	Redirects         string           `json:"redirects"`
	ToolSideEffects   SideEffectPolicy `json:"tool_side_effects"`
	DriverPermissions []string         `json:"driver_permissions"`
}

// IntentPlan is created offline.  It describes the maximum authorized scope;
// it never includes capability probe results.
type IntentPlan struct {
	EnvelopeMeta
	IntentPlanID               InstanceID          `json:"intent_plan_id"`
	ConfigDigest               Digest              `json:"config_digest"`
	Target                     TargetIntent        `json:"target"`
	Selectors                  []ArtifactSelector  `json:"selectors"`
	SupportManifestDigest      Digest              `json:"support_manifest_digest"`
	CandidateDenominatorDigest Digest              `json:"candidate_denominator_digest"`
	Probe                      ProbePolicy         `json:"probe"`
	ConditionalBranches        []ConditionalBranch `json:"conditional_branches"`
	Budget                     BudgetPolicy        `json:"budget"`
	Evidence                   EvidencePolicy      `json:"evidence"`
	Safety                     SafetyPolicy        `json:"safety"`
	Author                     string              `json:"author"`
	ApprovalRequirements       []string            `json:"approval_requirements"`
}

func (plan IntentPlan) Validate() error {
	if err := plan.EnvelopeMeta.Validate(); err != nil {
		return err
	}
	if plan.Kind != "IntentPlan" || plan.IntentPlanID != plan.InstanceID {
		return errors.New("IntentPlan identity does not match its envelope")
	}
	for name, digest := range map[string]Digest{
		"config":                plan.ConfigDigest,
		"support manifest":      plan.SupportManifestDigest,
		"candidate denominator": plan.CandidateDenominatorDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s digest: %w", name, err)
		}
	}
	if err := plan.Target.Validate(); err != nil {
		return err
	}
	if err := plan.Probe.Budget.Validate(); err != nil {
		return fmt.Errorf("probe budget: %w", err)
	}
	if err := plan.Budget.Validate(); err != nil {
		return err
	}
	if plan.Author == "" || len(plan.Selectors) == 0 {
		return errors.New("intent plan requires an author and at least one selector")
	}
	return validateIntentBranches(plan.ConditionalBranches)
}

func validateIntentBranches(branches []ConditionalBranch) error {
	seen := make(map[string]struct{}, len(branches))
	for _, branch := range branches {
		if !namePattern.MatchString(branch.Capability) || len(branch.Scenarios) == 0 {
			return fmt.Errorf("invalid conditional branch for %q", branch.Capability)
		}
		if _, duplicate := seen[branch.Capability]; duplicate {
			return fmt.Errorf("duplicate conditional branch %q", branch.Capability)
		}
		seen[branch.Capability] = struct{}{}
	}
	return nil
}

type CapabilityStatus string

const (
	CapabilitySupported   CapabilityStatus = "supported"
	CapabilityUnsupported CapabilityStatus = "unsupported"
	CapabilityUnknown     CapabilityStatus = "unknown"
)

type CapabilityFact struct {
	Capability string           `json:"capability"`
	Status     CapabilityStatus `json:"status"`
	Evidence   []ObjectRef      `json:"evidence"`
}

type CapabilityObservation struct {
	EnvelopeMeta
	ObservationID   InstanceID       `json:"capability_observation_id"`
	IntentPlanRef   ObjectRef        `json:"intent_plan_ref"`
	ProbePolicyHash Digest           `json:"probe_policy_digest"`
	Facts           []CapabilityFact `json:"facts"`
	ConsumedBudget  HardBudget       `json:"consumed_budget"`
}

type ScenarioDecision struct {
	ScenarioID  string          `json:"scenario_id"`
	Disposition PlanDisposition `json:"disposition"`
	ReasonCode  string          `json:"reason_code,omitempty"`
	Driver      ArtifactPin     `json:"driver"`
	DependsOn   []string        `json:"depends_on,omitempty"`
}

type TargetResolution struct {
	IdentityLevel       string `json:"identity_level"`
	ObservedFingerprint Digest `json:"observed_fingerprint"`
	Version             string `json:"version,omitempty"`
	ConfigurationDigest Digest `json:"configuration_digest,omitempty"`
	Model               string `json:"model,omitempty"`
	Region              string `json:"region,omitempty"`
}

type RuntimePolicy struct {
	Concurrency int64         `json:"concurrency"`
	Retries     int64         `json:"retries"`
	Timeout     Duration      `json:"timeout"`
	Capture     CaptureMode   `json:"capture"`
	Sandbox     string        `json:"sandbox"`
	Network     NetworkPolicy `json:"network"`
}

type FinalizerPlan struct {
	LeaseID       string     `json:"lease_id"`
	ResourceType  string     `json:"resource_type"`
	Operation     string     `json:"operation"`
	CleanupBudget HardBudget `json:"cleanup_budget"`
}

// ResolvedRunPlan is the only plan accepted by the executor.  Every artifact,
// branch, scenario, denominator, permission, and budget is exact.
type ResolvedRunPlan struct {
	EnvelopeMeta
	ResolvedPlanID            InstanceID         `json:"resolved_plan_id"`
	IntentPlanRef             ObjectRef          `json:"intent_plan_ref"`
	Resolver                  ArtifactPin        `json:"resolver"`
	CapabilityObservationRefs []ObjectRef        `json:"capability_observation_refs"`
	SupportLockDigest         Digest             `json:"support_lock_digest"`
	Artifacts                 []ArtifactPin      `json:"artifacts"`
	Target                    TargetResolution   `json:"target"`
	Scenarios                 []ScenarioDecision `json:"scenarios"`
	DenominatorDigest         Digest             `json:"denominator_digest"`
	Budget                    BudgetPolicy       `json:"budget"`
	Runtime                   RuntimePolicy      `json:"runtime"`
	Finalizers                []FinalizerPlan    `json:"finalizers,omitempty"`
}

func (plan ResolvedRunPlan) Validate() error {
	if err := plan.EnvelopeMeta.Validate(); err != nil {
		return err
	}
	if plan.Kind != "ResolvedRunPlan" || plan.ResolvedPlanID != plan.InstanceID {
		return errors.New("ResolvedRunPlan identity does not match its envelope")
	}
	if err := plan.IntentPlanRef.Validate(); err != nil {
		return fmt.Errorf("intent plan reference: %w", err)
	}
	if err := plan.Resolver.Validate(); err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	for _, digest := range []Digest{plan.SupportLockDigest, plan.DenominatorDigest, plan.Target.ObservedFingerprint} {
		if err := digest.Validate(); err != nil {
			return err
		}
	}
	if err := plan.Budget.Validate(); err != nil {
		return err
	}
	if plan.Runtime.Concurrency <= 0 || plan.Runtime.Retries < 0 {
		return errors.New("runtime concurrency must be positive and retries nonnegative")
	}
	if err := plan.Runtime.Timeout.Validate(); err != nil {
		return err
	}
	if len(plan.Scenarios) == 0 || len(plan.Artifacts) == 0 {
		return errors.New("resolved plan requires scenarios and exact artifacts")
	}
	return validateScenarioDAG(plan.Scenarios)
}

func validateScenarioDAG(decisions []ScenarioDecision) error {
	seen := make(map[string]int, len(decisions))
	for index, decision := range decisions {
		if !namePattern.MatchString(decision.ScenarioID) {
			return fmt.Errorf("invalid scenario ID %q", decision.ScenarioID)
		}
		if _, duplicate := seen[decision.ScenarioID]; duplicate {
			return fmt.Errorf("duplicate scenario ID %q", decision.ScenarioID)
		}
		seen[decision.ScenarioID] = index
		if !slices.Contains([]PlanDisposition{DispositionExecute, DispositionSkip, DispositionNotApplicable}, decision.Disposition) {
			return fmt.Errorf("invalid disposition %q", decision.Disposition)
		}
		if decision.Disposition != DispositionExecute && decision.ReasonCode == "" {
			return fmt.Errorf("scenario %s requires a reason for %s", decision.ScenarioID, decision.Disposition)
		}
		if err := decision.Driver.Validate(); err != nil {
			return fmt.Errorf("scenario %s driver: %w", decision.ScenarioID, err)
		}
	}
	for index, decision := range decisions {
		for _, dependency := range decision.DependsOn {
			dependencyIndex, exists := seen[dependency]
			if !exists {
				return fmt.Errorf("scenario %s depends on unknown scenario %s", decision.ScenarioID, dependency)
			}
			if dependencyIndex >= index {
				return fmt.Errorf("scenario %s dependency %s is not earlier in the ordered DAG", decision.ScenarioID, dependency)
			}
		}
	}
	return nil
}
