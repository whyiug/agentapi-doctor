package productrun

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/planner"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type IDSource func() (schema.InstanceID, error)

// PlanRequest contains only configuration references and public target
// metadata. Build never resolves Auth.Token and performs no network I/O.
type PlanRequest struct {
	TargetName string
	Target     config.Target
	Budget     schema.BudgetPolicy
	Producer   schema.Producer
	Author     string
	Now        func() time.Time
	NewID      IDSource
}

// PlannedRun is the offline result consumed by Execute. Target contains only
// the secret reference from config, never its resolved value.
type PlannedRun struct {
	TargetName            string                 `json:"target_name"`
	Target                config.Target          `json:"target"`
	ExecutionConfigDigest schema.Digest          `json:"execution_config_digest"`
	Intent                schema.IntentPlan      `json:"intent_plan"`
	Resolved              schema.ResolvedRunPlan `json:"resolved_run_plan"`
}

// Build creates both plans without probing, dialing, resolving credentials,
// or writing files. The ResolvedRunPlan binds an exact digest of the selected
// raw scenario definitions, request templates, catalog interpretations,
// driver, oracle, resolver, and candidate profile.
func Build(request PlanRequest) (PlannedRun, error) {
	if request.TargetName == "" {
		request.TargetName = "default"
	}
	if err := request.Target.Validate(); err != nil {
		return PlannedRun{}, fmt.Errorf("target: %w", err)
	}
	if err := validateAuthConfig(request.Target); err != nil {
		return PlannedRun{}, fmt.Errorf("target authentication: %w", err)
	}
	route, err := routeTarget(request.Target)
	if err != nil {
		return PlannedRun{}, fmt.Errorf("target route: %w", err)
	}
	artifacts, err := deriveArtifacts(request.Target.Protocol, request.Target.Model, route.endpointPath)
	if err != nil {
		return PlannedRun{}, err
	}
	if request.Budget == (schema.BudgetPolicy{}) {
		request.Budget = DefaultBudget(len(artifacts.materials))
	}
	if err := request.Budget.Validate(); err != nil {
		return PlannedRun{}, fmt.Errorf("budget: %w", err)
	}
	if request.Producer == (schema.Producer{}) {
		request.Producer = artifacts.producer
	}
	if err := request.Producer.Validate(); err != nil {
		return PlannedRun{}, fmt.Errorf("producer: %w", err)
	}
	if request.Author == "" {
		request.Author = "local-user"
	}
	now := request.Now
	if now == nil {
		now = time.Now
	}
	instant := now()
	newID := request.NewID
	if newID == nil {
		newID = func() (schema.InstanceID, error) {
			return schema.NewInstanceID(func() time.Time { return instant }, nil)
		}
	}
	intentID, err := newID()
	if err != nil {
		return PlannedRun{}, fmt.Errorf("intent plan ID: %w", err)
	}
	resolvedID, err := newID()
	if err != nil {
		return PlannedRun{}, fmt.Errorf("resolved plan ID: %w", err)
	}
	if intentID == resolvedID {
		return PlannedRun{}, errors.New("intent and resolved plan IDs must be distinct")
	}
	return buildExact(request.TargetName, request.Target, request.Budget, request.Producer, request.Author, intentID, resolvedID, schema.NewUTCTime(instant))
}

// PlanJSON validates the full exact binding and returns the canonical,
// persistence-safe plan snapshot used by plan-only output and run records.
// The snapshot preserves the immutable IntentPlan and ResolvedRunPlan plus
// the public endpoint fields needed to understand the run, but deliberately
// omits secret references and free-form target metadata.
func PlanJSON(planned PlannedRun) ([]byte, error) {
	if _, _, err := validatePlanned(planned); err != nil {
		return nil, err
	}
	snapshot := newPersistedPlan(planned)
	if err := snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("validate persisted plan snapshot: %w", err)
	}
	return schema.CanonicalMarshal(snapshot)
}

// frozenPlanJSON is an in-memory serialization used only to detach execution
// from caller-owned maps and pointers before network I/O. Unlike PlanJSON it
// contains the unresolved secret reference, so callers must never persist it.
func frozenPlanJSON(planned PlannedRun) ([]byte, error) {
	if _, _, err := validatePlanned(planned); err != nil {
		return nil, err
	}
	return schema.CanonicalMarshal(planned)
}

func buildExact(targetName string, target config.Target, budget schema.BudgetPolicy, producer schema.Producer, author string, intentID, resolvedID schema.InstanceID, createdAt schema.UTCTime) (PlannedRun, error) {
	if err := target.Validate(); err != nil {
		return PlannedRun{}, err
	}
	if err := validateAuthConfig(target); err != nil {
		return PlannedRun{}, err
	}
	route, err := routeTarget(target)
	if err != nil {
		return PlannedRun{}, err
	}
	derived, err := deriveArtifacts(target.Protocol, target.Model, route.endpointPath)
	if err != nil {
		return PlannedRun{}, err
	}
	// The plan envelopes are persisted and user-visible. Bind them only to a
	// deliberately safe projection so a low-entropy credential reference or
	// private metadata value cannot be recovered by offline digest guessing.
	configDigest, err := persistedConfigDigest(targetName, persistedTarget(target))
	if err != nil {
		return PlannedRun{}, err
	}
	// Execution still needs an exact binding to every input. This digest is
	// confined to frozenPlanJSON, which is used only in memory and is never
	// written to a run record or shown by plan-only output.
	executionConfigDigest, err := schema.CanonicalDigest(struct {
		TargetName string        `json:"target_name"`
		Target     config.Target `json:"target"`
	}{targetName, target})
	if err != nil {
		return PlannedRun{}, err
	}
	candidates := make([]planner.ScenarioCandidate, 0, len(derived.materials))
	for _, material := range derived.materials {
		candidates = append(candidates, planner.ScenarioCandidate{ID: material.Descriptor.ID, Driver: derived.driver})
	}
	probeBudget := schema.HardBudget{
		MaxRequests: 1, MaxRequestBytes: 1, MaxResponseBytes: 1,
		MaxArtifactBytes: 1, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Second),
	}
	intent, err := planner.BuildIntent(planner.IntentRequest{
		ID: intentID, CreatedAt: createdAt, Producer: producer, ConfigDigest: configDigest,
		Target: schema.TargetIntent{
			LogicalRef: targetName, ProtocolFamily: target.Protocol,
			IdentityExpectation: "configured-unverified", AllowedOrigin: route.origin,
		},
		Selectors: []schema.ArtifactSelector{{
			Kind: derived.pack.Kind, Name: derived.pack.Name,
			Constraint: "=" + derived.pack.Version, Allowed: []schema.Digest{derived.pack.Digest},
		}},
		SupportManifestDigest: derived.support,
		Probe:                 schema.ProbePolicy{Operations: []string{}, Budget: probeBudget, Network: schema.NetworkOffline},
		Scenarios:             candidates, Budget: budget,
		Evidence: schema.EvidencePolicy{
			Capture: schema.CaptureMode("redacted_content"), Redaction: "builtin-required-v1", Publication: "local-only",
		},
		Safety: schema.SafetyPolicy{
			Network: schema.NetworkTargetOnly, Redirects: "none", ToolSideEffects: schema.SideEffectsNone,
			DriverPermissions: []string{"network:exact-origin"},
		},
		Author:               author,
		ApprovalRequirements: []string{"candidate-interpretations-pending-independent-review"},
	})
	if err != nil {
		return PlannedRun{}, fmt.Errorf("build IntentPlan: %w", err)
	}
	resolved, err := planner.Resolve(intent, planner.ResolutionRequest{
		ID: resolvedID, CreatedAt: createdAt, Producer: producer,
		Resolver: derived.resolver, SupportLockDigest: derived.support,
		Artifacts: []schema.ArtifactPin{derived.pack, derived.driver, derived.oracle, derived.profile},
		Target: schema.TargetResolution{
			IdentityLevel: "configured-unverified", ObservedFingerprint: configDigest,
			ConfigurationDigest: configDigest, Model: target.Model,
		},
		Scenarios: candidates,
		Runtime: schema.RuntimePolicy{
			Concurrency: 1, Retries: 0, Timeout: budget.Hard.MaxDuration,
			Capture: schema.CaptureMode("redacted_content"), Sandbox: "in-process-no-tools", Network: schema.NetworkTargetOnly,
		},
	})
	if err != nil {
		return PlannedRun{}, fmt.Errorf("build ResolvedRunPlan: %w", err)
	}
	return PlannedRun{
		TargetName: targetName, Target: cloneTarget(target),
		ExecutionConfigDigest: executionConfigDigest, Intent: intent, Resolved: resolved,
	}, nil
}

// DefaultBudget is a hard, local candidate budget derived from the number of
// selected built-in scenarios and their immutable 512 KiB response ceiling.
func DefaultBudget(scenarioCount int) schema.BudgetPolicy {
	if scenarioCount < 1 {
		scenarioCount = 1
	}
	count := int64(scenarioCount)
	return schema.BudgetPolicy{
		Hard: schema.HardBudget{
			MaxRequests: count, MaxRequestBytes: count * (64 << 10),
			MaxResponseBytes: count * (512 << 10), MaxArtifactBytes: count * (9 << 20),
			MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Minute),
		},
		Reservation: schema.TokenBudget{},
		Cleanup: schema.HardBudget{
			MaxRequests: 1, MaxRequestBytes: 1, MaxResponseBytes: 1,
			MaxArtifactBytes: 1, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Second),
		},
	}
}

func validatePlanned(input PlannedRun) (artifacts, targetRoute, error) {
	if err := input.Intent.Validate(); err != nil {
		return artifacts{}, targetRoute{}, fmt.Errorf("intent plan: %w", err)
	}
	if err := input.Resolved.Validate(); err != nil {
		return artifacts{}, targetRoute{}, fmt.Errorf("resolved plan: %w", err)
	}
	if input.Resolved.IntentPlanRef != input.Intent.ObjectRef {
		return artifacts{}, targetRoute{}, errors.New("resolved plan is bound to a different IntentPlan")
	}
	if err := input.ExecutionConfigDigest.Validate(); err != nil {
		return artifacts{}, targetRoute{}, fmt.Errorf("execution config digest: %w", err)
	}
	expected, err := buildExact(
		input.TargetName, input.Target, input.Intent.Budget, input.Intent.Producer,
		input.Intent.Author, input.Intent.IntentPlanID, input.Resolved.ResolvedPlanID,
		input.Intent.CreatedAt,
	)
	if err != nil {
		return artifacts{}, targetRoute{}, fmt.Errorf("rebuild exact plan: %w", err)
	}
	actualIntent, err := schema.CanonicalMarshal(input.Intent)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	expectedIntent, err := schema.CanonicalMarshal(expected.Intent)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	actualResolved, err := schema.CanonicalMarshal(input.Resolved)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	expectedResolved, err := schema.CanonicalMarshal(expected.Resolved)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	if input.ExecutionConfigDigest != expected.ExecutionConfigDigest || !bytes.Equal(actualIntent, expectedIntent) || !bytes.Equal(actualResolved, expectedResolved) {
		return artifacts{}, targetRoute{}, errors.New("planned run differs from the exact built-in resolution")
	}
	route, err := routeTarget(input.Target)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	derived, err := deriveArtifacts(input.Target.Protocol, input.Target.Model, route.endpointPath)
	if err != nil {
		return artifacts{}, targetRoute{}, err
	}
	return derived, route, nil
}

func cloneTarget(source config.Target) config.Target {
	result := source
	if source.Auth != nil {
		copyAuth := *source.Auth
		result.Auth = &copyAuth
	}
	if source.Metadata != nil {
		result.Metadata = make(map[string]string, len(source.Metadata))
		for key, value := range source.Metadata {
			result.Metadata[key] = value
		}
	}
	return result
}
