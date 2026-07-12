// Package planner constructs immutable offline IntentPlans and resolves only
// branches that the IntentPlan authorized in advance.
package planner

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	IntentSchema   = "urn:agentapi-doctor:intent-plan:v1alpha1"
	ResolvedSchema = "urn:agentapi-doctor:resolved-run-plan:v1alpha1"
)

type ScenarioCandidate struct {
	ID           string
	Capabilities []string
	Driver       schema.ArtifactPin
	DependsOn    []string
}

type IntentRequest struct {
	ID                    schema.InstanceID
	CreatedAt             schema.UTCTime
	Producer              schema.Producer
	ConfigDigest          schema.Digest
	Target                schema.TargetIntent
	Selectors             []schema.ArtifactSelector
	SupportManifestDigest schema.Digest
	Probe                 schema.ProbePolicy
	Scenarios             []ScenarioCandidate
	Budget                schema.BudgetPolicy
	Evidence              schema.EvidencePolicy
	Safety                schema.SafetyPolicy
	Author                string
	ApprovalRequirements  []string
}

type intentProjection struct {
	SchemaVersion              string                     `json:"schema_version"`
	Kind                       string                     `json:"kind"`
	IntentPlanID               schema.InstanceID          `json:"intent_plan_id"`
	ConfigDigest               schema.Digest              `json:"config_digest"`
	Target                     schema.TargetIntent        `json:"target"`
	Selectors                  []schema.ArtifactSelector  `json:"selectors"`
	SupportManifestDigest      schema.Digest              `json:"support_manifest_digest"`
	CandidateDenominatorDigest schema.Digest              `json:"candidate_denominator_digest"`
	Probe                      schema.ProbePolicy         `json:"probe"`
	ConditionalBranches        []schema.ConditionalBranch `json:"conditional_branches"`
	Budget                     schema.BudgetPolicy        `json:"budget"`
	Evidence                   schema.EvidencePolicy      `json:"evidence"`
	Safety                     schema.SafetyPolicy        `json:"safety"`
	Author                     string                     `json:"author"`
	ApprovalRequirements       []string                   `json:"approval_requirements"`
	Producer                   schema.Producer            `json:"producer"`
	CreatedAt                  schema.UTCTime             `json:"created_at"`
}

func BuildIntent(request IntentRequest) (schema.IntentPlan, error) {
	if len(request.Scenarios) == 0 {
		return schema.IntentPlan{}, errors.New("at least one scenario candidate is required")
	}
	branches := make(map[string][]string)
	candidateIDs := make([]string, 0, len(request.Scenarios))
	seen := make(map[string]struct{}, len(request.Scenarios))
	for _, scenario := range request.Scenarios {
		if scenario.ID == "" {
			return schema.IntentPlan{}, errors.New("scenario ID is required")
		}
		if _, duplicate := seen[scenario.ID]; duplicate {
			return schema.IntentPlan{}, fmt.Errorf("duplicate scenario %s", scenario.ID)
		}
		seen[scenario.ID] = struct{}{}
		candidateIDs = append(candidateIDs, scenario.ID)
		for _, capability := range scenario.Capabilities {
			branches[capability] = append(branches[capability], scenario.ID)
		}
	}
	sort.Strings(candidateIDs)
	denominator, err := schema.CanonicalDigest(candidateIDs)
	if err != nil {
		return schema.IntentPlan{}, err
	}
	branchNames := make([]string, 0, len(branches))
	for capability := range branches {
		branchNames = append(branchNames, capability)
	}
	sort.Strings(branchNames)
	conditional := make([]schema.ConditionalBranch, 0, len(branchNames))
	for _, capability := range branchNames {
		scenarios := branches[capability]
		sort.Strings(scenarios)
		conditional = append(conditional, schema.ConditionalBranch{Capability: capability, Scenarios: scenarios})
	}
	projection := intentProjection{
		SchemaVersion:              IntentSchema,
		Kind:                       "IntentPlan",
		IntentPlanID:               request.ID,
		ConfigDigest:               request.ConfigDigest,
		Target:                     request.Target,
		Selectors:                  append([]schema.ArtifactSelector(nil), request.Selectors...),
		SupportManifestDigest:      request.SupportManifestDigest,
		CandidateDenominatorDigest: denominator,
		Probe:                      request.Probe,
		ConditionalBranches:        conditional,
		Budget:                     request.Budget,
		Evidence:                   request.Evidence,
		Safety:                     request.Safety,
		Author:                     request.Author,
		ApprovalRequirements:       append([]string(nil), request.ApprovalRequirements...),
		Producer:                   request.Producer,
		CreatedAt:                  request.CreatedAt,
	}
	meta, err := schema.SealMeta(IntentSchema, "IntentPlan", request.ID, request.Producer, request.CreatedAt, projection)
	if err != nil {
		return schema.IntentPlan{}, err
	}
	plan := schema.IntentPlan{
		EnvelopeMeta:               meta,
		IntentPlanID:               request.ID,
		ConfigDigest:               request.ConfigDigest,
		Target:                     request.Target,
		Selectors:                  projection.Selectors,
		SupportManifestDigest:      request.SupportManifestDigest,
		CandidateDenominatorDigest: denominator,
		Probe:                      request.Probe,
		ConditionalBranches:        conditional,
		Budget:                     request.Budget,
		Evidence:                   request.Evidence,
		Safety:                     request.Safety,
		Author:                     request.Author,
		ApprovalRequirements:       projection.ApprovalRequirements,
	}
	if err := plan.Validate(); err != nil {
		return schema.IntentPlan{}, err
	}
	return plan, nil
}

type ResolutionRequest struct {
	ID                schema.InstanceID
	CreatedAt         schema.UTCTime
	Producer          schema.Producer
	Resolver          schema.ArtifactPin
	Observations      []schema.CapabilityObservation
	SupportLockDigest schema.Digest
	Artifacts         []schema.ArtifactPin
	Target            schema.TargetResolution
	Scenarios         []ScenarioCandidate
	Runtime           schema.RuntimePolicy
	Finalizers        []schema.FinalizerPlan
}

func Resolve(intent schema.IntentPlan, request ResolutionRequest) (schema.ResolvedRunPlan, error) {
	if err := intent.Validate(); err != nil {
		return schema.ResolvedRunPlan{}, fmt.Errorf("intent plan: %w", err)
	}
	allowed := allowedBranches(intent)
	facts, refs, err := collectFacts(intent, request.Observations)
	if err != nil {
		return schema.ResolvedRunPlan{}, err
	}
	decisions := make([]schema.ScenarioDecision, 0, len(request.Scenarios))
	applicableIDs := make([]string, 0, len(request.Scenarios))
	for _, candidate := range request.Scenarios {
		disposition := schema.DispositionExecute
		reason := ""
		for _, capability := range candidate.Capabilities {
			if _, authorized := allowed[capability][candidate.ID]; !authorized {
				return schema.ResolvedRunPlan{}, fmt.Errorf("scenario %s capability branch %s was not authorized by IntentPlan", candidate.ID, capability)
			}
			switch facts[capability] {
			case schema.CapabilityUnsupported:
				disposition = schema.DispositionNotApplicable
				reason = string(schema.ReasonUnsupportedCapability)
			case schema.CapabilityUnknown, "":
				if disposition == schema.DispositionExecute {
					disposition = schema.DispositionSkip
					reason = string(schema.ReasonNotObserved)
				}
			}
		}
		if disposition != schema.DispositionNotApplicable {
			applicableIDs = append(applicableIDs, candidate.ID)
		}
		decisions = append(decisions, schema.ScenarioDecision{ScenarioID: candidate.ID, Disposition: disposition, ReasonCode: reason, Driver: candidate.Driver, DependsOn: append([]string(nil), candidate.DependsOn...)})
	}
	sort.Strings(applicableIDs)
	denominator, err := schema.CanonicalDigest(applicableIDs)
	if err != nil {
		return schema.ResolvedRunPlan{}, err
	}
	projection := struct {
		SchemaVersion             string                    `json:"schema_version"`
		Kind                      string                    `json:"kind"`
		ResolvedPlanID            schema.InstanceID         `json:"resolved_plan_id"`
		IntentPlanRef             schema.ObjectRef          `json:"intent_plan_ref"`
		Resolver                  schema.ArtifactPin        `json:"resolver"`
		CapabilityObservationRefs []schema.ObjectRef        `json:"capability_observation_refs"`
		SupportLockDigest         schema.Digest             `json:"support_lock_digest"`
		Artifacts                 []schema.ArtifactPin      `json:"artifacts"`
		Target                    schema.TargetResolution   `json:"target"`
		Scenarios                 []schema.ScenarioDecision `json:"scenarios"`
		DenominatorDigest         schema.Digest             `json:"denominator_digest"`
		Budget                    schema.BudgetPolicy       `json:"budget"`
		Runtime                   schema.RuntimePolicy      `json:"runtime"`
		Finalizers                []schema.FinalizerPlan    `json:"finalizers,omitempty"`
		Producer                  schema.Producer           `json:"producer"`
		CreatedAt                 schema.UTCTime            `json:"created_at"`
	}{ResolvedSchema, "ResolvedRunPlan", request.ID, intent.ObjectRef, request.Resolver, refs, request.SupportLockDigest, request.Artifacts, request.Target, decisions, denominator, intent.Budget, request.Runtime, request.Finalizers, request.Producer, request.CreatedAt}
	meta, err := schema.SealMeta(ResolvedSchema, "ResolvedRunPlan", request.ID, request.Producer, request.CreatedAt, projection)
	if err != nil {
		return schema.ResolvedRunPlan{}, err
	}
	plan := schema.ResolvedRunPlan{EnvelopeMeta: meta, ResolvedPlanID: request.ID, IntentPlanRef: intent.ObjectRef, Resolver: request.Resolver, CapabilityObservationRefs: refs, SupportLockDigest: request.SupportLockDigest, Artifacts: append([]schema.ArtifactPin(nil), request.Artifacts...), Target: request.Target, Scenarios: decisions, DenominatorDigest: denominator, Budget: intent.Budget, Runtime: request.Runtime, Finalizers: append([]schema.FinalizerPlan(nil), request.Finalizers...)}
	if err := plan.Validate(); err != nil {
		return schema.ResolvedRunPlan{}, err
	}
	return plan, nil
}

func allowedBranches(intent schema.IntentPlan) map[string]map[string]struct{} {
	allowed := make(map[string]map[string]struct{}, len(intent.ConditionalBranches))
	for _, branch := range intent.ConditionalBranches {
		allowed[branch.Capability] = make(map[string]struct{}, len(branch.Scenarios))
		for _, scenario := range branch.Scenarios {
			allowed[branch.Capability][scenario] = struct{}{}
		}
	}
	return allowed
}

func collectFacts(intent schema.IntentPlan, observations []schema.CapabilityObservation) (map[string]schema.CapabilityStatus, []schema.ObjectRef, error) {
	facts := make(map[string]schema.CapabilityStatus)
	refs := make([]schema.ObjectRef, 0, len(observations))
	for _, observation := range observations {
		if observation.IntentPlanRef != intent.ObjectRef {
			return nil, nil, errors.New("capability observation is bound to a different IntentPlan")
		}
		refs = append(refs, observation.ObjectRef)
		for _, fact := range observation.Facts {
			if existing, present := facts[fact.Capability]; present && existing != fact.Status {
				return nil, nil, fmt.Errorf("conflicting capability facts for %s", fact.Capability)
			}
			facts[fact.Capability] = fact.Status
		}
	}
	return facts, refs, nil
}

func DefaultTimes(now func() time.Time) (schema.InstanceID, schema.UTCTime, error) {
	if now == nil {
		now = time.Now
	}
	instant := now()
	id, err := schema.NewInstanceID(func() time.Time { return instant }, nil)
	return id, schema.NewUTCTime(instant), err
}
