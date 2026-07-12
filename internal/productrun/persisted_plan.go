package productrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const PersistedPlanSchema = "urn:agentapi-doctor:local-plan-snapshot:v1alpha1"

// PersistedPlan is the local, replay-oriented projection of a PlannedRun. It
// intentionally does not contain the credential reference or free-form target
// metadata. The public ConfigDigest binds only this safe projection; omitted
// inputs remain bound to the in-memory execution plan and are deliberately not
// exposed through a guessable digest. Target keeps the endpoint fields needed
// to understand the historical run.
type PersistedPlan struct {
	SchemaVersion string                 `json:"schema_version"`
	TargetName    string                 `json:"target_name"`
	Target        PersistedTarget        `json:"target"`
	Intent        schema.IntentPlan      `json:"intent_plan"`
	Resolved      schema.ResolvedRunPlan `json:"resolved_run_plan"`
}

type PersistedTarget struct {
	BaseURL  string         `json:"baseURL"`
	Protocol string         `json:"protocol"`
	Model    string         `json:"model"`
	Auth     *PersistedAuth `json:"auth,omitempty"`
}

type PersistedAuth struct {
	Type                 string `json:"type"`
	Header               string `json:"header,omitempty"`
	CredentialConfigured bool   `json:"credential_configured"`
}

// DecodePlanJSON accepts only the canonical, closed JSON shape emitted by
// PlanJSON and then revalidates all nested envelope and built-in bindings.
func DecodePlanJSON(raw []byte) (PersistedPlan, error) {
	var plan PersistedPlan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return PersistedPlan{}, fmt.Errorf("decode persisted plan: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PersistedPlan{}, errors.New("persisted plan must contain exactly one JSON document")
	}
	if err := plan.Validate(); err != nil {
		return PersistedPlan{}, err
	}
	canonical, err := schema.CanonicalMarshal(plan)
	if err != nil {
		return PersistedPlan{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return PersistedPlan{}, errors.New("persisted plan must be RFC8785 canonical JSON")
	}
	return plan, nil
}

func newPersistedPlan(planned PlannedRun) PersistedPlan {
	return PersistedPlan{
		SchemaVersion: PersistedPlanSchema,
		TargetName:    planned.TargetName,
		Target:        persistedTarget(planned.Target),
		Intent:        planned.Intent,
		Resolved:      planned.Resolved,
	}
}

func persistedTarget(target config.Target) PersistedTarget {
	result := PersistedTarget{BaseURL: target.BaseURL, Protocol: target.Protocol, Model: target.Model}
	if target.Auth != nil {
		result.Auth = &PersistedAuth{
			Type: target.Auth.Type, Header: target.Auth.Header, CredentialConfigured: true,
		}
	}
	return result
}

func persistedConfigDigest(targetName string, target PersistedTarget) (schema.Digest, error) {
	return schema.CanonicalDigest(struct {
		TargetName string          `json:"target_name"`
		Target     PersistedTarget `json:"target"`
	}{targetName, target})
}

// Validate verifies both envelope projection digests and stable cross-object
// target/ref bindings. It deliberately does not compare an old snapshot with
// the currently compiled built-in pack: historical runs must remain readable
// after the built-ins advance. Current-pack equality is enforced by Build and
// validatePlanned before execution.
func (plan PersistedPlan) Validate() error {
	if plan.SchemaVersion != PersistedPlanSchema {
		return fmt.Errorf("unsupported persisted plan schema %q", plan.SchemaVersion)
	}
	if plan.TargetName == "" || strings.EqualFold(plan.TargetName, "latest") {
		return errors.New("persisted plan requires a non-reserved target name")
	}
	publicTarget := config.Target{BaseURL: plan.Target.BaseURL, Protocol: plan.Target.Protocol, Model: plan.Target.Model}
	if err := publicTarget.Validate(); err != nil {
		return fmt.Errorf("persisted target: %w", err)
	}
	if plan.Target.Auth != nil {
		if !plan.Target.Auth.CredentialConfigured {
			return errors.New("persisted auth must explicitly record that a credential was configured")
		}
		authTarget := publicTarget
		authTarget.Auth = &config.Auth{
			Type: plan.Target.Auth.Type, Header: plan.Target.Auth.Header,
			Token: config.SecretReference{Ref: "env://REDACTED"},
		}
		if err := authTarget.Validate(); err != nil {
			return fmt.Errorf("persisted auth metadata: %w", err)
		}
		if err := validateAuthConfig(authTarget); err != nil {
			return fmt.Errorf("persisted auth metadata: %w", err)
		}
	}
	if err := verifyIntentEnvelope(plan.Intent); err != nil {
		return fmt.Errorf("intent plan: %w", err)
	}
	if err := verifyResolvedEnvelope(plan.Resolved); err != nil {
		return fmt.Errorf("resolved plan: %w", err)
	}
	if plan.Resolved.IntentPlanRef != plan.Intent.ObjectRef {
		return errors.New("resolved plan is bound to a different IntentPlan")
	}
	parsed, err := url.Parse(publicTarget.BaseURL)
	if err != nil {
		return err
	}
	origin := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
	if plan.Intent.Target.LogicalRef != plan.TargetName || plan.Intent.Target.ProtocolFamily != plan.Target.Protocol || plan.Intent.Target.AllowedOrigin != origin {
		return errors.New("persisted target does not match the IntentPlan target binding")
	}
	if plan.Resolved.Target.Model != plan.Target.Model {
		return errors.New("persisted target model does not match the ResolvedRunPlan")
	}
	if plan.Intent.ConfigDigest != plan.Resolved.Target.ObservedFingerprint || plan.Intent.ConfigDigest != plan.Resolved.Target.ConfigurationDigest {
		return errors.New("plan configuration digests do not match")
	}
	configDigest, err := persistedConfigDigest(plan.TargetName, plan.Target)
	if err != nil {
		return fmt.Errorf("digest persisted target projection: %w", err)
	}
	if configDigest != plan.Intent.ConfigDigest {
		return errors.New("persisted target projection does not match the plan configuration digest")
	}
	if plan.Intent.SupportManifestDigest != plan.Resolved.SupportLockDigest {
		return errors.New("resolved support lock does not match the IntentPlan support manifest")
	}
	return nil
}

func verifyIntentEnvelope(plan schema.IntentPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if len(plan.Extensions) != 0 {
		return errors.New("built-in IntentPlan does not permit unbound extensions")
	}
	projection := struct {
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
	}{
		plan.SchemaVersion, plan.Kind, plan.IntentPlanID, plan.ConfigDigest, plan.Target,
		plan.Selectors, plan.SupportManifestDigest, plan.CandidateDenominatorDigest,
		plan.Probe, plan.ConditionalBranches, plan.Budget, plan.Evidence, plan.Safety,
		plan.Author, plan.ApprovalRequirements, plan.Producer, plan.CreatedAt,
	}
	digest, err := schema.CanonicalDigest(projection)
	if err != nil {
		return err
	}
	if digest != plan.ContentDigest {
		return errors.New("IntentPlan immutable projection digest does not match its envelope")
	}
	return nil
}

func verifyResolvedEnvelope(plan schema.ResolvedRunPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if len(plan.Extensions) != 0 {
		return errors.New("built-in ResolvedRunPlan does not permit unbound extensions")
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
	}{
		plan.SchemaVersion, plan.Kind, plan.ResolvedPlanID, plan.IntentPlanRef,
		plan.Resolver, plan.CapabilityObservationRefs, plan.SupportLockDigest,
		plan.Artifacts, plan.Target, plan.Scenarios, plan.DenominatorDigest,
		plan.Budget, plan.Runtime, plan.Finalizers, plan.Producer, plan.CreatedAt,
	}
	digest, err := schema.CanonicalDigest(projection)
	if err != nil {
		return err
	}
	if digest != plan.ContentDigest {
		return errors.New("ResolvedRunPlan immutable projection digest does not match its envelope")
	}
	return nil
}
