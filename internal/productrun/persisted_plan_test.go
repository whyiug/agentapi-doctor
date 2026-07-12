package productrun

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestPlanJSONIsCanonicalPersistenceSafeAndIndependentlyVerifiable(t *testing.T) {
	const (
		secretReference = "env://PRIVATE_PROVIDER_KEY"
		privateMetadata = "tenant-internal-label"
	)
	planned := mustPlan(t, config.Target{
		BaseURL: "https://example.invalid/private/v1", Protocol: "openai-chat", Model: "fixture-model",
		Auth:     &config.Auth{Type: "header", Header: "x-api-key", Token: config.SecretReference{Ref: secretReference}},
		Metadata: map[string]string{"private": privateMetadata},
	}, schema.BudgetPolicy{})
	raw, err := PlanJSON(planned)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secretReference, "PRIVATE_PROVIDER_KEY", privateMetadata} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("persistence-safe plan contains %q", forbidden)
		}
	}
	if bytes.Contains(raw, []byte(planned.ExecutionConfigDigest)) {
		t.Fatal("persistence-safe plan exposes the full execution config digest")
	}
	decoded, err := DecodePlanJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Target.BaseURL != planned.Target.BaseURL || decoded.Target.Model != planned.Target.Model || decoded.Target.Auth == nil || decoded.Target.Auth.Header != "x-api-key" || !decoded.Target.Auth.CredentialConfigured {
		t.Fatalf("safe target context = %#v", decoded.Target)
	}
	if decoded.Intent.ObjectRef != planned.Intent.ObjectRef || decoded.Resolved.ObjectRef != planned.Resolved.ObjectRef {
		t.Fatal("plan snapshot changed immutable plan references")
	}
}

func TestExecutionBindingIncludesOmittedCredentialReferenceAndMetadata(t *testing.T) {
	planned := mustPlan(t, config.Target{
		BaseURL: "https://example.invalid/v1", Protocol: "openai-chat", Model: "fixture-model",
		Auth:     &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://FIRST_KEY"}},
		Metadata: map[string]string{"tenant": "first"},
	}, schema.BudgetPolicy{})

	tampered := planned
	tampered.Target = cloneTarget(planned.Target)
	tampered.Target.Auth.Token.Ref = "env://SECOND_KEY"
	if _, _, err := validatePlanned(tampered); err == nil {
		t.Fatal("changed secret reference retained execution authorization")
	}

	tampered = planned
	tampered.Target = cloneTarget(planned.Target)
	tampered.Target.Metadata["tenant"] = "second"
	if _, _, err := validatePlanned(tampered); err == nil {
		t.Fatal("changed private metadata retained execution authorization")
	}
}

func TestDecodePlanJSONRejectsSemanticAndShapeTampering(t *testing.T) {
	planned := mustPlan(t, config.Target{
		BaseURL: "https://example.invalid/v1", Protocol: "openai-responses", Model: "fixture-model",
		Auth: &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://PRIVATE_PROVIDER_KEY"}},
	}, schema.BudgetPolicy{})
	raw, err := PlanJSON(planned)
	if err != nil {
		t.Fatal(err)
	}
	base, err := DecodePlanJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*PersistedPlan)
	}{
		{name: "intent projection", mutate: func(plan *PersistedPlan) { plan.Intent.Author = "tampered" }},
		{name: "resolved projection", mutate: func(plan *PersistedPlan) { plan.Resolved.Runtime.Retries++ }},
		{name: "target origin binding", mutate: func(plan *PersistedPlan) { plan.Target.BaseURL = "https://other.example.invalid/v1" }},
		{name: "target API prefix binding", mutate: func(plan *PersistedPlan) { plan.Target.BaseURL = "https://example.invalid/other-prefix" }},
		{name: "auth header binding", mutate: func(plan *PersistedPlan) { plan.Target.Auth.Header = "x-other-key" }},
		{name: "auth projection", mutate: func(plan *PersistedPlan) { plan.Target.Auth.CredentialConfigured = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Intent = base.Intent
			candidate.Resolved = base.Resolved
			if base.Target.Auth != nil {
				auth := *base.Target.Auth
				candidate.Target.Auth = &auth
			}
			test.mutate(&candidate)
			encoded, err := schema.CanonicalMarshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePlanJSON(encoded); err == nil {
				t.Fatal("tampered plan was accepted")
			}
		})
	}

	var unknown map[string]any
	if err := json.Unmarshal(raw, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["unexpected"] = true
	encoded, err := schema.CanonicalMarshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePlanJSON(encoded); err == nil {
		t.Fatal("unknown plan field was accepted")
	}
}
