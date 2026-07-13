package productrun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/executor"
	"github.com/whyiug/agentapi-doctor/internal/rawdriver"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

func TestBuiltinScenarioBindingsMatchCandidateRequirementCatalog(t *testing.T) {
	type requirement struct {
		ID             string `json:"id"`
		Protocol       string `json:"protocol"`
		ScenarioID     string `json:"scenario_id"`
		Interpretation string `json:"interpretation"`
		Status         string `json:"status"`
		ReviewStatus   string `json:"review_status"`
	}
	type catalog struct {
		Status       string        `json:"status"`
		ReviewStatus string        `json:"review_status"`
		Requirements []requirement `json:"requirements"`
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "specs", "requirement-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source catalog
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	if source.Status != catalogStatus || source.ReviewStatus != catalogReviewState {
		t.Fatalf("catalog state = %s/%s", source.Status, source.ReviewStatus)
	}
	byID := make(map[string]requirement, len(source.Requirements))
	for _, item := range source.Requirements {
		byID[item.ID] = item
	}
	protocols := []string{"openai-chat", "openai-responses", "anthropic-messages"}
	for _, protocol := range protocols {
		entries, err := BuiltinScenarios(protocol)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 {
			t.Fatalf("%s: want four candidate checks, got %d", protocol, len(entries))
		}
		for _, entry := range entries {
			if entry.Check == "no_unknown_event" {
				t.Fatalf("%s maps the tolerant unknown-event semantic to a rejecting check", entry.ID)
			}
			catalogEntry, exists := byID[entry.RequirementID]
			if !exists {
				t.Fatalf("%s references absent requirement %s", entry.ID, entry.RequirementID)
			}
			wantProtocol := protocol
			if protocol == "openai-responses" {
				wantProtocol = "openai-responses-http"
			}
			if catalogEntry.Protocol != wantProtocol || catalogEntry.ScenarioID != entry.ID || catalogEntry.Interpretation != entry.RequirementInterpretation {
				t.Fatalf("catalog binding drift for %s: %#v / %#v", entry.ID, catalogEntry, entry)
			}
			if catalogEntry.Status != catalogStatus || catalogEntry.ReviewStatus != catalogReviewState || entry.CatalogStatus != catalogStatus || entry.CatalogReviewStatus != catalogReviewState {
				t.Fatalf("%s lost candidate/pending-review state", entry.ID)
			}
		}
	}
}

func TestBuildIsOfflineAndResolvedDigestBindsExactScenarioMaterial(t *testing.T) {
	target := config.Target{BaseURL: "http://127.0.0.1:1/v1", Protocol: "openai-responses", Model: "offline-model"}
	planned, err := Build(PlanRequest{TargetName: "offline", Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if planned.Intent.Probe.Network != schema.NetworkOffline || len(planned.Intent.Probe.Operations) != 0 {
		t.Fatalf("plan-only authorized a probe: %#v", planned.Intent.Probe)
	}
	if planned.Resolved.Target.IdentityLevel != "configured-unverified" || planned.Resolved.Target.Version != "" {
		t.Fatalf("offline plan invented observed identity: %#v", planned.Resolved.Target)
	}
	derived, route, err := validatePlanned(planned)
	if err != nil {
		t.Fatal(err)
	}
	if route.origin != "http://127.0.0.1:1" || route.endpointPath != "/v1/responses" {
		t.Fatalf("route = %#v", route)
	}
	materialized := materializeScenarios(derived, planned.Resolved.ContentDigest, nil)
	if len(materialized) != 4 {
		t.Fatalf("materialized %d scenarios", len(materialized))
	}
	for index, scenario := range materialized {
		if scenario.PlanDigest != planned.Resolved.ContentDigest || scenario.Driver != planned.Resolved.Scenarios[index].Driver {
			t.Fatalf("scenario %s is not plan/driver bound", scenario.ID)
		}
	}
	packFound := false
	for _, artifact := range planned.Resolved.Artifacts {
		if artifact.Kind == "ProtocolPack" {
			packFound = artifact == derived.pack
		}
	}
	if !packFound {
		t.Fatal("resolved artifacts do not bind the derived scenario pack")
	}

	tampered := planned
	tampered.Target.Model = "different-model"
	if _, _, err := validatePlanned(tampered); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("tampered target was accepted: %v", err)
	}
	tampered = planned
	tampered.Resolved.Scenarios[0].Driver.Digest = schema.NewDigest([]byte("wrong-driver"))
	if _, _, err := validatePlanned(tampered); err == nil {
		t.Fatal("tampered exact driver pin was accepted")
	}
}

func TestRouteTargetSafelyHandlesRootAndCompleteAPIPrefixes(t *testing.T) {
	tests := []struct {
		base, protocol, want string
	}{
		{"http://127.0.0.1:8090", "openai-chat", "/v1/chat/completions"},
		{"http://127.0.0.1:8090/", "openai-chat", "/v1/chat/completions"},
		{"http://127.0.0.1:8090/v1", "openai-responses", "/v1/responses"},
		{"http://127.0.0.1:8090/v1/", "anthropic-messages", "/v1/messages"},
		{"https://example.test/gateway", "openai-chat", "/gateway/chat/completions"},
		{"https://example.test/gateway/v1", "openai-responses", "/gateway/v1/responses"},
		{"https://example.test/api/v3", "openai-chat", "/api/v3/chat/completions"},
	}
	for _, test := range tests {
		route, err := routeTarget(config.Target{BaseURL: test.base, Protocol: test.protocol, Model: "model"})
		if err != nil {
			t.Fatalf("%s: %v", test.base, err)
		}
		if route.endpointPath != test.want || strings.Contains(route.endpointPath, "/v1/v1/") {
			t.Fatalf("%s -> %s, want %s", test.base, route.endpointPath, test.want)
		}
	}
	for _, invalid := range []string{
		"http://127.0.0.1:8090/a/../v1", "http://127.0.0.1:8090/a//v1",
		"http://127.0.0.1:8090/v1%2fadmin", `http://127.0.0.1:8090/v1\\admin`,
	} {
		if _, err := routeTarget(config.Target{BaseURL: invalid, Protocol: "openai-chat", Model: "model"}); err == nil {
			t.Fatalf("unsafe base path accepted: %s", invalid)
		}
	}
	_, err := Build(PlanRequest{Target: config.Target{
		BaseURL: "http://127.0.0.1:8090/v1", Protocol: "anthropic-messages", Model: "model",
		Auth: &config.Auth{Type: "header", Header: "anthropic-version", Token: config.SecretReference{Ref: "env://TOKEN"}},
	}})
	if err == nil || !strings.Contains(err.Error(), "protocol-controlled") {
		t.Fatalf("conflicting auth header was accepted: %v", err)
	}
}

func TestRequestBodiesUseVersionedScenarioOutputBudgets(t *testing.T) {
	if builtinVersion != "0.1.0-candidate.3" {
		t.Fatalf("built-in artifact version = %q, want candidate.3", builtinVersion)
	}
	if got := DefaultBudget(4).Hard.MaxDuration.Duration(); got != time.Minute {
		t.Fatalf("default remote-capable run deadline = %s, want 1m", got)
	}
	tests := []struct {
		protocol, path, field string
		want                  []int64
		wantTotal             int64
	}{
		{protocol: "openai-chat", path: "/v1/chat/completions", field: "max_completion_tokens", want: []int64{512, 64, 64, 64}, wantTotal: 704},
		{protocol: "openai-responses", path: "/v1/responses", field: "max_output_tokens", want: []int64{64, 64, 64, 512}, wantTotal: 704},
		{protocol: "anthropic-messages", path: "/v1/messages", field: "max_tokens", want: []int64{64, 64, 64, 64}, wantTotal: 256},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			derived, err := deriveArtifacts(test.protocol, "fixture-model", test.path)
			if err != nil {
				t.Fatal(err)
			}
			if len(derived.materials) != len(test.want) {
				t.Fatalf("material count = %d, want %d", len(derived.materials), len(test.want))
			}
			for index, material := range derived.materials {
				var decoded map[string]any
				if err := json.Unmarshal(material.Body, &decoded); err != nil {
					t.Fatal(err)
				}
				got, ok := decoded[test.field].(float64)
				if !ok || int64(got) != test.want[index] || material.Descriptor.RequestedOutputTokens != test.want[index] {
					t.Fatalf("%s budget = body:%#v descriptor:%d, want %d", material.Descriptor.ID, decoded[test.field], material.Descriptor.RequestedOutputTokens, test.want[index])
				}
				if _, injected := decoded["thinking"]; injected {
					t.Fatalf("%s injected a provider-specific thinking override", material.Descriptor.ID)
				}
			}
			budget := defaultBudgetFor(derived.materials)
			if budget.Reservation.MaxInputTokens != 0 || budget.Reservation.MaxOutputTokens != test.wantTotal {
				t.Fatalf("default token reservation = %#v, want output %d", budget.Reservation, test.wantTotal)
			}
			for _, artifact := range []schema.ArtifactPin{derived.driver, derived.oracle, derived.resolver, derived.pack, derived.profile} {
				if artifact.Version != builtinVersion {
					t.Fatalf("%s version = %q, want %q", artifact.Name, artifact.Version, builtinVersion)
				}
			}
			planned := mustPlan(t, config.Target{
				BaseURL: "http://127.0.0.1:1/v1", Protocol: test.protocol, Model: "fixture-model",
			}, schema.BudgetPolicy{})
			wantReservation := schema.TokenBudget{MaxOutputTokens: test.wantTotal}
			if planned.Intent.Budget.Reservation != wantReservation || planned.Resolved.Budget.Reservation != wantReservation {
				t.Fatalf("built plan reservations = intent:%#v resolved:%#v, want %#v", planned.Intent.Budget.Reservation, planned.Resolved.Budget.Reservation, wantReservation)
			}
		})
	}
	explicit := DefaultBudget(4)
	explicit.Reservation.MaxOutputTokens = 17
	planned := mustPlan(t, config.Target{BaseURL: "http://127.0.0.1:1/v1", Protocol: "openai-chat", Model: "fixture-model"}, explicit)
	if planned.Intent.Budget.Reservation.MaxOutputTokens != 17 || planned.Resolved.Budget.Reservation.MaxOutputTokens != 17 {
		t.Fatalf("explicit reservation was replaced: %#v / %#v", planned.Intent.Budget.Reservation, planned.Resolved.Budget.Reservation)
	}
	if _, err := requestBody("openai-chat", "fixture-model", false, 0); err == nil {
		t.Fatal("request body accepted a nonpositive output budget")
	}
}

func TestTerminalStatusEstimateUsesRequestedOutputCap(t *testing.T) {
	tests := []struct {
		protocol, path, scenarioID string
	}{
		{"openai-chat", "/v1/chat/completions", "openai-chat-002-terminal-status"},
		{"openai-responses", "/v1/responses", "openai-responses-http-039-terminal-status"},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			derived, err := deriveArtifacts(test.protocol, "fixture-model", test.path)
			if err != nil {
				t.Fatal(err)
			}
			scenarios := materializeScenarios(derived, schema.NewDigest([]byte("terminal-estimate-plan")), nil)
			registry, err := rawdriver.NewMemoryRegistry(scenarios...)
			if err != nil {
				t.Fatal(err)
			}
			index := slices.IndexFunc(scenarios, func(scenario rawdriver.Scenario) bool { return scenario.ID == test.scenarioID })
			if index < 0 {
				t.Fatalf("terminal scenario %q missing", test.scenarioID)
			}
			scenario := scenarios[index]
			estimate, err := registry.Estimate(schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver})
			if err != nil {
				t.Fatal(err)
			}
			if estimate.OutputTokens != terminalTokenCap {
				t.Fatalf("terminal estimate = %d, want %d", estimate.OutputTokens, terminalTokenCap)
			}
		})
	}
}

func TestRequestedOutputBudgetBindsPackProfileAndBaselineIdentity(t *testing.T) {
	before, err := deriveArtifacts("openai-chat", "fixture-model", "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	original := slices.Clone(descriptors["openai-chat"])
	mutated := slices.Clone(original)
	index := slices.IndexFunc(mutated, func(descriptor ScenarioDescriptor) bool {
		return descriptor.ID == "openai-chat-002-terminal-status"
	})
	if index < 0 {
		t.Fatal("terminal descriptor missing")
	}
	mutated[index].RequestedOutputTokens++
	descriptors["openai-chat"] = mutated
	defer func() { descriptors["openai-chat"] = original }()
	after, err := deriveArtifacts("openai-chat", "fixture-model", "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if before.pack.Digest == after.pack.Digest || before.profile.Digest == after.profile.Digest {
		t.Fatalf("requested token mutation did not propagate: pack %s/%s profile %s/%s", before.pack.Digest, after.pack.Digest, before.profile.Digest, after.profile.Digest)
	}
	if before.driver.Digest != after.driver.Digest || before.oracle.Digest != after.oracle.Digest || before.evaluator != after.evaluator || before.support != after.support {
		t.Fatal("requested token mutation changed an unrelated identity")
	}
	baseline := report.Baseline{
		SchemaVersion: report.BaselineSchemaVersion,
		Name:          "current", ProfileDigest: before.profile.Digest, PackDigest: before.pack.Digest,
		SupportLockDigest: before.support, DenominatorDigest: schema.NewDigest([]byte("denominator")),
		Cases: map[string]report.CaseState{},
	}
	for name, mutate := range map[string]func(*report.Baseline){
		"pack":    func(value *report.Baseline) { value.PackDigest = after.pack.Digest },
		"profile": func(value *report.Baseline) { value.ProfileDigest = after.profile.Digest },
	} {
		t.Run(name, func(t *testing.T) {
			current := baseline
			mutate(&current)
			if _, err := report.Compare(baseline, current); !errors.Is(err, report.ErrIncomparable) {
				t.Fatalf("changed %s identity remained comparable: %v", name, err)
			}
		})
	}
}

func TestExecuteReferencePassesAllThreeProtocolsAndPersistsValidBundle(t *testing.T) {
	protocols := []string{"openai-chat", "openai-responses", "anthropic-messages"}
	for index, protocol := range protocols {
		protocol := protocol
		t.Run(protocol, func(t *testing.T) {
			reference, err := referenceserver.New(referenceserver.Config{})
			if err != nil {
				t.Fatal(err)
			}
			paths := &pathRecorder{next: reference}
			server := httptest.NewServer(paths)
			defer server.Close()
			baseURL := server.URL
			if index%2 == 1 {
				baseURL += "/v1"
			}
			planned := mustPlan(t, config.Target{BaseURL: baseURL, Protocol: protocol, Model: "fixture-model"}, schema.BudgetPolicy{})
			dataRoot := filepath.Join(t.TempDir(), "data")
			execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: dataRoot})
			if err != nil {
				t.Fatal(err)
			}
			if execution.Report.Outcome != schema.ProfileCompatible || execution.Report.PrimaryExitCode != 0 || execution.Report.Dimensions["protocol"] != schema.DimensionPass {
				t.Fatalf("report = %#v", execution.Report)
			}
			if len(execution.Report.Cases) != 4 || execution.Report.Denominators.ExecutedCount != 4 {
				t.Fatalf("cases/denominator = %d/%#v", len(execution.Report.Cases), execution.Report.Denominators)
			}
			for _, item := range execution.Report.Cases {
				if item.Verdict == nil || *item.Verdict != schema.VerdictPass || item.ExecutionStatus != schema.ExecutionCompleted || len(item.AssertionResults) != 1 {
					t.Fatalf("case = %#v", item)
				}
			}
			wantPath := map[string]string{"openai-chat": "/v1/chat/completions", "openai-responses": "/v1/responses", "anthropic-messages": "/v1/messages"}[protocol]
			if got := paths.snapshot(); len(got) != 4 {
				t.Fatalf("request paths = %#v", got)
			} else {
				for _, path := range got {
					if path != wantPath {
						t.Fatalf("request path = %q, want %q", path, wantPath)
					}
				}
			}
			store, err := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
			if err != nil {
				t.Fatal(err)
			}
			record, err := store.Get(string(execution.ExecutorResult.RunID), false)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := report.Decode(record.Bundle)
			if err != nil || decoded.RunID != execution.ExecutorResult.RunID || record.BundleDigest != schema.NewDigest(execution.ReportJSON) {
				t.Fatalf("persisted report = %#v, %v", decoded, err)
			}
			wantPlan, err := PlanJSON(planned)
			if err != nil {
				t.Fatal(err)
			}
			var persistedPlan PersistedPlan
			if err := json.Unmarshal(record.Plan, &persistedPlan); err != nil {
				t.Fatal(err)
			}
			if err := persistedPlan.Validate(); err != nil {
				t.Fatalf("persisted plan cannot be independently revalidated: %v", err)
			}
			if !bytes.Equal(record.Plan, wantPlan) || record.PlanDigest != schema.NewDigest(wantPlan) {
				t.Fatalf("persisted plan bytes/digest differ from executed plan")
			}
			if decoded.IntentPlanRef != persistedPlan.Intent.ObjectRef || decoded.ResolvedPlanRef != persistedPlan.Resolved.ObjectRef {
				t.Fatalf("report refs cannot be dereferenced from persisted plan: report=%#v plan=%#v", decoded, persistedPlan)
			}
			if persistedPlan.Target.BaseURL != baseURL {
				t.Fatalf("persisted plan base URL = %q, want %q", persistedPlan.Target.BaseURL, baseURL)
			}
		})
	}
}

func TestExecuteClassifiesRequestedOutputLimitTerminationAsInconclusive(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(&limitedChatHandler{next: reference})
	defer server.Close()
	planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"}, schema.BudgetPolicy{})
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Report.Outcome != schema.ProfileInconclusive || execution.Report.PrimaryExitCode != 4 || execution.Report.Dimensions["protocol"] != schema.DimensionInconclusive {
		t.Fatalf("output-limit profile classification = %#v", execution.Report)
	}
	for _, item := range execution.Report.Cases {
		if len(item.Findings) != 0 {
			t.Fatalf("output-limit case gained target finding: %#v", item)
		}
		if item.ScenarioID == "openai-chat-002-terminal-status" {
			if item.Verdict == nil || *item.Verdict != schema.VerdictInconclusive || item.ReasonCode != schema.ReasonInsufficientSamples {
				t.Fatalf("terminal-status prerequisite = %#v", item)
			}
			continue
		}
		if item.Verdict == nil || *item.Verdict != schema.VerdictPass {
			t.Fatalf("unrelated assertion was not independently evaluated: %#v", item)
		}
	}
}

func TestExecutePersistsPlanFrozenBeforeNetwork(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		planned PlannedRun
		once    sync.Once
	)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		once.Do(func() { planned.Target.Metadata["state"] = "mutated-after-freeze" })
		reference.ServeHTTP(writer, request)
	}))
	defer server.Close()
	planned = mustPlan(t, config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
		Metadata: map[string]string{"state": "frozen-before-network"},
	}, schema.BudgetPolicy{})
	wantPlan, err := PlanJSON(planned)
	if err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(t.TempDir(), "data")
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: dataRoot})
	if err != nil {
		t.Fatal(err)
	}
	if planned.Target.Metadata["state"] != "mutated-after-freeze" {
		t.Fatal("fixture did not mutate the caller-owned plan after execution began")
	}
	store, err := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(string(execution.Report.RunID), false)
	if err != nil {
		t.Fatal(err)
	}
	var persisted PersistedPlan
	if err := json.Unmarshal(record.Plan, &persisted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Plan, wantPlan) {
		t.Fatal("persisted plan was not the pre-network snapshot")
	}
	if err := persisted.Validate(); err != nil {
		t.Fatalf("frozen persisted plan is not independently valid: %v", err)
	}
	if bytes.Contains(record.Plan, []byte("frozen-before-network")) || bytes.Contains(record.Plan, []byte("mutated-after-freeze")) {
		t.Fatal("free-form target metadata reached plan persistence")
	}
}

func TestEveryBuiltinAssertionPassesReferenceAndFailsTargetedMutation(t *testing.T) {
	for _, protocol := range []string{"openai-chat", "openai-responses", "anthropic-messages"} {
		entries, err := BuiltinScenarios(protocol)
		if err != nil {
			t.Fatal(err)
		}
		for _, descriptor := range entries {
			descriptor := descriptor
			t.Run(descriptor.ID, func(t *testing.T) {
				reference, err := referenceserver.New(referenceserver.Config{})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(&responseMutator{next: reference, protocol: protocol, check: descriptor.Check})
				defer server.Close()
				planned := mustPlan(t, config.Target{BaseURL: server.URL + "/v1", Protocol: protocol, Model: "fixture-model"}, schema.BudgetPolicy{})
				execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
				if err != nil {
					t.Fatal(err)
				}
				item, ok := findCase(execution.Report.Cases, descriptor.ID)
				if !ok || item.Verdict == nil || *item.Verdict != schema.VerdictFail || len(item.Findings) != 1 {
					t.Fatalf("targeted mutant did not kill %s: %#v", descriptor.ID, item)
				}
				if item.Findings[0].RequirementID != descriptor.RequirementID || item.AssertionResults[0].RequirementID != descriptor.RequirementID {
					t.Fatalf("failure attributed to wrong requirement: %#v", item)
				}
			})
		}
	}
}

func TestExecuteEnforcesHardRequestBudgetBeforeNetwork(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	paths := &pathRecorder{next: reference}
	server := httptest.NewServer(paths)
	defer server.Close()
	limited := DefaultBudget(4)
	limited.Hard.MaxRequests = 1
	planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"}, limited)
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(paths.snapshot()); got != 1 || execution.ExecutorResult.Budget.Consumed.Requests != 1 {
		t.Fatalf("network/ledger requests = %d/%d", got, execution.ExecutorResult.Budget.Consumed.Requests)
	}
	if execution.Report.Outcome != schema.ProfileInconclusive || execution.Report.PrimaryExitCode != 4 || execution.Report.Denominators.ExecutedCount != 1 {
		t.Fatalf("budget report = %#v", execution.Report)
	}
	for index, item := range execution.Report.Cases {
		if index == 0 {
			if item.Verdict == nil || *item.Verdict != schema.VerdictPass {
				t.Fatalf("first case = %#v", item)
			}
			continue
		}
		if item.ExecutionStatus != schema.ExecutionSkipped || item.ReasonCode != schema.ReasonBudgetExhausted || item.Verdict != nil {
			t.Fatalf("case after hard budget = %#v", item)
		}
	}
}

func TestExecuteEnforcesOutputTokenReservationBeforeNetwork(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	paths := &pathRecorder{next: reference}
	server := httptest.NewServer(paths)
	defer server.Close()
	limited := DefaultBudget(4)
	limited.Reservation.MaxOutputTokens = structuralTokenCap - 1
	planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"}, limited)
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(paths.snapshot()); got != 0 || execution.ExecutorResult.Budget.Consumed.Requests != 0 {
		t.Fatalf("token reservation allowed network/ledger requests = %d/%d", got, execution.ExecutorResult.Budget.Consumed.Requests)
	}
	for _, item := range execution.Report.Cases {
		if item.ExecutionStatus != schema.ExecutionSkipped || item.ReasonCode != schema.ReasonBudgetExhausted || item.Verdict != nil {
			t.Fatalf("case exceeded token reservation: %#v", item)
		}
	}
}

func TestExecuteCancellationPersistsPartialReportWithoutDialing(t *testing.T) {
	planned := mustPlan(t, config.Target{
		BaseURL: "http://127.0.0.1:1/v1", Protocol: "openai-responses", Model: "fixture-model",
	}, schema.BudgetPolicy{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dataRoot := filepath.Join(t.TempDir(), "data")
	execution, err := Execute(ctx, ExecuteRequest{Planned: planned, DataRoot: dataRoot})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if execution.Report.PrimaryExitCode != 130 || execution.Report.Outcome != schema.ProfileInconclusive || execution.RecordDigest.Validate() != nil {
		t.Fatalf("partial cancellation report = %#v", execution)
	}
	store, openErr := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if _, getErr := store.Get(string(execution.ExecutorResult.RunID), false); getErr != nil {
		t.Fatalf("partial report was not persisted: %v", getErr)
	}
}

func TestExecuteCancellationDuringFinalScenarioIsInterruptedWithoutHarnessCondition(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	releaseFinalHandler := make(chan struct{})
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestMu.Lock()
		requestCount++
		current := requestCount
		requestMu.Unlock()
		if current == 4 {
			cancel()
			<-releaseFinalHandler
			return
		}
		reference.ServeHTTP(writer, request)
	}))
	defer func() {
		close(releaseFinalHandler)
		server.Close()
	}()

	planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"}, schema.BudgetPolicy{})
	execution, err := Execute(ctx, ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if execution.Report.PrimaryExitCode != 130 || execution.Report.Outcome != schema.ProfileInconclusive {
		t.Fatalf("final-scenario cancellation report = %#v", execution.Report)
	}
	if len(execution.Report.Cases) != 4 {
		t.Fatalf("cases = %#v", execution.Report.Cases)
	}
	last := execution.Report.Cases[3]
	if last.ExecutionStatus != schema.ExecutionCancelled || last.ReasonCode != schema.ReasonCancelledByUser || last.Verdict != nil {
		t.Fatalf("last case = %#v", last)
	}
	sawCancelled := false
	for _, condition := range execution.Report.Conditions {
		if condition.Code == "run_cancelled" {
			sawCancelled = true
		}
		if condition.Code == "harness_error" {
			t.Fatalf("caller cancellation was reported as a harness fault: %#v", execution.Report.Conditions)
		}
	}
	if !sawCancelled {
		t.Fatalf("cancellation report omitted its lifecycle condition: %#v", execution.Report.Conditions)
	}
}

func TestExecuteDeadlinePersistsInconclusivePartialReport(t *testing.T) {
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-releaseHandler:
		}
	}))
	defer func() {
		close(releaseHandler)
		server.Close()
	}()
	budget := DefaultBudget(4)
	budget.Hard.MaxDuration = schema.NewDuration(50 * time.Millisecond)
	planned := mustPlan(t, config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
	}, budget)
	dataRoot := filepath.Join(t.TempDir(), "data")
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: dataRoot})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
	if execution.Report.PrimaryExitCode != 4 || execution.Report.Outcome != schema.ProfileInconclusive || execution.RecordDigest.Validate() != nil {
		t.Fatalf("partial deadline report = %#v", execution.Report)
	}
	found := false
	for _, condition := range execution.Report.Conditions {
		if condition.Code == "run_deadline_exceeded" {
			found = true
		}
		if condition.Code == "harness_error" {
			t.Fatalf("run deadline was reported as a harness fault: %#v", execution.Report.Conditions)
		}
	}
	if !found {
		t.Fatalf("deadline report omitted its condition: %#v", execution.Report.Conditions)
	}
	store, openErr := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if _, getErr := store.Get(string(execution.Report.RunID), false); getErr != nil {
		t.Fatalf("partial deadline report was not persisted: %v", getErr)
	}
}

func TestAggregateUsesDocumentedExitPrecedence(t *testing.T) {
	completed := func(id string, verdict schema.Verdict) schema.CaseResult {
		return schema.CaseResult{ScenarioID: id, PlanDisposition: schema.DispositionExecute, ExecutionStatus: schema.ExecutionCompleted, Verdict: verdictPointer(verdict)}
	}
	cancelled := func(id string) schema.CaseResult {
		return schema.CaseResult{ScenarioID: id, PlanDisposition: schema.DispositionExecute, ExecutionStatus: schema.ExecutionCancelled}
	}
	errored := func(id string) schema.CaseResult {
		return schema.CaseResult{ScenarioID: id, PlanDisposition: schema.DispositionExecute, ExecutionStatus: schema.ExecutionErrored}
	}
	tests := []struct {
		name            string
		cases           []schema.CaseResult
		classes         map[string]executor.ErrorClass
		executionErr    error
		budgetExhausted bool
		wantOutcome     schema.ProfileOutcome
		wantDimension   schema.DimensionOutcome
		wantExit        int
	}{
		{
			name:    "caller cancellation outranks permission infrastructure and failure",
			cases:   []schema.CaseResult{errored("auth"), cancelled("cancelled"), completed("failure", schema.VerdictFail)},
			classes: map[string]executor.ErrorClass{"auth": executor.ErrorAuthentication}, executionErr: context.Canceled,
			wantOutcome: schema.ProfileInconclusive, wantDimension: schema.DimensionInconclusive, wantExit: 130,
		},
		{
			name:    "permission outranks deadline cancellation",
			cases:   []schema.CaseResult{errored("auth"), cancelled("deadline")},
			classes: map[string]executor.ErrorClass{"auth": executor.ErrorAuthentication}, executionErr: context.DeadlineExceeded,
			wantOutcome: schema.ProfileInconclusive, wantDimension: schema.DimensionInconclusive, wantExit: 5,
		},
		{
			name:  "infrastructure outranks deadline cancellation",
			cases: []schema.CaseResult{errored("driver"), cancelled("deadline")}, executionErr: context.DeadlineExceeded,
			wantOutcome: schema.ProfileInconclusive, wantDimension: schema.DimensionInconclusive, wantExit: 3,
		},
		{
			name:  "deadline cancellation outranks target failure",
			cases: []schema.CaseResult{completed("failure", schema.VerdictFail), cancelled("deadline")}, executionErr: context.DeadlineExceeded,
			wantOutcome: schema.ProfileInconclusive, wantDimension: schema.DimensionInconclusive, wantExit: 4,
		},
		{
			name:        "target failure outranks warning",
			cases:       []schema.CaseResult{completed("warning", schema.VerdictWarn), completed("failure", schema.VerdictFail)},
			wantOutcome: schema.ProfileIncompatible, wantDimension: schema.DimensionFail, wantExit: 1,
		},
		{
			name:        "warning remains successful degraded outcome",
			cases:       []schema.CaseResult{completed("warning", schema.VerdictWarn)},
			wantOutcome: schema.ProfileDegraded, wantDimension: schema.DimensionDegraded, wantExit: 0,
		},
		{
			name: "exhausted snapshot makes completed pass incomplete", cases: []schema.CaseResult{completed("pass", schema.VerdictPass)}, budgetExhausted: true,
			wantOutcome: schema.ProfileInconclusive, wantDimension: schema.DimensionInconclusive, wantExit: 4,
		},
		{
			name:        "all pass",
			cases:       []schema.CaseResult{completed("pass", schema.VerdictPass)},
			wantOutcome: schema.ProfileCompatible, wantDimension: schema.DimensionPass, wantExit: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome, dimension, exitCode := aggregate(test.cases, test.classes, test.executionErr, test.budgetExhausted)
			if outcome != test.wantOutcome || dimension != test.wantDimension || exitCode != test.wantExit {
				t.Fatalf("aggregate = %s/%s/%d, want %s/%s/%d", outcome, dimension, exitCode, test.wantOutcome, test.wantDimension, test.wantExit)
			}
		})
	}
}

func TestExecuteKeepsSecretInMemoryAndRedactsBeforeAllPersistence(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(reference)
	defer server.Close()
	target := config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-chat", Model: "fixture-model",
		Auth: &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://SYNTHETIC_TOKEN"}},
	}
	planned := mustPlan(t, target, schema.BudgetPolicy{})
	plannedJSON, err := PlanJSON(planned)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte(referenceserver.SyntheticBearerToken)
	if bytes.Contains(plannedJSON, credential) {
		t.Fatal("plan-only result contains a resolved credential")
	}
	if bytes.Contains(plannedJSON, []byte(target.Auth.Token.Ref)) {
		t.Fatal("plan-only result contains a secret reference")
	}
	resolver := &staticSecretResolver{value: credential}
	dataRoot := filepath.Join(t.TempDir(), "data")
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: dataRoot, Secrets: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Report.Outcome != schema.ProfileCompatible || resolver.calls != 1 {
		t.Fatalf("secret execution = %#v, calls=%d", execution.Report, resolver.calls)
	}
	var persisted bytes.Buffer
	err = filepath.WalkDir(dataRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		raw, readErr := os.ReadFile(path)
		if readErr == nil {
			persisted.Write(raw)
		}
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted.Bytes(), credential) || bytes.Contains(persisted.Bytes(), []byte("Bearer "+string(credential))) {
		t.Fatal("credential canary reached evidence or run persistence")
	}
	if !bytes.Contains(persisted.Bytes(), []byte("[REDACTED]")) {
		t.Fatal("no redaction marker was persisted for the authenticated request")
	}
	store, err := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(string(execution.Report.RunID), false)
	if err != nil {
		t.Fatal(err)
	}
	var persistedPlan PersistedPlan
	if err := json.Unmarshal(record.Plan, &persistedPlan); err != nil {
		t.Fatal(err)
	}
	if persistedPlan.Target.BaseURL != target.BaseURL || persistedPlan.Target.Auth == nil || !persistedPlan.Target.Auth.CredentialConfigured {
		t.Fatalf("persisted plan did not preserve safe target context: %#v", persistedPlan.Target)
	}
	if bytes.Contains(record.Plan, credential) || bytes.Contains(record.Plan, []byte(target.Auth.Token.Ref)) {
		t.Fatal("persisted plan contains a credential or secret reference")
	}
}

func TestExecuteOmitsSensitiveMetadataFromPersistence(t *testing.T) {
	credential := []byte("synthetic-plan-canary-secret")
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	requests := &pathRecorder{next: reference}
	server := httptest.NewServer(requests)
	defer server.Close()
	secretRef := "env://SENSITIVE_REF_MARKER"
	target := config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
		Auth:     &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: secretRef}},
		Metadata: map[string]string{"must_not_persist": string(credential)},
	}
	dataRoot := filepath.Join(t.TempDir(), "data")
	execution, err := Execute(context.Background(), ExecuteRequest{
		Planned: mustPlan(t, target, schema.BudgetPolicy{}), DataRoot: dataRoot,
		Secrets: &staticSecretResolver{value: credential},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen := requests.snapshot(); len(seen) != 4 {
		t.Fatalf("requests = %v", seen)
	}
	store, err := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(string(execution.Report.RunID), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{credential, []byte(secretRef), []byte("must_not_persist")} {
		if bytes.Contains(record.Plan, forbidden) {
			t.Fatalf("sensitive value %q reached persisted plan", forbidden)
		}
	}
}

func TestExecuteRedactsReflectedCredentialBeforeAssertionAndFingerprint(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	credentials := []string{"reflected-secret-alpha-123", "reflected-secret-bravo-456"}
	fingerprints := make([]schema.Digest, 0, len(credentials))
	for _, credential := range credentials {
		credential := credential
		t.Run(credential, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				reflected := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
				upstreamRequest := request.Clone(request.Context())
				upstreamRequest.Header = request.Header.Clone()
				upstreamRequest.Header.Set("Authorization", "Bearer "+referenceserver.SyntheticBearerToken)
				recorded := httptest.NewRecorder()
				reference.ServeHTTP(recorded, upstreamRequest)
				if recorded.Code == http.StatusOK && strings.HasPrefix(recorded.Header().Get("Content-Type"), "application/json") {
					var value map[string]any
					if decodeErr := json.Unmarshal(recorded.Body.Bytes(), &value); decodeErr != nil {
						t.Errorf("decode reference response: %v", decodeErr)
						return
					}
					choices, _ := value["choices"].([]any)
					if len(choices) > 0 {
						choices[0].(map[string]any)["finish_reason"] = reflected
						rewriteJSON(recorded, value)
					}
				}
				for name, values := range recorded.Header() {
					for _, value := range values {
						writer.Header().Add(name, value)
					}
				}
				writer.WriteHeader(recorded.Code)
				_, _ = writer.Write(recorded.Body.Bytes())
			}))
			defer server.Close()

			target := config.Target{
				BaseURL: server.URL + "/v1", Protocol: "openai-chat", Model: "fixture-model",
				Auth: &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://SYNTHETIC_TOKEN"}},
			}
			dataRoot := filepath.Join(t.TempDir(), "data")
			execution, executeErr := Execute(context.Background(), ExecuteRequest{
				Planned: mustPlan(t, target, schema.BudgetPolicy{}), DataRoot: dataRoot,
				Secrets: &staticSecretResolver{value: []byte(credential)},
			})
			if executeErr != nil {
				t.Fatal(executeErr)
			}
			item, ok := findCase(execution.Report.Cases, "openai-chat-002-terminal-status")
			if !ok || len(item.AssertionResults) != 1 || len(item.Findings) != 1 {
				t.Fatalf("reflected credential did not reach the expected assertion path: %#v", item)
			}
			if item.AssertionResults[0].Observed != "[REDACTED]" {
				t.Fatalf("observed value was not redacted: %#v", item.AssertionResults[0].Observed)
			}
			fingerprints = append(fingerprints, item.Findings[0].Fingerprint)

			resultJSON, marshalErr := json.Marshal(execution.ExecutorResult)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var persisted bytes.Buffer
			walkErr := filepath.WalkDir(dataRoot, func(path string, entry fs.DirEntry, visitErr error) error {
				if visitErr != nil || entry.IsDir() {
					return visitErr
				}
				raw, readErr := os.ReadFile(path)
				if readErr == nil {
					persisted.Write(raw)
				}
				return readErr
			})
			if walkErr != nil {
				t.Fatal(walkErr)
			}
			for label, raw := range map[string][]byte{
				"executor result": resultJSON, "report JSON": execution.ReportJSON, "persistent store": persisted.Bytes(),
			} {
				if bytes.Contains(raw, []byte(credential)) {
					t.Fatalf("%s contains reflected credential", label)
				}
			}
		})
	}
	if len(fingerprints) != 2 || fingerprints[0] != fingerprints[1] {
		t.Fatalf("finding fingerprint depends on the reflected credential: %#v", fingerprints)
	}
}

func TestExecuteLastScenarioRunBudgetExhaustionCannotPassRun(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var requestMu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestMu.Lock()
		requestCount++
		current := requestCount
		requestMu.Unlock()

		recorded := httptest.NewRecorder()
		reference.ServeHTTP(recorded, request)
		if current == 4 && recorded.Code == http.StatusOK {
			var value map[string]any
			if decodeErr := json.Unmarshal(recorded.Body.Bytes(), &value); decodeErr != nil {
				t.Errorf("decode final response: %v", decodeErr)
				return
			}
			usage, ok := value["usage"].(map[string]any)
			if !ok {
				t.Error("final response omitted usage")
				return
			}
			output := int64(terminalTokenCap + 3*structuralTokenCap + 1)
			usage["output_tokens"] = output
			usage["total_tokens"] = output + 4
			rewriteJSON(recorded, value)
		}
		for name, values := range recorded.Header() {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.Header().Del("Content-Length")
		writer.WriteHeader(recorded.Code)
		_, _ = writer.Write(recorded.Body.Bytes())
	}))
	defer server.Close()

	planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-responses", Model: "fixture-model"}, schema.BudgetPolicy{})
	execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Report.Outcome != schema.ProfileInconclusive || execution.Report.PrimaryExitCode != 4 || !execution.ExecutorResult.Budget.Exhausted {
		t.Fatalf("overshoot aggregate = %#v / %#v", execution.Report, execution.ExecutorResult.Budget)
	}
	last, ok := findCase(execution.Report.Cases, "openai-responses-http-039-terminal-status")
	if !ok || last.ExecutionStatus != schema.ExecutionCompleted || last.Verdict == nil || *last.Verdict != schema.VerdictPass || last.ReasonCode != schema.ReasonBudgetExhausted {
		t.Fatalf("last overshooting case = %#v", last)
	}
	if !hasCondition(execution.Report.Conditions, "run_budget_exhausted") {
		t.Fatalf("overshoot report omitted durable condition: %#v", execution.Report.Conditions)
	}
	decoded, err := report.Decode(execution.ReportJSON)
	if err != nil || !hasCondition(decoded.Conditions, "run_budget_exhausted") {
		t.Fatalf("persisted overshoot condition = %#v, %v", decoded.Conditions, err)
	}
}

func TestExecuteSeparatesTargetFailureFromTransportAndAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name         string
		protocol     string
		status       int
		contentType  string
		body         []byte
		wantOutcome  schema.ProfileOutcome
		wantExit     int
		wantStatus   schema.ExecutionStatus
		wantReason   schema.ReasonCode
		wantVerdict  *schema.Verdict
		wantFindings bool
		wantUnknown  bool
	}{
		{
			name: "ordinary target rejection", status: http.StatusBadRequest, contentType: "application/json",
			body: validChatDocument(), wantOutcome: schema.ProfileIncompatible, wantExit: 1,
			wantStatus: schema.ExecutionCompleted, wantVerdict: verdictPointer(schema.VerdictFail), wantFindings: true,
		},
		{
			name: "Chat provider output-limit field unsupported", protocol: "openai-chat", status: http.StatusBadRequest, contentType: "application/json",
			body:        []byte(`{"error":{"message":"Unsupported parameter: 'max_completion_tokens'.","param":"max_completion_tokens","code":"unsupported_parameter"}}`),
			wantOutcome: schema.ProfileInconclusive, wantExit: 4, wantStatus: schema.ExecutionCompleted,
			wantReason: schema.ReasonUnsupportedCapability, wantVerdict: verdictPointer(schema.VerdictInconclusive), wantUnknown: true,
		},
		{
			name: "Responses provider output-limit field unsupported", protocol: "openai-responses", status: http.StatusBadRequest, contentType: "application/json",
			body:        []byte(`{"error":{"message":"Unknown parameter: max_output_tokens","param":"max_output_tokens","code":"unknown_parameter"}}`),
			wantOutcome: schema.ProfileInconclusive, wantExit: 4, wantStatus: schema.ExecutionCompleted,
			wantReason: schema.ReasonUnsupportedCapability, wantVerdict: verdictPointer(schema.VerdictInconclusive), wantUnknown: true,
		},
		{
			name: "authentication", status: http.StatusUnauthorized, contentType: "application/json",
			body: []byte(`{"error":{"code":"synthetic"}}`), wantOutcome: schema.ProfileInconclusive, wantExit: 5,
			wantStatus: schema.ExecutionErrored, wantReason: schema.ReasonAuthenticationFailed, wantUnknown: true,
		},
		{
			name: "permission", status: http.StatusForbidden, contentType: "application/json",
			body: []byte(`{"error":{"code":"synthetic"}}`), wantOutcome: schema.ProfileInconclusive, wantExit: 5,
			wantStatus: schema.ExecutionErrored, wantReason: schema.ReasonPermissionDenied, wantUnknown: true,
		},
		{
			name: "transient", status: http.StatusTooManyRequests, contentType: "application/json",
			body: []byte(`{"error":{"code":"synthetic"}}`), wantOutcome: schema.ProfileInconclusive, wantExit: 3,
			wantStatus: schema.ExecutionErrored, wantReason: schema.ReasonTransientError, wantUnknown: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.body)
			}))
			defer server.Close()
			protocol := test.protocol
			if protocol == "" {
				protocol = "openai-chat"
			}
			planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: protocol, Model: "fixture-model"}, schema.BudgetPolicy{})
			dataRoot := filepath.Join(t.TempDir(), "data")
			execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: dataRoot})
			if err != nil {
				t.Fatal(err)
			}
			if execution.Report.Outcome != test.wantOutcome || execution.Report.PrimaryExitCode != test.wantExit {
				t.Fatalf("aggregate = %s/%d", execution.Report.Outcome, execution.Report.PrimaryExitCode)
			}
			evidenceStore, err := cas.Open(filepath.Join(dataRoot, "evidence"), cas.DefaultMaxObjectBytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range execution.Report.Cases {
				if item.ExecutionStatus != test.wantStatus || item.ReasonCode != test.wantReason {
					t.Fatalf("case classification = %#v", item)
				}
				if test.wantVerdict == nil && item.Verdict != nil || test.wantVerdict != nil && (item.Verdict == nil || *item.Verdict != *test.wantVerdict) {
					t.Fatalf("case verdict = %#v", item)
				}
				if test.wantFindings != (len(item.Findings) > 0) {
					t.Fatalf("case findings = %#v", item.Findings)
				}
				if len(item.EvidenceRefs) == 0 {
					t.Fatalf("case lost persisted response evidence: %#v", item)
				}
				for _, ref := range item.EvidenceRefs {
					evidence, err := evidenceStore.GetEvidence(context.Background(), ref)
					if err != nil || evidence.RunID != execution.Report.RunID {
						t.Fatalf("case Evidence ref does not close over this run: ref=%#v evidence=%#v err=%v", ref, evidence, err)
					}
				}
			}
			if test.wantUnknown {
				if !slices.Equal(execution.ExecutorResult.Budget.Unknown, []string{"input_tokens", "output_tokens"}) {
					t.Fatalf("aggregate unknown usage = %#v", execution.ExecutorResult.Budget)
				}
				for _, attempt := range execution.ExecutorResult.Attempts {
					if attempt.ConsumedBudget.InputTokens != nil || attempt.ConsumedBudget.OutputTokens != nil || !slices.Equal(attempt.ConsumedBudget.Unknown, []string{"input_tokens", "output_tokens"}) {
						t.Fatalf("attempt usage was presented as observed zero: %#v", attempt.ConsumedBudget)
					}
				}
				if !hasCondition(execution.Report.Conditions, "provider_usage_unknown") {
					t.Fatalf("durable report omitted unknown usage: %#v", execution.Report.Conditions)
				}
			}
		})
	}
}

func TestExactResolverRejectsEveryNonExactPin(t *testing.T) {
	runner := &stubRunner{}
	pin := schema.ArtifactPin{Kind: "Driver", Name: "exact-driver", Version: "1.0.0", Digest: schema.NewDigest([]byte("exact"))}
	resolver, err := NewExactResolver(pin, runner)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := resolver.Resolve(pin); err != nil || got != runner {
		t.Fatalf("exact pin did not resolve: %v", err)
	}
	mutations := []schema.ArtifactPin{pin, pin, pin, pin}
	mutations[0].Kind = "Oracle"
	mutations[1].Name = "other-driver"
	mutations[2].Version = "1.0.1"
	mutations[3].Digest = schema.NewDigest([]byte("other"))
	for _, mutation := range mutations {
		if _, err := resolver.Resolve(mutation); err == nil {
			t.Fatalf("non-exact pin resolved: %#v", mutation)
		}
	}
}

type pathRecorder struct {
	mu   sync.Mutex
	next http.Handler
	seen []string
}

type limitedChatHandler struct {
	next http.Handler
}

func (handler *limitedChatHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	recorded := httptest.NewRecorder()
	handler.next.ServeHTTP(recorded, request)
	if strings.HasPrefix(recorded.Header().Get("Content-Type"), "text/event-stream") {
		body := strings.Replace(recorded.Body.String(), `"finish_reason":"stop"`, `"finish_reason":"length"`, 1)
		recorded.Body.Reset()
		recorded.Body.WriteString(body)
	} else if recorded.Code == http.StatusOK {
		var value map[string]any
		if err := json.Unmarshal(recorded.Body.Bytes(), &value); err == nil {
			choices, _ := value["choices"].([]any)
			if len(choices) > 0 {
				choices[0].(map[string]any)["finish_reason"] = "length"
				rewriteJSON(recorded, value)
			}
		}
	}
	for name, values := range recorded.Header() {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(recorded.Code)
	_, _ = writer.Write(recorded.Body.Bytes())
}

func (recorder *pathRecorder) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	recorder.mu.Lock()
	recorder.seen = append(recorder.seen, request.URL.Path)
	recorder.mu.Unlock()
	recorder.next.ServeHTTP(writer, request)
}

func (recorder *pathRecorder) snapshot() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return slices.Clone(recorder.seen)
}

type responseMutator struct {
	next     http.Handler
	protocol string
	check    rawdriver.CheckKind
}

func (mutator *responseMutator) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	recorded := httptest.NewRecorder()
	mutator.next.ServeHTTP(recorded, request)
	mutateResponse(recorded, mutator.protocol, string(mutator.check))
	for name, values := range recorded.Header() {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(recorded.Code)
	_, _ = writer.Write(recorded.Body.Bytes())
}

func mutateResponse(recorded *httptest.ResponseRecorder, protocol, check string) {
	streaming := strings.HasPrefix(recorded.Header().Get("Content-Type"), "text/event-stream")
	switch check {
	case "finish_reason":
		if streaming {
			return
		}
		var value map[string]any
		_ = json.Unmarshal(recorded.Body.Bytes(), &value)
		if protocol == "openai-chat" {
			choices, _ := value["choices"].([]any)
			if len(choices) > 0 {
				choices[0].(map[string]any)["finish_reason"] = "fixture_invalid_reason"
			}
		} else if protocol == "openai-responses" {
			value["status"] = "fixture_invalid_reason"
		}
		rewriteJSON(recorded, value)
	case "required_response_envelope":
		if streaming {
			return
		}
		var value map[string]any
		_ = json.Unmarshal(recorded.Body.Bytes(), &value)
		delete(value, "id")
		rewriteJSON(recorded, value)
	case "stream_media_type":
		if streaming {
			recorded.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
	case "no_post_terminal_data":
		if !streaming {
			return
		}
		suffix := map[string]string{
			"openai-chat":        "data: {\"id\":\"late\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"late\"},\"finish_reason\":null}]}\n\n",
			"openai-responses":   "event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"sequence_number\":999}\n\n",
			"anthropic-messages": "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
		}[protocol]
		recorded.Body.WriteString(suffix)
	case "terminal_event":
		if !streaming {
			return
		}
		marker := map[string]string{
			"openai-chat": "data: [DONE]", "openai-responses": "event: response.completed", "anthropic-messages": "event: message_stop",
		}[protocol]
		blocks := strings.Split(recorded.Body.String(), "\n\n")
		kept := blocks[:0]
		for _, block := range blocks {
			if !strings.Contains(block, marker) {
				kept = append(kept, block)
			}
		}
		recorded.Body.Reset()
		recorded.Body.WriteString(strings.Join(kept, "\n\n"))
	}
}

func rewriteJSON(recorded *httptest.ResponseRecorder, value any) {
	recorded.Body.Reset()
	_ = json.NewEncoder(recorded.Body).Encode(value)
}

type staticSecretResolver struct {
	value []byte
	calls int
}

func (resolver *staticSecretResolver) Resolve(context.Context, string) ([]byte, error) {
	resolver.calls++
	return slices.Clone(resolver.value), nil
}

type stubRunner struct{}

func (*stubRunner) Estimate(schema.ScenarioDecision) (budget.Usage, error) {
	return budget.Usage{Requests: 1}, nil
}
func (*stubRunner) Run(context.Context, executor.Invocation) (executor.Outcome, error) {
	return executor.Outcome{}, errors.New("not used")
}
func (*stubRunner) Finalize(context.Context, schema.FinalizerPlan) (budget.Usage, error) {
	return budget.Usage{}, errors.New("not used")
}

func mustPlan(t *testing.T, target config.Target, runBudget schema.BudgetPolicy) PlannedRun {
	t.Helper()
	planned, err := Build(PlanRequest{TargetName: "fixture", Target: target, Budget: runBudget})
	if err != nil {
		t.Fatal(err)
	}
	return planned
}

func findCase(cases []schema.CaseResult, id string) (schema.CaseResult, bool) {
	for _, item := range cases {
		if item.ScenarioID == id {
			return item, true
		}
	}
	return schema.CaseResult{}, false
}

func hasCondition(conditions []report.Condition, code string) bool {
	return slices.ContainsFunc(conditions, func(condition report.Condition) bool { return condition.Code == code })
}

func verdictPointer(value schema.Verdict) *schema.Verdict { return &value }

func validChatDocument() []byte {
	return []byte(`{"id":"chatcmpl_test","object":"chat.completion","created":1700000000,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
}
