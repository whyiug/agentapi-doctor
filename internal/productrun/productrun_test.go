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

	"github.com/whyiug/agentapi-doctor/internal/budget"
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

func TestRouteTargetSafelyHandlesRootAndV1Prefixes(t *testing.T) {
	tests := []struct {
		base, protocol, want string
	}{
		{"http://127.0.0.1:8090", "openai-chat", "/v1/chat/completions"},
		{"http://127.0.0.1:8090/", "openai-chat", "/v1/chat/completions"},
		{"http://127.0.0.1:8090/v1", "openai-responses", "/v1/responses"},
		{"http://127.0.0.1:8090/v1/", "anthropic-messages", "/v1/messages"},
		{"https://example.test/gateway", "openai-chat", "/gateway/v1/chat/completions"},
		{"https://example.test/gateway/v1", "openai-responses", "/gateway/v1/responses"},
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
		})
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

func TestExecuteSeparatesTargetFailureFromTransportAndAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        []byte
		wantOutcome schema.ProfileOutcome
		wantExit    int
		wantStatus  schema.ExecutionStatus
		wantReason  schema.ReasonCode
		wantVerdict *schema.Verdict
	}{
		{
			name: "ordinary target rejection", status: http.StatusBadRequest, contentType: "application/json",
			body: validChatDocument(), wantOutcome: schema.ProfileIncompatible, wantExit: 1,
			wantStatus: schema.ExecutionCompleted, wantVerdict: verdictPointer(schema.VerdictFail),
		},
		{
			name: "authentication", status: http.StatusUnauthorized, contentType: "application/json",
			body: []byte(`{"error":{"code":"synthetic"}}`), wantOutcome: schema.ProfileInconclusive, wantExit: 5,
			wantStatus: schema.ExecutionErrored, wantReason: schema.ReasonHarnessError,
		},
		{
			name: "transient", status: http.StatusTooManyRequests, contentType: "application/json",
			body: []byte(`{"error":{"code":"synthetic"}}`), wantOutcome: schema.ProfileInconclusive, wantExit: 3,
			wantStatus: schema.ExecutionErrored, wantReason: schema.ReasonTransientError,
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
			planned := mustPlan(t, config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"}, schema.BudgetPolicy{})
			execution, err := Execute(context.Background(), ExecuteRequest{Planned: planned, DataRoot: filepath.Join(t.TempDir(), "data")})
			if err != nil {
				t.Fatal(err)
			}
			if execution.Report.Outcome != test.wantOutcome || execution.Report.PrimaryExitCode != test.wantExit {
				t.Fatalf("aggregate = %s/%d", execution.Report.Outcome, execution.Report.PrimaryExitCode)
			}
			for _, item := range execution.Report.Cases {
				if item.ExecutionStatus != test.wantStatus || item.ReasonCode != test.wantReason {
					t.Fatalf("case classification = %#v", item)
				}
				if test.wantVerdict == nil && item.Verdict != nil || test.wantVerdict != nil && (item.Verdict == nil || *item.Verdict != *test.wantVerdict) {
					t.Fatalf("case verdict = %#v", item)
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

func verdictPointer(value schema.Verdict) *schema.Verdict { return &value }

func validChatDocument() []byte {
	return []byte(`{"id":"chatcmpl_test","object":"chat.completion","created":1700000000,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
}
