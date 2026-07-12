package e2e_test

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
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/executor"
	"github.com/whyiug/agentapi-doctor/internal/rawdriver"
	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/internal/transport"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

const secretCanary = referenceserver.SyntheticBearerToken

type mutationCase struct {
	id       mutantserver.ID
	protocol rawdriver.Protocol
	path     string
	body     json.RawMessage
	stream   bool
	check    rawdriver.CheckKind
	allowed  []string
	usage    *rawdriver.TokenUsage
}

func TestRawDriverReferencePassesAndAllTargetedMutantsAreKilled(t *testing.T) {
	total := int64(6)
	cases := []mutationCase{
		{mutantserver.ArgumentsObjectInsteadOfString, rawdriver.ProtocolOpenAIChat, "/v1/chat/completions", rawChatBody(t, false, true), false, rawdriver.CheckArgumentsString, nil, nil},
		{mutantserver.MissingOutputIndex, rawdriver.ProtocolOpenAIResponses, "/v1/responses", rawResponsesBody(t, true, false), true, rawdriver.CheckOutputIndexes, nil, nil},
		{mutantserver.DuplicateOutputIndex, rawdriver.ProtocolOpenAIResponses, "/v1/responses", rawResponsesBody(t, true, false), true, rawdriver.CheckOutputIndexes, nil, nil},
		{mutantserver.DroppedStreamingToolCall, rawdriver.ProtocolOpenAIChat, "/v1/chat/completions", rawChatBody(t, true, true), true, rawdriver.CheckStreamingToolCall, nil, nil},
		{mutantserver.InvalidFinishReason, rawdriver.ProtocolOpenAIChat, "/v1/chat/completions", rawChatBody(t, false, false), false, rawdriver.CheckFinishReason, []string{"stop"}, nil},
		{mutantserver.MissingTerminalEvent, rawdriver.ProtocolOpenAIChat, "/v1/chat/completions", rawChatBody(t, true, false), true, rawdriver.CheckTerminalEvent, nil, nil},
		{mutantserver.DuplicateTerminalEvent, rawdriver.ProtocolOpenAIChat, "/v1/chat/completions", rawChatBody(t, true, false), true, rawdriver.CheckTerminalEvent, nil, nil},
		{mutantserver.ToolCallIDChanged, rawdriver.ProtocolOpenAIResponses, "/v1/responses", rawResponsesBody(t, true, true), true, rawdriver.CheckStableToolCallID, nil, nil},
		{mutantserver.UnknownEventCrashesClient, rawdriver.ProtocolAnthropic, "/v1/messages", rawAnthropicBody(t, true, false), true, rawdriver.CheckNoUnknownEvent, nil, nil},
		{mutantserver.UnclosedReasoningBlock, rawdriver.ProtocolOpenAIResponses, "/v1/responses", rawResponsesBody(t, true, false), true, rawdriver.CheckClosedReasoning, nil, nil},
		{mutantserver.UsageInconsistent, rawdriver.ProtocolOpenAIResponses, "/v1/responses", rawResponsesBody(t, false, false), false, rawdriver.CheckUsageConsistent, nil, &rawdriver.TokenUsage{Input: 4, Output: 2, Total: &total}},
		{mutantserver.TruncatedUTF8, rawdriver.ProtocolAnthropic, "/v1/messages", rawAnthropicBody(t, true, false), true, rawdriver.CheckValidUTF8, nil, nil},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(string(testCase.id), func(t *testing.T) {
			reference, err := referenceserver.New(referenceserver.Config{})
			if err != nil {
				t.Fatal(err)
			}
			referenceServer := httptest.NewServer(reference)
			referenceOutcome, _, _ := runScenario(t, referenceServer, scenarioFor(testCase, "reference-"+string(testCase.id)))
			referenceServer.Close()
			if referenceOutcome.Verdict != schema.VerdictPass || len(referenceOutcome.Findings) != 0 || len(referenceOutcome.AssertionResults) != 1 {
				t.Fatalf("reference result = %#v", referenceOutcome)
			}
			if referenceOutcome.AssertionResults[0].Verdict != schema.VerdictPass {
				t.Fatalf("reference assertion = %#v", referenceOutcome.AssertionResults[0])
			}

			mutation, err := mutantserver.New(testCase.id)
			if err != nil {
				t.Fatal(err)
			}
			mutant, err := referenceserver.New(referenceserver.Config{Transformer: mutation})
			if err != nil {
				t.Fatal(err)
			}
			mutantServer := httptest.NewServer(mutant)
			mutantOutcome, _, _ := runScenario(t, mutantServer, scenarioFor(testCase, "mutant-"+string(testCase.id)))
			mutantServer.Close()
			if mutantOutcome.Verdict != schema.VerdictFail || len(mutantOutcome.Findings) != 1 || len(mutantOutcome.AssertionResults) != 1 {
				t.Fatalf("mutant result = %#v", mutantOutcome)
			}
			if mutantOutcome.AssertionResults[0].Verdict != schema.VerdictFail || mutantOutcome.Findings[0].Category == "" {
				t.Fatalf("mutant assertion/finding = %#v / %#v", mutantOutcome.AssertionResults[0], mutantOutcome.Findings[0])
			}
			for _, ref := range mutantOutcome.EvidenceRefs {
				if ref.Kind != "Evidence" || ref.ContentDigest.Validate() != nil {
					t.Fatalf("invalid evidence ref: %#v", ref)
				}
			}
		})
	}
}

func TestRawDriverPlanBudgetCancellationAndErrorBoundaries(t *testing.T) {
	base := mutationCase{
		protocol: rawdriver.ProtocolOpenAIChat,
		path:     "/v1/chat/completions",
		body:     rawChatBody(t, false, false),
		check:    rawdriver.CheckFinishReason,
		allowed:  []string{"stop"},
	}

	t.Run("plan digest", func(t *testing.T) {
		handler := statusHandler(http.StatusOK, validChatResponse())
		server := httptest.NewServer(handler)
		defer server.Close()
		scenario := scenarioFor(base, "plan-digest")
		runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
		invocation := invocationFor(t, scenario)
		invocation.PlanDigest = digest("different-plan")
		outcome, err := runner.Run(context.Background(), invocation)
		assertRunError(t, outcome, err, executor.ErrorHarness)
	})

	t.Run("request body budget", func(t *testing.T) {
		scenario := scenarioFor(base, "request-budget")
		scenario.Budget.RequestBytes = 1
		if _, err := rawdriver.NewMemoryRegistry(scenario); err == nil || !strings.Contains(err.Error(), "request body exceeds") {
			t.Fatalf("expected request budget rejection, got %v", err)
		}
	})

	t.Run("response body budget", func(t *testing.T) {
		server := httptest.NewServer(statusHandler(http.StatusOK, validChatResponse()))
		defer server.Close()
		scenario := scenarioFor(base, "response-budget")
		scenario.Budget.ResponseBytes = 8
		runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
		outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
		assertRunError(t, outcome, err, executor.ErrorHarness)
	})

	for _, statusCase := range []struct {
		name   string
		status int
		class  executor.ErrorClass
	}{
		{"authentication", http.StatusUnauthorized, executor.ErrorAuthentication},
		{"permission", http.StatusForbidden, executor.ErrorPermission},
		{"rate limit", http.StatusTooManyRequests, executor.ErrorTransient},
		{"server error", http.StatusInternalServerError, executor.ErrorTransient},
	} {
		statusCase := statusCase
		t.Run(statusCase.name, func(t *testing.T) {
			server := httptest.NewServer(statusHandler(statusCase.status, []byte(`{"error":{"code":"synthetic"}}`)))
			defer server.Close()
			scenario := scenarioFor(base, "status-"+statusCase.name)
			runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
			outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
			assertRunError(t, outcome, err, statusCase.class)
		})
	}

	t.Run("ordinary target rejection is a target FAIL", func(t *testing.T) {
		server := httptest.NewServer(statusHandler(http.StatusBadRequest, validChatResponse()))
		defer server.Close()
		scenario := scenarioFor(base, "target-400")
		runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
		outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
		if err != nil || outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "unexpected_http_status" {
			t.Fatalf("400 target result = %#v, %v", outcome, err)
		}
	})

	t.Run("driver connection failure", func(t *testing.T) {
		server := httptest.NewServer(statusHandler(http.StatusOK, validChatResponse()))
		scenario := scenarioFor(base, "driver-failure")
		runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
		server.Close()
		outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
		assertRunError(t, outcome, err, executor.ErrorDriver)
	})

	t.Run("cancellation", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			close(started)
			select {
			case <-request.Context().Done():
			case <-release:
			}
		}))
		scenario := scenarioFor(base, "cancelled")
		runner, _, _ := newRunner(t, server.URL, scenario, 1<<20)
		ctx, cancel := context.WithCancel(context.Background())
		invocation := invocationFor(t, scenario)
		type runResult struct {
			outcome executor.Outcome
			err     error
		}
		result := make(chan runResult, 1)
		go func() {
			outcome, runErr := runner.Run(ctx, invocation)
			result <- runResult{outcome: outcome, err: runErr}
		}()
		<-started
		cancel()
		run := <-result
		close(release)
		server.Close()
		assertRunError(t, run.outcome, run.err, executor.ErrorHarness)
		if !errors.Is(run.err, context.Canceled) {
			t.Fatalf("cancellation was not preserved: %v", run.err)
		}
	})
}

func TestRawDriverRedactsBeforeCASAndUsesExactRegistryEstimate(t *testing.T) {
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(reference)
	defer server.Close()
	caseInput := mutationCase{
		protocol: rawdriver.ProtocolOpenAIChat,
		path:     "/v1/chat/completions",
		body:     rawChatBody(t, false, false),
		check:    rawdriver.CheckFinishReason,
		allowed:  []string{"stop"},
	}
	scenario := scenarioFor(caseInput, "redaction-cas")
	runner, storeRoot, registry := newRunner(t, server.URL, scenario, 1<<20)
	estimate, err := runner.Estimate(schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver})
	if err != nil {
		t.Fatal(err)
	}
	if estimate.Requests != 1 || estimate.RequestBytes != int64(len(scenario.Body)) || estimate.ResponseBytes != scenario.Budget.ResponseBytes {
		t.Fatalf("estimate = %#v", estimate)
	}
	other := scenario
	other.PlanDigest = digest("another-plan")
	if err := registry.Register(other); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Estimate(schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous estimate to fail, got %v", err)
	}

	outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
	if err != nil || outcome.Verdict != schema.VerdictPass || outcome.Usage.ArtifactBytes <= 0 {
		t.Fatalf("outcome = %#v, %v", outcome, err)
	}
	var persisted bytes.Buffer
	objectCount := 0
	err = filepath.WalkDir(storeRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		objectCount++
		persisted.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if objectCount < 3 {
		t.Fatalf("expected request, response metadata, and response body CAS objects; got %d", objectCount)
	}
	if bytes.Contains(persisted.Bytes(), []byte(secretCanary)) || bytes.Contains(persisted.Bytes(), []byte("Bearer "+secretCanary)) {
		t.Fatal("secret canary reached the evidence CAS")
	}
	if !bytes.Contains(persisted.Bytes(), []byte(redaction.Replacement)) {
		t.Fatal("redaction marker was not persisted")
	}
}

func scenarioFor(testCase mutationCase, id string) rawdriver.Scenario {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("Authorization", "Bearer "+referenceserver.SyntheticBearerToken)
	if testCase.protocol == rawdriver.ProtocolAnthropic {
		headers.Set("anthropic-version", "2023-06-01")
	}
	return rawdriver.Scenario{
		PlanDigest:     digest("plan-" + id),
		ID:             id,
		Driver:         driverPin(),
		Protocol:       testCase.protocol,
		Method:         http.MethodPost,
		Path:           testCase.path,
		Headers:        headers,
		Body:           testCase.body,
		Streaming:      testCase.stream,
		ExpectedStatus: http.StatusOK,
		Budget:         rawdriver.BodyBudget{RequestBytes: 1 << 20, ResponseBytes: 1 << 20},
		Assertion: rawdriver.AssertionSpec{
			AssertionID:     "synthetic." + id,
			RequirementID:   "REQ-SYNTHETIC-RAW-HTTP",
			Role:            schema.AssertionNormative,
			Oracle:          oraclePin(),
			EvaluatorDigest: digest("evaluator-v1"),
			Check:           testCase.check,
			AllowedValues:   testCase.allowed,
			ExpectedUsage:   testCase.usage,
		},
	}
}

func runScenario(t *testing.T, server *httptest.Server, scenario rawdriver.Scenario) (executor.Outcome, string, *rawdriver.MemoryRegistry) {
	t.Helper()
	runner, root, registry := newRunner(t, server.URL, scenario, 2<<20)
	outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
	if err != nil {
		t.Fatalf("run scenario: %v", err)
	}
	return outcome, root, registry
}

func newRunner(t *testing.T, origin string, scenario rawdriver.Scenario, maxResponseBytes int64) (*rawdriver.Runner, string, *rawdriver.MemoryRegistry) {
	t.Helper()
	registry, err := rawdriver.NewMemoryRegistry(scenario)
	if err != nil {
		t.Fatal(err)
	}
	client, err := transport.New(transport.Policy{
		AllowedOrigin:    origin,
		Mode:             transport.NetworkLocalTarget,
		Redirects:        transport.RedirectNone,
		AllowPlainHTTP:   true,
		MaxRequestBytes:  2 << 20,
		MaxResponseBytes: maxResponseBytes,
		Timeout:          3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "cas")
	store, err := cas.Open(root, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	redactorInstance, err := redaction.New(nil, [][]byte{[]byte(secretCanary)})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := rawdriver.New(rawdriver.Config{
		Registry:  registry,
		Transport: client,
		Store:     store,
		Redactor:  redactorInstance,
		Producer: schema.Producer{
			Name: "rawdriver-e2e", Version: "1.0.0", ArtifactDigest: digest("rawdriver-producer"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner, root, registry
}

func invocationFor(t *testing.T, scenario rawdriver.Scenario) executor.Invocation {
	t.Helper()
	return executor.Invocation{
		RunID:         newID(t),
		InvocationID:  newID(t),
		AttemptID:     newID(t),
		PlanDigest:    scenario.PlanDigest,
		Scenario:      schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver},
		AttemptNumber: 1,
	}
}

func assertRunError(t *testing.T, outcome executor.Outcome, err error, class executor.ErrorClass) {
	t.Helper()
	var typed *executor.RunError
	if !errors.As(err, &typed) || typed.Class != class {
		t.Fatalf("expected %s RunError, got %#v / %v", class, typed, err)
	}
	if outcome.Verdict != "" || len(outcome.Findings) != 0 || len(outcome.AssertionResults) != 0 {
		t.Fatalf("non-target error gained endpoint result: %#v", outcome)
	}
}

func statusHandler(status int, body []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	})
}

func validChatResponse() []byte {
	return []byte(`{"id":"chatcmpl_test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
}

func rawChatBody(t *testing.T, stream, tool bool) json.RawMessage {
	t.Helper()
	value := map[string]any{
		"model": "fixture-model", "messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": stream,
	}
	if tool {
		value["tools"] = []any{map[string]any{
			"type": "function", "function": map[string]any{"name": "synthetic_echo", "parameters": map[string]any{"type": "object"}},
		}}
	}
	return mustRawJSON(t, value)
}

func rawResponsesBody(t *testing.T, stream, tool bool) json.RawMessage {
	t.Helper()
	value := map[string]any{"model": "fixture-model", "input": "hello", "stream": stream}
	if tool {
		value["tools"] = []any{map[string]any{"type": "function", "name": "synthetic_echo"}}
	}
	return mustRawJSON(t, value)
}

func rawAnthropicBody(t *testing.T, stream, tool bool) json.RawMessage {
	t.Helper()
	value := map[string]any{
		"model": "fixture-model", "max_tokens": 16,
		"messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": stream,
	}
	if tool {
		value["tools"] = []any{map[string]any{"name": "synthetic_echo", "input_schema": map[string]any{"type": "object"}}}
	}
	return mustRawJSON(t, value)
}

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func digest(label string) schema.Digest { return schema.NewDigest([]byte(label)) }

func driverPin() schema.ArtifactPin {
	return schema.ArtifactPin{Kind: "Driver", Name: "raw-http", Version: "1.0.0", Digest: digest("raw-http-driver")}
}

func oraclePin() schema.ArtifactPin {
	return schema.ArtifactPin{Kind: "Oracle", Name: "raw-http-oracle", Version: "1.0.0", Digest: digest("raw-http-oracle")}
}

func newID(t *testing.T) schema.InstanceID {
	t.Helper()
	id, err := schema.NewInstanceID(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
