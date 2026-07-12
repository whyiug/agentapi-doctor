package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	t.Run("partial response evidence survives recorder failure", func(t *testing.T) {
		stream := "data: {\"id\":\"chatcmpl_partial\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"},\"finish_reason\":null}]}\n\n" +
			"data: {\"padding\":\"" + strings.Repeat("x", 2048) + "\"}\n\n"
		server := httptest.NewServer(streamHandler(http.StatusOK, []byte(stream)))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, true, false), stream: true, check: rawdriver.CheckTerminalEvent,
		}, "partial-body-evidence")
		runner, root, _ := newRunnerWithObservationLimit(t, server.URL, scenario, 1<<20, 1024)
		outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
		typed := assertRunError(t, outcome, err, executor.ErrorHarness)
		if len(typed.EvidenceRefs) != 3 {
			t.Fatalf("partial recorder failure retained %d Evidence refs, want request, metadata, and first event", len(typed.EvidenceRefs))
		}
		store, openErr := cas.Open(root, 4<<20)
		if openErr != nil {
			t.Fatal(openErr)
		}
		partial, getErr := store.GetEvidence(context.Background(), typed.EvidenceRefs[2])
		if getErr != nil {
			t.Fatalf("partial response Evidence is dangling: %v", getErr)
		}
		if partial.EvidenceKind != "sse_logical_event" {
			t.Fatalf("partial response Evidence kind = %q", partial.EvidenceKind)
		}
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
			runner, root, _ := newRunner(t, server.URL, scenario, 1<<20)
			outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
			typed := assertRunError(t, outcome, err, statusCase.class)
			if len(typed.EvidenceRefs) != 3 {
				t.Fatalf("classified status retained %d Evidence refs, want request, metadata, and body", len(typed.EvidenceRefs))
			}
			store, openErr := cas.Open(root, 4<<20)
			if openErr != nil {
				t.Fatal(openErr)
			}
			for _, ref := range typed.EvidenceRefs {
				if _, getErr := store.GetEvidence(context.Background(), ref); getErr != nil {
					t.Fatalf("classified status returned dangling Evidence ref %#v: %v", ref, getErr)
				}
			}
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

func TestRawDriverOutputLimitPrerequisitesDoNotBecomeTargetFailures(t *testing.T) {
	unsupported := []struct {
		name     string
		protocol rawdriver.Protocol
		path     string
		body     json.RawMessage
		response []byte
		field    string
		status   int
	}{
		{
			name: "chat unsupported_parameter", protocol: rawdriver.ProtocolOpenAIChat,
			path: "/v1/chat/completions", body: rawChatBody(t, false, false), field: "max_completion_tokens",
			response: []byte(`{"error":{"message":"Unsupported parameter: 'max_completion_tokens'.","type":"invalid_request_error","param":"max_completion_tokens","code":"unsupported_parameter"}}`),
		},
		{
			name: "responses extra_forbidden", protocol: rawdriver.ProtocolOpenAIResponses,
			path: "/v1/responses", body: rawResponsesBody(t, false, false), field: "max_output_tokens",
			response: []byte(`{"detail":[{"type":"extra_forbidden","loc":["body","max_output_tokens"],"msg":"Extra inputs are not permitted"}]}`),
			status:   http.StatusUnprocessableEntity,
		},
	}
	for _, test := range unsupported {
		t.Run(test.name, func(t *testing.T) {
			status := test.status
			if status == 0 {
				status = http.StatusBadRequest
			}
			server := httptest.NewServer(statusHandler(status, test.response))
			defer server.Close()
			scenario := scenarioFor(mutationCase{
				protocol: test.protocol, path: test.path, body: test.body,
				check: rawdriver.CheckFinishReason, allowed: []string{"completed", "stop"},
			}, "output-limit-unsupported-"+string(test.protocol))
			outcome, _, _ := runScenario(t, server, scenario)
			assertOutputLimitInconclusive(t, outcome, schema.ReasonUnsupportedCapability, test.field)
		})
	}

	t.Run("ordinary 422 mentioning the field remains target FAIL", func(t *testing.T) {
		response := []byte(`{"detail":[{"type":"greater_than_equal","loc":["body","max_output_tokens"],"msg":"Input should be greater than or equal to 1"}]}`)
		server := httptest.NewServer(statusHandler(http.StatusUnprocessableEntity, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIResponses, path: "/v1/responses",
			body: rawResponsesBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"completed"},
		}, "ordinary-output-limit-422")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "unexpected_http_status" {
			t.Fatalf("ordinary 422 was hidden: %#v", outcome)
		}
	})

	t.Run("ordinary 400 mentioning the field remains target FAIL", func(t *testing.T) {
		response := []byte(`{"error":{"message":"max_completion_tokens must be at least 1","param":"max_completion_tokens","code":"invalid_value"}}`)
		server := httptest.NewServer(statusHandler(http.StatusBadRequest, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"stop"},
		}, "ordinary-output-limit-400")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "unexpected_http_status" {
			t.Fatalf("ordinary 400 was hidden: %#v", outcome)
		}
	})

	t.Run("unsupported unrelated field remains target FAIL", func(t *testing.T) {
		response := []byte(`{"error":{"message":"Unsupported parameter: 'temperature'.","param":"temperature","code":"unsupported_parameter"},"request":{"max_completion_tokens":64}}`)
		server := httptest.NewServer(statusHandler(http.StatusBadRequest, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"stop"},
		}, "ordinary-unrelated-400")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "unexpected_http_status" {
			t.Fatalf("unrelated 400 was hidden: %#v", outcome)
		}
	})

	t.Run("chat length with requested cap is inconclusive", func(t *testing.T) {
		response := []byte(`{"id":"chatcmpl_limited","object":"chat.completion","created":1700000000,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":64,"total_tokens":68}}`)
		server := httptest.NewServer(statusHandler(http.StatusOK, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"stop"},
		}, "chat-output-limit-reached")
		outcome, _, _ := runScenario(t, server, scenario)
		assertOutputLimitInconclusive(t, outcome, schema.ReasonInsufficientSamples, "max_completion_tokens")
	})

	t.Run("responses incomplete max_output_tokens is inconclusive", func(t *testing.T) {
		response := limitedResponsesDocument("max_output_tokens")
		server := httptest.NewServer(statusHandler(http.StatusOK, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIResponses, path: "/v1/responses",
			body: rawResponsesBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"completed"},
		}, "responses-output-limit-reached")
		outcome, _, _ := runScenario(t, server, scenario)
		assertOutputLimitInconclusive(t, outcome, schema.ReasonInsufficientSamples, "max_output_tokens")
	})

	t.Run("chat streaming length leaves an unrelated assertion evaluable", func(t *testing.T) {
		stream := "data: {\"id\":\"chatcmpl_limited\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n" +
			"data: {\"id\":\"chatcmpl_limited\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n\n" +
			"data: [DONE]\n\n"
		server := httptest.NewServer(streamHandler(http.StatusOK, []byte(stream)))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, true, false), stream: true, check: rawdriver.CheckNoPostTerminal,
		}, "chat-stream-output-limit-reached")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictPass || len(outcome.Findings) != 0 {
			t.Fatalf("output limit changed unrelated post-terminal assertion: %#v", outcome)
		}
	})

	t.Run("responses streaming incomplete remains a valid terminal event", func(t *testing.T) {
		stream := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_limited\",\"status\":\"in_progress\"}}\n\n" +
			"event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_limited\",\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"},\"usage\":{\"input_tokens\":4,\"output_tokens\":64,\"total_tokens\":68}}}\n\n"
		server := httptest.NewServer(streamHandler(http.StatusOK, []byte(stream)))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIResponses, path: "/v1/responses",
			body: rawResponsesBody(t, true, false), stream: true, check: rawdriver.CheckTerminalEvent,
		}, "responses-stream-output-limit-reached")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictPass || len(outcome.Findings) != 0 {
			t.Fatalf("output limit changed terminal-event assertion: %#v", outcome)
		}
	})

	t.Run("cap marker does not hide an independent envelope failure", func(t *testing.T) {
		response := []byte(`{"object":"chat.completion","created":1700000000,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":"length"}]}`)
		server := httptest.NewServer(statusHandler(http.StatusOK, response))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: rawChatBody(t, false, false), check: rawdriver.CheckRequiredEnvelope,
		}, "chat-output-limit-invalid-envelope")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "required_response_envelope_missing" {
			t.Fatalf("output limit hid an independent envelope failure: %#v", outcome)
		}
	})

	t.Run("other Responses incomplete reason remains target FAIL", func(t *testing.T) {
		server := httptest.NewServer(statusHandler(http.StatusOK, limitedResponsesDocument("content_filter")))
		defer server.Close()
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIResponses, path: "/v1/responses",
			body: rawResponsesBody(t, false, false), check: rawdriver.CheckFinishReason, allowed: []string{"completed"},
		}, "responses-other-incomplete")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "finish_reason_invalid" {
			t.Fatalf("unrelated incomplete response was hidden: %#v", outcome)
		}
	})

	t.Run("length without requested cap remains target FAIL", func(t *testing.T) {
		response := []byte(`{"id":"chatcmpl_limited","object":"chat.completion","created":1700000000,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":"length"}]}`)
		server := httptest.NewServer(statusHandler(http.StatusOK, response))
		defer server.Close()
		body := removeJSONField(t, rawChatBody(t, false, false), "max_completion_tokens")
		scenario := scenarioFor(mutationCase{
			protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
			body: body, check: rawdriver.CheckFinishReason, allowed: []string{"stop"},
		}, "chat-length-without-limit")
		outcome, _, _ := runScenario(t, server, scenario)
		if outcome.Verdict != schema.VerdictFail || len(outcome.Findings) != 1 || outcome.Findings[0].Category != "finish_reason_invalid" {
			t.Fatalf("uncapped length response was hidden: %#v", outcome)
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

func TestRawDriverBoundsSSEEvidenceAmplification(t *testing.T) {
	const ordinaryRefreshToken = "ordinary-refresh-value-not-a-canary-or-detector"
	var stream bytes.Buffer
	for index := 0; index < 600; index++ {
		sensitiveField := ""
		if index == 512 {
			sensitiveField = `,"refresh_token":"` + ordinaryRefreshToken + `"`
		}
		_, _ = fmt.Fprintf(&stream, "data: {\"id\":\"chatcmpl_many\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"fixture-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"},\"finish_reason\":null}]%s}\n\n", sensitiveField)
	}
	stream.WriteString("data: {\"id\":\"chatcmpl_many\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"fixture-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
	stream.WriteString("data: [DONE]\n\n")

	server := httptest.NewServer(streamHandler(http.StatusOK, stream.Bytes()))
	defer server.Close()
	scenario := scenarioFor(mutationCase{
		protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
		body: rawChatBody(t, true, false), stream: true, check: rawdriver.CheckTerminalEvent,
	}, "bounded-sse-evidence")
	runner, root, _ := newRunner(t, server.URL, scenario, 2<<20)
	estimate, err := runner.Estimate(schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
	if err != nil {
		t.Fatalf("bounded SSE execution: %v", err)
	}
	if len(outcome.EvidenceRefs) != 3 {
		t.Fatalf("event amplification created %d Evidence refs, want request, metadata, and one fallback", len(outcome.EvidenceRefs))
	}
	if outcome.Usage.ArtifactBytes <= 0 || outcome.Usage.ArtifactBytes > estimate.ArtifactBytes {
		t.Fatalf("artifact accounting = %d, stream = %d, reservation = %d", outcome.Usage.ArtifactBytes, stream.Len(), estimate.ArtifactBytes)
	}
	store, err := cas.Open(root, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	responseEvidence, err := store.GetEvidence(context.Background(), outcome.EvidenceRefs[2])
	if err != nil {
		t.Fatal(err)
	}
	if responseEvidence.EvidenceKind != "sse_event_limit_fallback" {
		t.Fatalf("fallback evidence kind = %q", responseEvidence.EvidenceKind)
	}
	if responseEvidence.PayloadRef == nil {
		t.Fatal("fallback Evidence omitted its JSON payload")
	}
	fallbackPayload, err := store.Get(context.Background(), responseEvidence.PayloadRef.ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fallbackPayload, []byte(ordinaryRefreshToken)) || !bytes.Contains(fallbackPayload, []byte(redaction.Replacement)) {
		t.Fatalf("fallback JSON did not field-redact refresh_token: %s", fallbackPayload)
	}
	var fallback struct {
		Representation  string            `json:"representation"`
		CompleteEvents  int               `json:"complete_event_count"`
		JSONEvents      int               `json:"json_event_count"`
		DoneEvents      int               `json:"done_event_count"`
		OrderedJSONData []json.RawMessage `json:"ordered_json_data"`
	}
	if err := json.Unmarshal(fallbackPayload, &fallback); err != nil {
		t.Fatalf("decode fallback JSON: %v", err)
	}
	if fallback.Representation != "bounded_sse_json_projection_v1" || fallback.CompleteEvents != 602 || fallback.JSONEvents != 601 || fallback.DoneEvents != 1 || len(fallback.OrderedJSONData) != fallback.JSONEvents {
		t.Fatalf("fallback projection = %#v", fallback)
	}
	fileCount := 0
	redactionMarkerSeen := false
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr == nil && !entry.IsDir() {
			fileCount++
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if bytes.Contains(raw, []byte(ordinaryRefreshToken)) {
				t.Fatalf("ordinary refresh_token reached CAS at %q", path)
			}
			redactionMarkerSeen = redactionMarkerSeen || bytes.Contains(raw, []byte(redaction.Replacement))
		}
		return walkErr
	}); err != nil {
		t.Fatal(err)
	}
	if fileCount > 12 {
		t.Fatalf("bounded SSE response created %d CAS files", fileCount)
	}
	if !redactionMarkerSeen {
		t.Fatal("bounded SSE fallback persisted no redaction marker")
	}
}

func TestRawDriverOpaqueContentUsesMetadataOnlyEvidence(t *testing.T) {
	const ordinaryRefreshToken = "ordinary-opaque-refresh-value-not-a-detector"
	invalidWire := "data: {\"refresh_token\":\"" + ordinaryRefreshToken + "\"}\n" + strings.Repeat("x: y\n", 1024) + "\n"
	tests := []struct {
		name               string
		streaming          bool
		response           string
		wantEvidenceKind   string
		wantRepresentation string
	}{
		{
			name: "non-JSON HTTP body", response: "refresh_token=" + ordinaryRefreshToken,
			wantEvidenceKind: "http_response_body_omitted", wantRepresentation: "opaque_content_omitted_v1",
		},
		{
			name: "non-JSON SSE data", streaming: true,
			response:         "data: refresh_token=" + ordinaryRefreshToken + "\n\ndata: [DONE]\n\n",
			wantEvidenceKind: "sse_non_json_data_omitted", wantRepresentation: "opaque_content_omitted_v1",
		},
		{
			name: "incomplete SSE tail", streaming: true,
			response:         "data: {\"id\":\"safe-complete-event\"}\n\ndata: {\"refresh_token\":\"" + ordinaryRefreshToken + "\"",
			wantEvidenceKind: "sse_incomplete_wire", wantRepresentation: "sse_wire_summary_v1",
		},
		{
			name: "invalid SSE wire", streaming: true, response: invalidWire,
			wantEvidenceKind: "sse_invalid_wire", wantRepresentation: "sse_wire_summary_v1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var handler http.Handler
			if test.streaming {
				handler = streamHandler(http.StatusOK, []byte(test.response))
			} else {
				handler = statusHandler(http.StatusOK, []byte(test.response))
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			check := rawdriver.CheckRequiredEnvelope
			if test.streaming {
				check = rawdriver.CheckTerminalEvent
			}
			scenario := scenarioFor(mutationCase{
				protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
				body: rawChatBody(t, test.streaming, false), stream: test.streaming, check: check,
			}, "opaque-content-"+strings.ReplaceAll(test.name, " ", "-"))
			outcome, root, _ := runScenario(t, server, scenario)
			if len(outcome.EvidenceRefs) < 3 {
				t.Fatalf("opaque response produced too few Evidence refs: %#v", outcome.EvidenceRefs)
			}
			store, err := cas.Open(root, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			foundSummary := false
			for _, ref := range outcome.EvidenceRefs {
				evidence, getErr := store.GetEvidence(context.Background(), ref)
				if getErr != nil {
					t.Fatal(getErr)
				}
				if evidence.EvidenceKind != test.wantEvidenceKind {
					continue
				}
				foundSummary = true
				payload, getErr := store.Get(context.Background(), evidence.PayloadRef.ContentDigest)
				if getErr != nil {
					t.Fatal(getErr)
				}
				if !bytes.Contains(payload, []byte(`"representation":"`+test.wantRepresentation+`"`)) {
					t.Fatalf("opaque Evidence payload is not an explicit metadata summary: %s", payload)
				}
			}
			if !foundSummary {
				t.Fatalf("opaque response omitted Evidence kind %q", test.wantEvidenceKind)
			}
			if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil || entry.IsDir() {
					return walkErr
				}
				raw, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				if bytes.Contains(raw, []byte(ordinaryRefreshToken)) {
					t.Fatalf("opaque refresh_token reached CAS at %q", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRawDriverCompactsMaxSizedTinyNonJSONSSEFallback(t *testing.T) {
	const event = "data:x\n\n"
	eventCount := (512 << 10) / len(event)
	body := bytes.Repeat([]byte(event), eventCount)
	server := httptest.NewServer(streamHandler(http.StatusUnauthorized, body))
	defer server.Close()
	scenario := scenarioFor(mutationCase{
		protocol: rawdriver.ProtocolOpenAIChat, path: "/v1/chat/completions",
		body: rawChatBody(t, true, false), stream: true, check: rawdriver.CheckTerminalEvent,
	}, "tiny-non-json-sse-fallback")
	runner, root, _ := newRunner(t, server.URL, scenario, 1<<20)
	estimate, err := runner.Estimate(schema.ScenarioDecision{ScenarioID: scenario.ID, Disposition: schema.DispositionExecute, Driver: scenario.Driver})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := runner.Run(context.Background(), invocationFor(t, scenario))
	typed := assertRunError(t, outcome, err, executor.ErrorAuthentication)
	if len(typed.EvidenceRefs) != 3 || typed.Usage.ArtifactBytes <= 0 || typed.Usage.ArtifactBytes > estimate.ArtifactBytes {
		t.Fatalf("tiny-event fallback evidence/budget = %d/%#v", len(typed.EvidenceRefs), typed.Usage)
	}
	store, err := cas.Open(root, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	fallbackEvidence, err := store.GetEvidence(context.Background(), typed.EvidenceRefs[2])
	if err != nil {
		t.Fatal(err)
	}
	if fallbackEvidence.EvidenceKind != "sse_event_limit_fallback" || fallbackEvidence.PayloadRef == nil {
		t.Fatalf("tiny-event fallback Evidence = %#v", fallbackEvidence)
	}
	payload, err := store.Get(context.Background(), fallbackEvidence.PayloadRef.ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) >= 1<<20 {
		t.Fatalf("tiny-event fallback expanded to %d bytes", len(payload))
	}
	var projection struct {
		CompleteEvents int               `json:"complete_event_count"`
		JSONEvents     int               `json:"json_event_count"`
		NonJSONOmitted int               `json:"non_json_data_omitted"`
		OrderedJSON    []json.RawMessage `json:"ordered_json_data"`
	}
	if err := json.Unmarshal(payload, &projection); err != nil {
		t.Fatal(err)
	}
	if projection.CompleteEvents != eventCount || projection.JSONEvents != 0 || projection.NonJSONOmitted != eventCount || len(projection.OrderedJSON) != 0 {
		t.Fatalf("tiny-event projection = %#v, want %d omitted events", projection, eventCount)
	}
	fileCount := 0
	if err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr == nil && !entry.IsDir() {
			fileCount++
		}
		return walkErr
	}); err != nil {
		t.Fatal(err)
	}
	if fileCount > 12 {
		t.Fatalf("tiny-event fallback created %d CAS files", fileCount)
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
	return newRunnerWithObservationLimit(t, origin, scenario, maxResponseBytes, 0)
}

func newRunnerWithObservationLimit(t *testing.T, origin string, scenario rawdriver.Scenario, maxResponseBytes int64, maxObservationBytes int) (*rawdriver.Runner, string, *rawdriver.MemoryRegistry) {
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
		Registry:            registry,
		Transport:           client,
		Store:               store,
		Redactor:            redactorInstance,
		MaxObservationBytes: maxObservationBytes,
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

func assertRunError(t *testing.T, outcome executor.Outcome, err error, class executor.ErrorClass) *executor.RunError {
	t.Helper()
	var typed *executor.RunError
	if !errors.As(err, &typed) || typed.Class != class {
		t.Fatalf("expected %s RunError, got %#v / %v", class, typed, err)
	}
	if outcome.Verdict != "" || len(outcome.Findings) != 0 || len(outcome.AssertionResults) != 0 {
		t.Fatalf("non-target error gained endpoint result: %#v", outcome)
	}
	return typed
}

func statusHandler(status int, body []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	})
}

func streamHandler(status int, body []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	})
}

func assertOutputLimitInconclusive(t *testing.T, outcome executor.Outcome, reason schema.ReasonCode, field string) {
	t.Helper()
	if outcome.Verdict != schema.VerdictInconclusive || outcome.ReasonCode != reason || len(outcome.Findings) != 0 || len(outcome.AssertionResults) != 1 {
		t.Fatalf("output-limit prerequisite = %#v", outcome)
	}
	assertion := outcome.AssertionResults[0]
	if assertion.Verdict != schema.VerdictInconclusive || assertion.ReasonCode != reason {
		t.Fatalf("output-limit assertion = %#v", assertion)
	}
	observed, ok := assertion.Observed.(map[string]any)
	if !ok || observed["request_field"] != field {
		t.Fatalf("output-limit field missing from observed prerequisite: %#v", assertion.Observed)
	}
}

func limitedResponsesDocument(reason string) []byte {
	value := map[string]any{
		"id": "resp_limited", "object": "response", "created_at": 1700000000,
		"status": "incomplete", "model": "fixture-model", "output": []any{},
		"incomplete_details": map[string]any{"reason": reason},
		"usage":              map[string]any{"input_tokens": 4, "output_tokens": 64, "total_tokens": 68},
	}
	result, _ := json.Marshal(value)
	return result
}

func removeJSONField(t *testing.T, raw json.RawMessage, field string) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	delete(value, field)
	return mustRawJSON(t, value)
}

func validChatResponse() []byte {
	return []byte(`{"id":"chatcmpl_test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
}

func rawChatBody(t *testing.T, stream, tool bool) json.RawMessage {
	t.Helper()
	value := map[string]any{
		"model": "fixture-model", "messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": stream,
		"max_completion_tokens": 64,
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
	value := map[string]any{"model": "fixture-model", "input": "hello", "stream": stream, "max_output_tokens": 64}
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
