package e2e_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
	synthetictools "github.com/whyiug/agentapi-doctor/reference/synthetic-tools"
)

type fixtureCase struct {
	name     string
	path     string
	body     []byte
	stream   bool
	tool     bool
	protocol referenceserver.Protocol
	headers  map[string]string
}

func fixtureCases(t *testing.T) []fixtureCase {
	t.Helper()
	result := make([]fixtureCase, 0, 12)
	for _, stream := range []bool{false, true} {
		for _, tool := range []bool{false, true} {
			suffix := "text"
			if tool {
				suffix = "tool"
			}
			mode := "json"
			if stream {
				mode = "sse"
			}
			result = append(result,
				fixtureCase{
					name: "chat-" + suffix + "-" + mode, path: "/v1/chat/completions",
					body: chatBody(t, stream, tool), stream: stream, tool: tool, protocol: referenceserver.ProtocolOpenAIChat,
				},
				fixtureCase{
					name: "responses-" + suffix + "-" + mode, path: "/v1/responses",
					body: responsesBody(t, stream, tool), stream: stream, tool: tool, protocol: referenceserver.ProtocolOpenAIResponses,
				},
				fixtureCase{
					name: "anthropic-" + suffix + "-" + mode, path: "/v1/messages",
					body: anthropicBody(t, stream, tool), stream: stream, tool: tool, protocol: referenceserver.ProtocolAnthropic,
					headers: map[string]string{"anthropic-version": "2023-06-01"},
				},
			)
		}
	}
	return result
}

func chatBody(t *testing.T, stream, tool bool) []byte {
	t.Helper()
	request := map[string]any{
		"model": "synthetic-model", "messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": stream,
	}
	if tool {
		request["tools"] = []any{synthetictools.OpenAIDefinition()}
	}
	return mustJSON(t, request)
}

func responsesBody(t *testing.T, stream, tool bool) []byte {
	t.Helper()
	request := map[string]any{"model": "synthetic-model", "input": "hello", "stream": stream}
	if tool {
		request["tools"] = []any{map[string]any{"type": "function", "name": synthetictools.EchoName}}
	}
	return mustJSON(t, request)
}

func anthropicBody(t *testing.T, stream, tool bool) []byte {
	t.Helper()
	request := map[string]any{
		"model": "synthetic-model", "messages": []any{map[string]any{"role": "user", "content": "hello"}},
		"max_tokens": 64, "stream": stream,
	}
	if tool {
		request["tools"] = []any{synthetictools.AnthropicDefinition()}
	}
	return mustJSON(t, request)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func perform(t *testing.T, transformer referenceserver.Transformer, fixture fixtureCase) *httptest.ResponseRecorder {
	t.Helper()
	handler, err := referenceserver.New(referenceserver.Config{Transformer: transformer, MaxBodyBytes: 32 << 10, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, fixture.path, bytes.NewReader(fixture.body))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	for name, value := range fixture.headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestReferenceServerIsDeterministicAcrossProtocolsModesAndTools(t *testing.T) {
	for _, fixture := range fixtureCases(t) {
		t.Run(fixture.name, func(t *testing.T) {
			first := perform(t, nil, fixture)
			second := perform(t, nil, fixture)
			if first.Code != http.StatusOK || second.Code != http.StatusOK {
				t.Fatalf("reference status first=%d second=%d bodies=%s / %s", first.Code, second.Code, first.Body.String(), second.Body.String())
			}
			if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
				t.Fatalf("reference output is nondeterministic\nfirst: %s\nsecond:%s", first.Body, second.Body)
			}
			if first.Header().Get("X-AgentAPI-Fixture") != "non-authoritative-synthetic" {
				t.Fatal("fixture did not disclose its non-authoritative status")
			}
			if !bytes.Contains(first.Body.Bytes(), []byte(`"usage"`)) {
				t.Fatalf("usage missing: %s", first.Body.String())
			}
			if fixture.tool && !bytes.Contains(first.Body.Bytes(), []byte(synthetictools.CallID)) {
				t.Fatalf("tool call missing: %s", first.Body.String())
			}
			if fixture.stream {
				if !utf8.Valid(first.Body.Bytes()) {
					t.Fatal("reference SSE is not valid UTF-8")
				}
				assertOneTerminal(t, fixture.protocol, first.Body.String())
			} else {
				var document map[string]any
				if err := json.Unmarshal(first.Body.Bytes(), &document); err != nil {
					t.Fatalf("invalid reference JSON: %v", err)
				}
				if fixture.tool {
					assertNativeArgumentType(t, fixture.protocol, document)
				}
			}
		})
	}
}

func assertOneTerminal(t *testing.T, protocol referenceserver.Protocol, body string) {
	t.Helper()
	marker := ""
	switch protocol {
	case referenceserver.ProtocolOpenAIChat:
		marker = "data: [DONE]"
	case referenceserver.ProtocolOpenAIResponses:
		marker = "event: response.completed"
	case referenceserver.ProtocolAnthropic:
		marker = "event: message_stop"
	}
	if count := strings.Count(body, marker); count != 1 {
		t.Fatalf("want one terminal %q, got %d: %s", marker, count, body)
	}
}

func assertNativeArgumentType(t *testing.T, protocol referenceserver.Protocol, document map[string]any) {
	t.Helper()
	switch protocol {
	case referenceserver.ProtocolOpenAIChat:
		choice := document["choices"].([]any)[0].(map[string]any)
		message := choice["message"].(map[string]any)
		call := message["tool_calls"].([]any)[0].(map[string]any)
		if _, ok := call["function"].(map[string]any)["arguments"].(string); !ok {
			t.Fatal("Chat arguments must be a JSON string in the reference interpretation")
		}
	case referenceserver.ProtocolOpenAIResponses:
		call := document["output"].([]any)[0].(map[string]any)
		if _, ok := call["arguments"].(string); !ok {
			t.Fatal("Responses arguments must be a JSON string in the reference interpretation")
		}
	case referenceserver.ProtocolAnthropic:
		call := document["content"].([]any)[0].(map[string]any)
		if _, ok := call["input"].(map[string]any); !ok {
			t.Fatal("Anthropic tool input must remain an object in the reference interpretation")
		}
	}
}

func TestReferenceServerRejectsSecretsAmbiguousBodiesAndExcess(t *testing.T) {
	handler, err := referenceserver.New(referenceserver.Config{MaxBodyBytes: 128, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		body        []byte
		contentType string
		auth        string
		want        int
	}{
		{name: "non-fixture credential", body: chatBody(t, false, false), contentType: "application/json", auth: "Bearer definitely-not-the-synthetic-token", want: http.StatusBadRequest},
		{name: "wrong content type", body: chatBody(t, false, false), contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "duplicate key", body: []byte(`{"model":"a","model":"b","messages":[{}]}`), contentType: "application/json", want: http.StatusBadRequest},
		{name: "unknown field", body: []byte(`{"model":"a","messages":[{}],"endpoint_url":"http://invalid.invalid"}`), contentType: "application/json", want: http.StatusBadRequest},
		{name: "body limit", body: []byte(`{"model":"` + strings.Repeat("x", 256) + `","messages":[{}]}`), contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			if test.auth != "" {
				request.Header.Set("Authorization", test.auth)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("want %d got %d: %s", test.want, response.Code, response.Body.String())
			}
			for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-AgentAPI-Fixture"} {
				if response.Header().Get(header) == "" {
					t.Errorf("missing header %s", header)
				}
			}
		})
	}
	if _, err := referenceserver.New(referenceserver.Config{MaxBodyBytes: -1}); err == nil {
		t.Fatal("accepted invalid body limit")
	}
}

type slowFixtureTransformer struct{}

func (slowFixtureTransformer) ID() string { return "synthetic-slow-transformer" }
func (slowFixtureTransformer) Apply(*referenceserver.Exchange) error {
	// Windows timer resolution can exceed a few milliseconds. Keep this delay
	// well beyond that resolution so the deadline assertion is deterministic on
	// every supported runner.
	time.Sleep(100 * time.Millisecond)
	return nil
}

func TestReferenceServerEnforcesRequestDeadlineAndCanonicalRoute(t *testing.T) {
	handler, err := referenceserver.New(referenceserver.Config{
		MaxBodyBytes:   32 << 10,
		RequestTimeout: time.Millisecond,
		Transformer:    slowFixtureTransformer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, false, false)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("want request timeout, got %d: %s", response.Code, response.Body.String())
	}

	handler, err = referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions?endpoint=http://invalid.invalid", bytes.NewReader(chatBody(t, false, false)))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "canonical_path_without_query_required") {
		t.Fatalf("query-bearing fixture route accepted: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMutationCatalogAndSinglePrimaryComposition(t *testing.T) {
	want := []mutantserver.ID{
		mutantserver.ArgumentsObjectInsteadOfString,
		mutantserver.MissingOutputIndex,
		mutantserver.DuplicateOutputIndex,
		mutantserver.DroppedStreamingToolCall,
		mutantserver.InvalidFinishReason,
		mutantserver.MissingTerminalEvent,
		mutantserver.DuplicateTerminalEvent,
		mutantserver.ToolCallIDChanged,
		mutantserver.UnknownEventCrashesClient,
		mutantserver.UnclosedReasoningBlock,
		mutantserver.UsageInconsistent,
		mutantserver.TruncatedUTF8,
	}
	catalog := mutantserver.Catalog()
	if len(catalog) != len(want) {
		t.Fatalf("want %d mutations, got %d", len(want), len(catalog))
	}
	for index, id := range want {
		if catalog[index].ID != id || catalog[index].Description == "" || len(catalog[index].Protocols) == 0 {
			t.Fatalf("unstable catalog entry %d: %#v", index, catalog[index])
		}
	}
	first, _ := mutantserver.Mutation(want[0])
	second, _ := mutantserver.Mutation(want[1])
	if _, err := mutantserver.Compose(first, second); err == nil {
		t.Fatal("composed two primary faults")
	}
	annotation, err := mutantserver.Annotation("test-annotation", "X-Fixture-Annotation", "present")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutantserver.Compose(first, annotation); err != nil {
		t.Fatalf("one primary plus non-fault decorator should compose: %v", err)
	}
}

func TestEveryMutantChangesItsTargetStructure(t *testing.T) {
	tests := []struct {
		id      mutantserver.ID
		fixture fixtureCase
		assert  func(*testing.T, []byte, []byte)
	}{
		{mutantserver.ArgumentsObjectInsteadOfString, caseByName(t, "chat-tool-json"), contains(`"arguments":{"text":"fixture"}`)},
		{mutantserver.MissingOutputIndex, caseByName(t, "responses-text-sse"), fewer(`"output_index"`)},
		{mutantserver.DuplicateOutputIndex, caseByName(t, "responses-text-sse"), contains("item_duplicate_index")},
		{mutantserver.DroppedStreamingToolCall, caseByName(t, "chat-tool-sse"), absent(`"delta":{"tool_calls"`)},
		{mutantserver.InvalidFinishReason, caseByName(t, "chat-text-json"), contains("fixture_invalid_reason")},
		{mutantserver.MissingTerminalEvent, caseByName(t, "chat-text-sse"), countIs("data: [DONE]", 0)},
		{mutantserver.DuplicateTerminalEvent, caseByName(t, "chat-text-sse"), countIs("data: [DONE]", 2)},
		{mutantserver.ToolCallIDChanged, caseByName(t, "chat-tool-sse"), contains("call_mutated_0001")},
		{mutantserver.UnknownEventCrashesClient, caseByName(t, "anthropic-text-sse"), contains("fixture.unknown")},
		{mutantserver.UnclosedReasoningBlock, caseByName(t, "responses-text-sse"), contains("item_reasoning_open")},
		{mutantserver.UsageInconsistent, caseByName(t, "responses-text-json"), contains(`"total_tokens":1`)},
		{mutantserver.TruncatedUTF8, caseByName(t, "anthropic-text-sse"), func(t *testing.T, _, mutated []byte) {
			if utf8.Valid(mutated) {
				t.Fatal("truncated-utf8 mutant remained valid UTF-8")
			}
		}},
	}
	for _, test := range tests {
		t.Run(string(test.id), func(t *testing.T) {
			reference := perform(t, nil, test.fixture)
			plan, err := mutantserver.New(test.id)
			if err != nil {
				t.Fatal(err)
			}
			mutated := perform(t, plan, test.fixture)
			if reference.Code != http.StatusOK || mutated.Code != http.StatusOK {
				t.Fatalf("reference=%d mutant=%d mutant-body=%s", reference.Code, mutated.Code, mutated.Body.String())
			}
			if bytes.Equal(reference.Body.Bytes(), mutated.Body.Bytes()) {
				t.Fatal("mutant did not change wire output")
			}
			if mutated.Header().Get("X-AgentAPI-Mutant") != string(test.id) {
				t.Fatalf("missing stable mutant ID header: %q", mutated.Header().Get("X-AgentAPI-Mutant"))
			}
			test.assert(t, reference.Body.Bytes(), mutated.Body.Bytes())
		})
	}
}

func caseByName(t *testing.T, name string) fixtureCase {
	t.Helper()
	for _, fixture := range fixtureCases(t) {
		if fixture.name == name {
			return fixture
		}
	}
	t.Fatalf("fixture %s not found", name)
	return fixtureCase{}
}

func contains(fragment string) func(*testing.T, []byte, []byte) {
	return func(t *testing.T, _, mutated []byte) {
		t.Helper()
		if !bytes.Contains(mutated, []byte(fragment)) {
			t.Fatalf("mutant missing %q: %s", fragment, mutated)
		}
	}
}

func absent(fragment string) func(*testing.T, []byte, []byte) {
	return func(t *testing.T, _, mutated []byte) {
		t.Helper()
		if bytes.Contains(mutated, []byte(fragment)) {
			t.Fatalf("mutant retained %q: %s", fragment, mutated)
		}
	}
}

func fewer(fragment string) func(*testing.T, []byte, []byte) {
	return func(t *testing.T, reference, mutated []byte) {
		t.Helper()
		if bytes.Count(mutated, []byte(fragment)) >= bytes.Count(reference, []byte(fragment)) {
			t.Fatalf("mutant did not remove %q", fragment)
		}
	}
}

func countIs(fragment string, count int) func(*testing.T, []byte, []byte) {
	return func(t *testing.T, _, mutated []byte) {
		t.Helper()
		if got := bytes.Count(mutated, []byte(fragment)); got != count {
			t.Fatalf("want %d occurrences of %q, got %d", count, fragment, got)
		}
	}
}

func TestSyntheticToolIsInertAndDeterministic(t *testing.T) {
	call := synthetictools.NewCall("")
	first, err := synthetictools.Execute(call)
	if err != nil {
		t.Fatal(err)
	}
	second, err := synthetictools.Execute(call)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustJSON(t, first), mustJSON(t, second)) || first["echo"] != "fixture" {
		t.Fatalf("synthetic tool is not deterministic: %#v / %#v", first, second)
	}
}
