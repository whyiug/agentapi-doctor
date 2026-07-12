package rawdriver

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/whyiug/agentapi-doctor/internal/normalizer"
	"github.com/whyiug/agentapi-doctor/internal/oracle"
	"github.com/whyiug/agentapi-doctor/internal/recorder"
	"github.com/whyiug/agentapi-doctor/internal/statemachine"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type observedUsage struct {
	Input     int64
	Output    int64
	Total     int64
	HasInput  bool
	HasOutput bool
	HasTotal  bool
}

type exchangeFacts struct {
	validUTF8       bool
	framingComplete bool
	terminalCount   int
	postTerminal    int
	unknownCount    int
	toolCallCount   int
	argumentTypes   []string
	finishReasons   []string
	usage           observedUsage
	stateEvents     []statemachine.Event
	documents       []json.RawMessage
	items           []schema.IRItem
	parseOutcomes   []oracle.Outcome
	responseObjects []map[string]any
}

type evaluation struct {
	Outcome oracle.Outcome
	Usage   observedUsage
}

func evaluate(scenario Scenario, status int, headers http.Header, body []byte, refs []schema.ObjectRef) (evaluation, error) {
	statusOutcome := observedPass(refs)
	if status != scenario.ExpectedStatus {
		statusOutcome = observedFail(refs, "unexpected_http_status", scenario.ExpectedStatus, status)
	}
	contentTypeOutcome := checkContentType(scenario.Streaming, headers, refs)

	var (
		facts exchangeFacts
		err   error
	)
	if scenario.Streaming {
		facts, err = parseStream(scenario, body, refs)
	} else {
		facts, err = parseJSONResponse(scenario, body, refs)
	}
	if err != nil {
		return evaluation{}, err
	}

	checkOutcome := checkScenario(scenario, facts, refs)
	stateOutcome := func() oracle.Outcome {
		return oracle.EvaluateStateMachine(oracle.Input[[]statemachine.Event]{
			Value: facts.stateEvents, EvidenceRefs: refs, Complete: true,
		})
	}
	// The new product scenarios each emit one AssertionResult and therefore
	// only combine prerequisites/oracles that belong to that catalog meaning.
	// This avoids attributing, for example, a terminal mutation to the separate
	// stream-media-type requirement merely because both used one response.
	var outcomes []oracle.Outcome
	switch scenario.Assertion.Check {
	case CheckStreamMediaType:
		outcomes = []oracle.Outcome{statusOutcome, contentTypeOutcome, checkOutcome}
	case CheckRequiredEnvelope:
		outcomes = []oracle.Outcome{statusOutcome, contentTypeOutcome}
		outcomes = append(outcomes, facts.parseOutcomes...)
		outcomes = append(outcomes, checkOutcome)
	case CheckTerminalEvent:
		outcomes = []oracle.Outcome{statusOutcome, contentTypeOutcome}
		outcomes = append(outcomes, facts.parseOutcomes...)
		outcomes = append(outcomes, checkOutcome, stateOutcome())
	case CheckNoPostTerminal:
		outcomes = []oracle.Outcome{statusOutcome, contentTypeOutcome, checkOutcome}
	default:
		outcomes = []oracle.Outcome{statusOutcome, contentTypeOutcome, checkOutcome}
		if scenario.Streaming {
			outcomes = append(outcomes, stateOutcome())
		}
		outcomes = append(outcomes, facts.parseOutcomes...)
		if len(facts.items) > 0 {
			outcomes = append(outcomes, oracle.EvaluateRelations(oracle.Input[[]schema.IRItem]{
				Value: facts.items, EvidenceRefs: refs, Complete: true,
			}))
		} else {
			outcomes = append(outcomes, observedFail(refs, "empty_normalized_interaction", "at least one valid response document", "none"))
		}
	}
	return evaluation{Outcome: combineOutcomes(refs, outcomes...), Usage: facts.usage}, nil
}

func parseJSONResponse(scenario Scenario, body []byte, refs []schema.ObjectRef) (exchangeFacts, error) {
	facts := exchangeFacts{validUTF8: utf8.Valid(body), framingComplete: true}
	raw := json.RawMessage(slices.Clone(body))
	facts.documents = append(facts.documents, raw)
	facts.parseOutcomes = append(facts.parseOutcomes, oracle.EvaluateSchema(oracle.Input[json.RawMessage]{
		Value: raw, EvidenceRefs: refs, Complete: true,
	}, objectSchema()))
	if !json.Valid(raw) {
		return facts, nil
	}
	item, err := normalizer.Normalize(normalizer.Request{
		ItemID:         "response-document",
		IRType:         schema.IRMessage,
		SourceProtocol: string(scenario.Protocol),
		InteractionID:  scenario.ID,
		NativeValue:    raw,
		EvidenceRefs:   refs,
		Transform:      normalizer.TransformIdentity,
		Version:        "1.0.0",
	})
	if err != nil {
		return exchangeFacts{}, fmt.Errorf("normalize JSON response: %w", err)
	}
	facts.items = append(facts.items, item)
	value, err := decodeObject(raw)
	if err != nil {
		return exchangeFacts{}, fmt.Errorf("decode validated JSON response: %w", err)
	}
	facts.responseObjects = append(facts.responseObjects, value)
	inspectNonStream(scenario.Protocol, value, &facts)
	return facts, nil
}

func parseStream(scenario Scenario, body []byte, refs []schema.ObjectRef) (exchangeFacts, error) {
	facts := exchangeFacts{validUTF8: utf8.Valid(body), framingComplete: true}
	if len(body) == 0 {
		facts.framingComplete = false
		return facts, nil
	}
	assembler := recorder.NewSSEAssembler(max(len(body)+1, 1024))
	events, err := assembler.Feed(recorder.ReadChunk{Sequence: 1, ByteOffset: 0, Data: body})
	if err != nil {
		// The complete bounded HTTP body is target evidence. Invalid event framing
		// is reported as a wire failure, not promoted to a harness error.
		facts.parseOutcomes = append(facts.parseOutcomes, observedFail(refs, "invalid_sse_framing", "bounded logical SSE events", "invalid framing"))
		return facts, nil
	}
	tail := assembler.Finish()
	if tail.BufferedBytes != 0 || tail.PendingFieldCount != 0 {
		facts.framingComplete = false
		facts.parseOutcomes = append(facts.parseOutcomes, observedFail(refs, "incomplete_sse_event", "blank-line terminated logical event", "trailing partial event"))
	}
	state := newStreamDecoder(scenario.Protocol)
	terminalSeen := false
	for index, event := range events {
		if terminalSeen && event.Data != "" {
			facts.postTerminal++
		}
		state.consume(event, &facts)
		if isTerminalEvent(scenario.Protocol, event) {
			terminalSeen = true
		}
		if event.Data == "[DONE]" {
			continue
		}
		raw := json.RawMessage([]byte(event.Data))
		facts.documents = append(facts.documents, slices.Clone(raw))
		outcome := oracle.EvaluateSchema(oracle.Input[json.RawMessage]{
			Value: raw, EvidenceRefs: refs, Complete: true,
		}, objectSchema())
		facts.parseOutcomes = append(facts.parseOutcomes, outcome)
		if !json.Valid(raw) {
			continue
		}
		item, normalizeErr := normalizer.Normalize(normalizer.Request{
			ItemID:         fmt.Sprintf("event-%06d", index+1),
			IRType:         schema.IRLifecycleEvent,
			SourceProtocol: string(scenario.Protocol),
			InteractionID:  scenario.ID,
			NativeValue:    raw,
			EvidenceRefs:   refs,
			Transform:      normalizer.TransformIdentity,
			Version:        "1.0.0",
		})
		if normalizeErr != nil {
			return exchangeFacts{}, fmt.Errorf("normalize SSE event %d: %w", index+1, normalizeErr)
		}
		facts.items = append(facts.items, item)
	}
	facts.stateEvents = state.events
	return facts, nil
}

func objectSchema() oracle.Schema {
	return oracle.Schema{Types: []oracle.JSONType{oracle.TypeObject}, AllowUnknown: true}
}

func checkContentType(streaming bool, headers http.Header, refs []schema.ObjectRef) oracle.Outcome {
	expected := "application/json"
	if streaming {
		expected = "text/event-stream"
	}
	actual, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || actual != expected {
		return observedFail(refs, "unexpected_content_type", expected, headers.Get("Content-Type"))
	}
	return observedPass(refs)
}

func checkScenario(scenario Scenario, facts exchangeFacts, refs []schema.ObjectRef) oracle.Outcome {
	switch scenario.Assertion.Check {
	case CheckArgumentsString:
		if len(facts.argumentTypes) == 0 {
			return observedFail(refs, "tool_arguments_not_observed", "JSON-encoded string arguments", "none")
		}
		for _, actual := range facts.argumentTypes {
			if actual != "string" {
				return observedFail(refs, "tool_arguments_wrong_type", "string", actual)
			}
		}
	case CheckStreamingToolCall:
		if facts.toolCallCount == 0 {
			return observedFail(refs, "streaming_tool_call_missing", "at least one streamed tool call", "none")
		}
	case CheckFinishReason:
		if len(facts.finishReasons) == 0 {
			return observedFail(refs, "finish_reason_missing", scenario.Assertion.AllowedValues, "none")
		}
		for _, reason := range facts.finishReasons {
			if !slices.Contains(scenario.Assertion.AllowedValues, reason) {
				return observedFail(refs, "finish_reason_invalid", scenario.Assertion.AllowedValues, reason)
			}
		}
	case CheckTerminalEvent:
		if facts.terminalCount != 1 || !facts.framingComplete {
			return observedFail(refs, "terminal_event_count", 1, facts.terminalCount)
		}
	case CheckNoUnknownEvent:
		if facts.unknownCount != 0 {
			return observedFail(refs, "unexpected_fixture_event", 0, facts.unknownCount)
		}
	case CheckUsageConsistent:
		return checkUsage(scenario.Assertion.ExpectedUsage, facts.usage, refs)
	case CheckValidUTF8:
		if !facts.validUTF8 {
			return observedFail(refs, "invalid_utf8", "valid UTF-8 stream bytes", "truncated code point")
		}
	case CheckRequiredEnvelope:
		return checkRequiredEnvelope(scenario.Protocol, facts.responseObjects, refs)
	case CheckStreamMediaType:
		// checkContentType is always evaluated before this scenario-specific
		// marker. Keeping the marker explicit makes the catalog mapping exact.
	case CheckNoPostTerminal:
		if facts.terminalCount == 0 {
			return oracle.Outcome{
				Verdict: schema.VerdictInconclusive, ReasonCode: schema.ReasonNotObserved,
				Code: "terminal_not_observed", EvidenceRefs: slices.Clone(refs),
			}
		}
		if facts.postTerminal != 0 {
			return observedFail(refs, "semantic_data_after_terminal", 0, facts.postTerminal)
		}
	case CheckOutputIndexes, CheckStableToolCallID, CheckClosedReasoning:
		// The typed state-machine oracle below is authoritative for these checks.
	default:
		return oracle.Outcome{Verdict: schema.VerdictInconclusive, ReasonCode: schema.ReasonHarnessError, Code: "unsupported_registered_check", EvidenceRefs: slices.Clone(refs)}
	}
	return observedPass(refs)
}

func checkRequiredEnvelope(protocol Protocol, documents []map[string]any, refs []schema.ObjectRef) oracle.Outcome {
	if len(documents) != 1 || documents[0] == nil {
		return observedFail(refs, "required_response_envelope_missing", "one response object", len(documents))
	}
	value := documents[0]
	requiredString := func(name string) bool {
		text, ok := stringValue(value[name])
		return ok && text != ""
	}
	requiredArray := func(name string) bool {
		_, ok := value[name].([]any)
		return ok
	}
	requiredObject := func(name string) bool {
		_, ok := value[name].(map[string]any)
		return ok
	}
	valid := false
	switch protocol {
	case ProtocolOpenAIChat:
		_, created := integerValue(value["created"])
		valid = requiredString("id") && value["object"] == "chat.completion" && created && requiredString("model") && requiredArray("choices")
	case ProtocolOpenAIResponses:
		_, created := integerValue(value["created_at"])
		valid = requiredString("id") && value["object"] == "response" && created && requiredString("status") && requiredString("model") && requiredArray("output")
	case ProtocolAnthropic:
		valid = requiredString("id") && value["type"] == "message" && value["role"] == "assistant" && requiredString("model") && requiredArray("content") && requiredObject("usage")
	}
	if !valid {
		return observedFail(refs, "required_response_envelope_missing", "documented protocol envelope", "one or more required fields are absent or invalid")
	}
	return observedPass(refs)
}

func isTerminalEvent(protocol Protocol, event recorder.SSELogicalEvent) bool {
	if protocol == ProtocolOpenAIChat {
		return event.Data == "[DONE]"
	}
	if event.Event == "message_stop" && protocol == ProtocolAnthropic {
		return true
	}
	if protocol != ProtocolOpenAIResponses || event.Data == "[DONE]" {
		return false
	}
	value, err := decodeObject([]byte(event.Data))
	if err != nil {
		return false
	}
	typeName, _ := stringValue(value["type"])
	return typeName == "response.completed" || typeName == "response.failed" || typeName == "response.incomplete"
}

func checkUsage(expected *TokenUsage, actual observedUsage, refs []schema.ObjectRef) oracle.Outcome {
	if expected == nil {
		return oracle.Outcome{Verdict: schema.VerdictInconclusive, ReasonCode: schema.ReasonHarnessError, Code: "missing_usage_expectation", EvidenceRefs: slices.Clone(refs)}
	}
	expectedMap := map[string]any{"input": expected.Input, "output": expected.Output}
	observedMap := map[string]any{"input_observed": actual.HasInput, "input": actual.Input, "output_observed": actual.HasOutput, "output": actual.Output}
	if !actual.HasInput || !actual.HasOutput || actual.Input != expected.Input || actual.Output != expected.Output {
		return observedFail(refs, "usage_mismatch", expectedMap, observedMap)
	}
	if expected.Total != nil {
		expectedMap["total"] = *expected.Total
		observedMap["total_observed"] = actual.HasTotal
		observedMap["total"] = actual.Total
		if !actual.HasTotal || actual.Total != *expected.Total || actual.Total != actual.Input+actual.Output {
			return observedFail(refs, "usage_inconsistent", expectedMap, observedMap)
		}
	}
	return observedPass(refs)
}

func combineOutcomes(refs []schema.ObjectRef, outcomes ...oracle.Outcome) oracle.Outcome {
	for _, outcome := range outcomes {
		if outcome.TargetFailure {
			return outcome
		}
	}
	for _, outcome := range outcomes {
		if outcome.Verdict == schema.VerdictInconclusive || outcome.Verdict == schema.VerdictWarn {
			return outcome
		}
	}
	return observedPass(refs)
}

func observedPass(refs []schema.ObjectRef) oracle.Outcome {
	return oracle.Outcome{Verdict: schema.VerdictPass, Code: "assertion_satisfied", EvidenceRefs: slices.Clone(refs)}
}

func observedFail(refs []schema.ObjectRef, code string, expected, observed any) oracle.Outcome {
	return oracle.Outcome{
		Verdict: schema.VerdictFail, Code: code, Expected: expected, Observed: observed,
		EvidenceRefs: slices.Clone(refs), TargetFailure: true,
	}
}

func inspectNonStream(protocol Protocol, value map[string]any, facts *exchangeFacts) {
	switch protocol {
	case ProtocolOpenAIChat:
		choice := firstObject(value["choices"])
		message := objectValue(choice["message"])
		for _, call := range arrayValue(message["tool_calls"]) {
			facts.toolCallCount++
			function := objectValue(objectValue(call)["function"])
			facts.argumentTypes = append(facts.argumentTypes, jsonType(function["arguments"]))
		}
		if reason, ok := stringValue(choice["finish_reason"]); ok {
			facts.finishReasons = append(facts.finishReasons, reason)
		}
		readUsage(objectValue(value["usage"]), "prompt_tokens", "completion_tokens", "total_tokens", &facts.usage)
	case ProtocolOpenAIResponses:
		for _, itemValue := range arrayValue(value["output"]) {
			item := objectValue(itemValue)
			if item["type"] == "function_call" {
				facts.toolCallCount++
				facts.argumentTypes = append(facts.argumentTypes, jsonType(item["arguments"]))
			}
		}
		if reason, ok := stringValue(value["status"]); ok {
			facts.finishReasons = append(facts.finishReasons, reason)
		}
		readUsage(objectValue(value["usage"]), "input_tokens", "output_tokens", "total_tokens", &facts.usage)
	case ProtocolAnthropic:
		for _, contentValue := range arrayValue(value["content"]) {
			content := objectValue(contentValue)
			if content["type"] == "tool_use" {
				facts.toolCallCount++
			}
		}
		if reason, ok := stringValue(value["stop_reason"]); ok {
			facts.finishReasons = append(facts.finishReasons, reason)
		}
		readUsage(objectValue(value["usage"]), "input_tokens", "output_tokens", "", &facts.usage)
	}
}

func readUsage(value map[string]any, inputName, outputName, totalName string, usage *observedUsage) {
	if input, ok := integerValue(value[inputName]); ok {
		usage.Input, usage.HasInput = input, true
	}
	if output, ok := integerValue(value[outputName]); ok {
		usage.Output, usage.HasOutput = output, true
	}
	if totalName != "" {
		if total, ok := integerValue(value[totalName]); ok {
			usage.Total, usage.HasTotal = total, true
		}
	}
}

func decodeObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func objectValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func arrayValue(value any) []any {
	result, _ := value.([]any)
	return result
}

func firstObject(value any) map[string]any {
	values := arrayValue(value)
	if len(values) == 0 {
		return nil
	}
	return objectValue(values[0])
}

func stringValue(value any) (string, bool) {
	result, ok := value.(string)
	return result, ok
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil && result >= 0
	case float64:
		result := int64(typed)
		return result, typed >= 0 && float64(result) == typed
	case int:
		return int64(typed), typed >= 0
	case int64:
		return typed, typed >= 0
	default:
		return 0, false
	}
}

func indexValue(value any) int {
	result, ok := integerValue(value)
	if !ok || result > int64(^uint(0)>>1) {
		return -1
	}
	return int(result)
}

func jsonType(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case json.Number, float64, int, int64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

type toolLifecycle struct {
	itemID    string
	callID    string
	arguments string
}

type streamDecoder struct {
	protocol       Protocol
	events         []statemachine.Event
	chatCreated    bool
	chatTools      map[int]*toolLifecycle
	anthropicItems map[int]*toolLifecycle
}

func newStreamDecoder(protocol Protocol) *streamDecoder {
	return &streamDecoder{protocol: protocol, chatTools: make(map[int]*toolLifecycle), anthropicItems: make(map[int]*toolLifecycle)}
}

func (decoder *streamDecoder) append(event statemachine.Event) {
	event.Sequence = uint64(len(decoder.events) + 1)
	decoder.events = append(decoder.events, event)
}

func (decoder *streamDecoder) consume(event recorder.SSELogicalEvent, facts *exchangeFacts) {
	if event.Data == "[DONE]" {
		facts.terminalCount++
		decoder.ensureChatCreated()
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCompleted})
		return
	}
	value, err := decodeObject([]byte(event.Data))
	if err != nil {
		return
	}
	typeName, _ := stringValue(value["type"])
	if event.Event == "fixture.unknown" || typeName == "fixture.unknown" {
		facts.unknownCount++
	}
	switch decoder.protocol {
	case ProtocolOpenAIResponses:
		decoder.consumeResponses(value, typeName, facts)
	case ProtocolOpenAIChat:
		decoder.consumeChat(value, facts)
	case ProtocolAnthropic:
		decoder.consumeAnthropic(event.Event, value, facts)
	}
}

func (decoder *streamDecoder) ensureChatCreated() {
	if !decoder.chatCreated {
		decoder.chatCreated = true
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCreated})
	}
}

func (decoder *streamDecoder) consumeResponses(value map[string]any, typeName string, facts *exchangeFacts) {
	switch typeName {
	case "response.created":
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCreated})
	case "response.in_progress":
		decoder.append(statemachine.Event{Type: statemachine.EventResponseInProgress})
	case "response.output_item.added":
		item := objectValue(value["item"])
		itemID, _ := stringValue(item["id"])
		itemKind, _ := stringValue(item["type"])
		callID, _ := stringValue(item["call_id"])
		decoder.append(statemachine.Event{Type: statemachine.EventOutputItemAdded, ItemID: itemID, ItemKind: itemKind, OutputIndex: indexValue(value["output_index"]), CallID: callID})
		if itemKind == "function_call" {
			facts.toolCallCount++
			if _, exists := item["arguments"]; exists {
				facts.argumentTypes = append(facts.argumentTypes, jsonType(item["arguments"]))
			}
		}
	case "response.function_call_arguments.delta":
		itemID, _ := stringValue(value["item_id"])
		callID, _ := stringValue(value["call_id"])
		delta, _ := stringValue(value["delta"])
		decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDelta, ItemID: itemID, CallID: callID, Delta: delta})
	case "response.function_call_arguments.done":
		itemID, _ := stringValue(value["item_id"])
		callID, _ := stringValue(value["call_id"])
		arguments, isString := stringValue(value["arguments"])
		if isString {
			facts.argumentTypes = append(facts.argumentTypes, "string")
		} else {
			facts.argumentTypes = append(facts.argumentTypes, jsonType(value["arguments"]))
		}
		decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDone, ItemID: itemID, CallID: callID, Arguments: arguments})
	case "response.output_item.done":
		item := objectValue(value["item"])
		itemID, _ := stringValue(item["id"])
		callID, _ := stringValue(item["call_id"])
		decoder.append(statemachine.Event{Type: statemachine.EventOutputItemDone, ItemID: itemID, CallID: callID})
	case "response.completed":
		facts.terminalCount++
		response := objectValue(value["response"])
		if reason, ok := stringValue(response["status"]); ok {
			facts.finishReasons = append(facts.finishReasons, reason)
		}
		readUsage(objectValue(response["usage"]), "input_tokens", "output_tokens", "total_tokens", &facts.usage)
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCompleted})
	case "response.failed":
		facts.terminalCount++
		decoder.append(statemachine.Event{Type: statemachine.EventResponseFailed})
	case "response.incomplete":
		facts.terminalCount++
		decoder.append(statemachine.Event{Type: statemachine.EventResponseIncomplete})
	}
}

func (decoder *streamDecoder) consumeChat(value map[string]any, facts *exchangeFacts) {
	decoder.ensureChatCreated()
	readUsage(objectValue(value["usage"]), "prompt_tokens", "completion_tokens", "total_tokens", &facts.usage)
	choice := firstObject(value["choices"])
	if choice == nil {
		return
	}
	delta := objectValue(choice["delta"])
	for _, callValue := range arrayValue(delta["tool_calls"]) {
		call := objectValue(callValue)
		index := indexValue(call["index"])
		callID, _ := stringValue(call["id"])
		function := objectValue(call["function"])
		lifecycle := decoder.chatTools[index]
		if lifecycle == nil {
			lifecycle = &toolLifecycle{itemID: "chat-tool-" + strconv.Itoa(index), callID: callID}
			decoder.chatTools[index] = lifecycle
			decoder.append(statemachine.Event{Type: statemachine.EventOutputItemAdded, ItemID: lifecycle.itemID, ItemKind: "function_call", OutputIndex: index, CallID: callID})
			facts.toolCallCount++
		}
		if arguments, exists := function["arguments"]; exists {
			argumentType := jsonType(arguments)
			facts.argumentTypes = append(facts.argumentTypes, argumentType)
			if text, ok := stringValue(arguments); ok && text != "" {
				lifecycle.arguments += text
				decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDelta, ItemID: lifecycle.itemID, CallID: callID, Delta: text})
			}
		}
	}
	if reason, ok := stringValue(choice["finish_reason"]); ok {
		facts.finishReasons = append(facts.finishReasons, reason)
		for _, index := range sortedToolIndexes(decoder.chatTools) {
			tool := decoder.chatTools[index]
			decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDone, ItemID: tool.itemID, CallID: tool.callID, Arguments: tool.arguments})
			decoder.append(statemachine.Event{Type: statemachine.EventOutputItemDone, ItemID: tool.itemID, CallID: tool.callID})
		}
	}
}

func (decoder *streamDecoder) consumeAnthropic(eventName string, value map[string]any, facts *exchangeFacts) {
	switch eventName {
	case "message_start":
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCreated})
		message := objectValue(value["message"])
		usage := objectValue(message["usage"])
		if input, ok := integerValue(usage["input_tokens"]); ok {
			facts.usage.Input, facts.usage.HasInput = input, true
		}
	case "content_block_start":
		index := indexValue(value["index"])
		block := objectValue(value["content_block"])
		kind, _ := stringValue(block["type"])
		callID, _ := stringValue(block["id"])
		itemKind := kind
		if kind == "tool_use" {
			itemKind = "function_call"
			facts.toolCallCount++
		}
		lifecycle := &toolLifecycle{itemID: "anthropic-item-" + strconv.Itoa(index), callID: callID}
		decoder.anthropicItems[index] = lifecycle
		decoder.append(statemachine.Event{Type: statemachine.EventOutputItemAdded, ItemID: lifecycle.itemID, ItemKind: itemKind, OutputIndex: index, CallID: callID})
	case "content_block_delta":
		index := indexValue(value["index"])
		lifecycle := decoder.anthropicItems[index]
		delta := objectValue(value["delta"])
		if lifecycle != nil && delta["type"] == "input_json_delta" {
			partial, _ := stringValue(delta["partial_json"])
			lifecycle.arguments += partial
			facts.argumentTypes = append(facts.argumentTypes, "string")
			decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDelta, ItemID: lifecycle.itemID, CallID: lifecycle.callID, Delta: partial})
		}
	case "content_block_stop":
		index := indexValue(value["index"])
		lifecycle := decoder.anthropicItems[index]
		if lifecycle == nil {
			return
		}
		if lifecycle.callID != "" {
			decoder.append(statemachine.Event{Type: statemachine.EventArgumentsDone, ItemID: lifecycle.itemID, CallID: lifecycle.callID, Arguments: lifecycle.arguments})
		}
		decoder.append(statemachine.Event{Type: statemachine.EventOutputItemDone, ItemID: lifecycle.itemID, CallID: lifecycle.callID})
	case "message_delta":
		delta := objectValue(value["delta"])
		if reason, ok := stringValue(delta["stop_reason"]); ok {
			facts.finishReasons = append(facts.finishReasons, reason)
		}
		usage := objectValue(value["usage"])
		if output, ok := integerValue(usage["output_tokens"]); ok {
			facts.usage.Output, facts.usage.HasOutput = output, true
		}
	case "message_stop":
		facts.terminalCount++
		decoder.append(statemachine.Event{Type: statemachine.EventResponseCompleted})
	}
}

func sortedToolIndexes(tools map[int]*toolLifecycle) []int {
	indexes := make([]int, 0, len(tools))
	for index := range tools {
		indexes = append(indexes, index)
	}
	slices.Sort(indexes)
	return indexes
}
