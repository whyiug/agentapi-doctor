package server

import (
	"encoding/json"
	"errors"
	"net/http"

	synthetictools "github.com/whyiug/agentapi-doctor/reference/synthetic-tools"
)

type responsesTool struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type responsesRequest struct {
	Model        string          `json:"model"`
	Input        json.RawMessage `json:"input"`
	Instructions string          `json:"instructions,omitempty"`
	Tools        []responsesTool `json:"tools,omitempty"`
	Stream       bool            `json:"stream,omitempty"`
	Store        *bool           `json:"store,omitempty"`
}

func (handler *Handler) buildResponses(writer http.ResponseWriter, request *http.Request) (Exchange, error) {
	var input responsesRequest
	if err := handler.decodeJSON(writer, request, &input); err != nil {
		return Exchange{}, err
	}
	if input.Model == "" || len(input.Input) == 0 || string(input.Input) == "null" {
		return Exchange{}, errors.New("model and input are required")
	}
	scenario := ScenarioText
	toolName := ""
	if len(input.Tools) > 0 {
		scenario = ScenarioTool
		toolName = input.Tools[0].Name
	}
	exchange := Exchange{Protocol: ProtocolOpenAIResponses, Scenario: scenario, Streaming: input.Stream, Status: http.StatusOK, Headers: make(http.Header)}
	if input.Stream {
		exchange.Events = responsesStream(input.Model, scenario, toolName)
	} else {
		exchange.JSON = responsesResponse(input.Model, scenario, toolName)
	}
	return exchange, nil
}

func responsesResponse(model string, scenario Scenario, toolName string) map[string]any {
	output := []any{responsesMessageItem()}
	if scenario == ScenarioTool {
		call := synthetictools.NewCall(toolName)
		output = []any{map[string]any{
			"id": "item_call_ref_0001", "type": "function_call", "status": "completed",
			"call_id": call.ID, "name": call.Name, "arguments": call.ArgumentsJSON(),
		}}
	}
	return map[string]any{
		"id": "resp_ref_0001", "object": "response", "created_at": 1700000000,
		"status": "completed", "model": model, "output": output,
		"usage": map[string]any{"input_tokens": 4, "output_tokens": 2, "total_tokens": 6},
	}
}

func responsesMessageItem() map[string]any {
	return map[string]any{
		"id": "item_msg_ref_0001", "type": "message", "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": "synthetic response", "annotations": []any{}}},
	}
}

func responsesStream(model string, scenario Scenario, toolName string) []SSEEvent {
	sequence := 0
	event := func(eventType string, fields map[string]any) SSEEvent {
		sequence++
		fields["type"] = eventType
		fields["sequence_number"] = sequence
		return SSEEvent{Event: eventType, Data: fields}
	}
	responseBase := map[string]any{"id": "resp_ref_0001", "object": "response", "status": "in_progress", "model": model}
	events := []SSEEvent{event("response.created", map[string]any{"response": responseBase})}
	if scenario == ScenarioText {
		item := map[string]any{"id": "item_msg_ref_0001", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}
		events = append(events,
			event("response.output_item.added", map[string]any{"output_index": 0, "item": item}),
			event("response.content_part.added", map[string]any{"item_id": "item_msg_ref_0001", "output_index": 0, "content_index": 0, "part": map[string]any{"type": "output_text", "text": ""}}),
			event("response.output_text.delta", map[string]any{"item_id": "item_msg_ref_0001", "output_index": 0, "content_index": 0, "delta": "synthetic response"}),
			event("response.output_text.done", map[string]any{"item_id": "item_msg_ref_0001", "output_index": 0, "content_index": 0, "text": "synthetic response"}),
			event("response.content_part.done", map[string]any{"item_id": "item_msg_ref_0001", "output_index": 0, "content_index": 0, "part": map[string]any{"type": "output_text", "text": "synthetic response"}}),
			event("response.output_item.done", map[string]any{"output_index": 0, "item": responsesMessageItem()}),
		)
	} else {
		call := synthetictools.NewCall(toolName)
		item := map[string]any{
			"id": "item_call_ref_0001", "type": "function_call", "status": "in_progress",
			"call_id": call.ID, "name": call.Name, "arguments": "",
		}
		doneItem := map[string]any{
			"id": "item_call_ref_0001", "type": "function_call", "status": "completed",
			"call_id": call.ID, "name": call.Name, "arguments": call.ArgumentsJSON(),
		}
		events = append(events,
			event("response.output_item.added", map[string]any{"output_index": 0, "item": item}),
			event("response.function_call_arguments.delta", map[string]any{"item_id": "item_call_ref_0001", "output_index": 0, "delta": call.ArgumentsJSON()}),
			event("response.function_call_arguments.done", map[string]any{"item_id": "item_call_ref_0001", "output_index": 0, "arguments": call.ArgumentsJSON()}),
			event("response.output_item.done", map[string]any{"output_index": 0, "item": doneItem}),
		)
	}
	completed := responsesResponse(model, scenario, toolName)
	events = append(events, event("response.completed", map[string]any{"response": completed}))
	events[len(events)-1].Terminal = true
	return events
}
