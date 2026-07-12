package server

import (
	"encoding/json"
	"errors"
	"net/http"

	synthetictools "github.com/whyiug/agentapi-doctor/reference/synthetic-tools"
)

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicRequest struct {
	Model     string            `json:"model"`
	Messages  []json.RawMessage `json:"messages"`
	MaxTokens int               `json:"max_tokens"`
	System    json.RawMessage   `json:"system,omitempty"`
	Tools     []anthropicTool   `json:"tools,omitempty"`
	Stream    bool              `json:"stream,omitempty"`
}

func (handler *Handler) buildAnthropic(writer http.ResponseWriter, request *http.Request) (Exchange, error) {
	var input anthropicRequest
	if err := handler.decodeJSON(writer, request, &input); err != nil {
		return Exchange{}, err
	}
	if input.Model == "" || len(input.Messages) == 0 || input.MaxTokens < 1 {
		return Exchange{}, errors.New("model, messages, and max_tokens are required")
	}
	scenario := ScenarioText
	toolName := ""
	if len(input.Tools) > 0 {
		scenario = ScenarioTool
		toolName = input.Tools[0].Name
	}
	exchange := Exchange{Protocol: ProtocolAnthropic, Scenario: scenario, Streaming: input.Stream, Status: http.StatusOK, Headers: make(http.Header)}
	if input.Stream {
		exchange.Events = anthropicStream(input.Model, scenario, toolName)
	} else {
		exchange.JSON = anthropicResponse(input.Model, scenario, toolName)
	}
	return exchange, nil
}

func anthropicResponse(model string, scenario Scenario, toolName string) map[string]any {
	content := []any{map[string]any{"type": "text", "text": "synthetic response"}}
	stopReason := "end_turn"
	if scenario == ScenarioTool {
		call := synthetictools.NewCall(toolName)
		content = []any{map[string]any{"type": "tool_use", "id": call.ID, "name": call.Name, "input": call.Arguments}}
		stopReason = "tool_use"
	}
	return map[string]any{
		"id": "msg_ref_0001", "type": "message", "role": "assistant", "model": model,
		"content": content, "stop_reason": stopReason, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": 4, "output_tokens": 2},
	}
}

func anthropicStream(model string, scenario Scenario, toolName string) []SSEEvent {
	events := []SSEEvent{{Event: "message_start", Data: map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": "msg_ref_0001", "type": "message", "role": "assistant", "model": model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 4, "output_tokens": 0},
		},
	}}}
	stopReason := "end_turn"
	if scenario == ScenarioText {
		events = append(events,
			SSEEvent{Event: "content_block_start", Data: map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}}},
			SSEEvent{Event: "content_block_delta", Data: map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "synthetic response"}}},
			SSEEvent{Event: "content_block_stop", Data: map[string]any{"type": "content_block_stop", "index": 0}},
		)
	} else {
		stopReason = "tool_use"
		call := synthetictools.NewCall(toolName)
		events = append(events,
			SSEEvent{Event: "content_block_start", Data: map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "tool_use", "id": call.ID, "name": call.Name, "input": map[string]any{}}}},
			SSEEvent{Event: "content_block_delta", Data: map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": call.ArgumentsJSON()}}},
			SSEEvent{Event: "content_block_stop", Data: map[string]any{"type": "content_block_stop", "index": 0}},
		)
	}
	events = append(events,
		SSEEvent{Event: "message_delta", Data: map[string]any{
			"type": "message_delta", "delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
			"usage": map[string]any{"output_tokens": 2},
		}},
		SSEEvent{Event: "message_stop", Data: map[string]any{"type": "message_stop"}, Terminal: true},
	)
	return events
}
