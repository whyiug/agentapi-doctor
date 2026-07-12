package server

import (
	"encoding/json"
	"errors"
	"net/http"

	synthetictools "github.com/whyiug/agentapi-doctor/reference/synthetic-tools"
)

type chatTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
	} `json:"function"`
}

type chatRequest struct {
	Model               string            `json:"model"`
	Messages            []json.RawMessage `json:"messages"`
	Tools               []chatTool        `json:"tools,omitempty"`
	Stream              bool              `json:"stream,omitempty"`
	MaxCompletionTokens *int              `json:"max_completion_tokens,omitempty"`
	ParallelToolCalls   *bool             `json:"parallel_tool_calls,omitempty"`
}

func (handler *Handler) buildChat(writer http.ResponseWriter, request *http.Request) (Exchange, error) {
	var input chatRequest
	if err := handler.decodeJSON(writer, request, &input); err != nil {
		return Exchange{}, err
	}
	if input.Model == "" || len(input.Messages) == 0 {
		return Exchange{}, errors.New("model and messages are required")
	}
	scenario := ScenarioText
	toolName := ""
	if len(input.Tools) > 0 {
		scenario = ScenarioTool
		toolName = input.Tools[0].Function.Name
	}
	exchange := Exchange{Protocol: ProtocolOpenAIChat, Scenario: scenario, Streaming: input.Stream, Status: http.StatusOK, Headers: make(http.Header)}
	if input.Stream {
		exchange.Events = chatStream(input.Model, scenario, toolName)
	} else {
		exchange.JSON = chatResponse(input.Model, scenario, toolName)
	}
	return exchange, nil
}

func chatResponse(model string, scenario Scenario, toolName string) map[string]any {
	message := map[string]any{"role": "assistant", "content": "synthetic response"}
	finish := "stop"
	if scenario == ScenarioTool {
		call := synthetictools.NewCall(toolName)
		message = map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{map[string]any{
				"id":       call.ID,
				"type":     "function",
				"function": map[string]any{"name": call.Name, "arguments": call.ArgumentsJSON()},
			}},
		}
		finish = "tool_calls"
	}
	return map[string]any{
		"id":      "chatcmpl_ref_0001",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
	}
}

func chatStream(model string, scenario Scenario, toolName string) []SSEEvent {
	events := []SSEEvent{{Data: chatChunk(model, []any{map[string]any{
		"index": 0, "delta": map[string]any{"role": "assistant", "content": ""}, "finish_reason": nil,
	}})}}
	finish := "stop"
	if scenario == ScenarioText {
		events = append(events, SSEEvent{Data: chatChunk(model, []any{map[string]any{
			"index": 0, "delta": map[string]any{"content": "synthetic response"}, "finish_reason": nil,
		}})})
	} else {
		finish = "tool_calls"
		call := synthetictools.NewCall(toolName)
		events = append(events,
			SSEEvent{Data: chatChunk(model, []any{map[string]any{
				"index": 0,
				"delta": map[string]any{"tool_calls": []any{map[string]any{
					"index": 0, "id": call.ID, "type": "function",
					"function": map[string]any{"name": call.Name, "arguments": ""},
				}}},
				"finish_reason": nil,
			}})},
			SSEEvent{Data: chatChunk(model, []any{map[string]any{
				"index": 0,
				"delta": map[string]any{"tool_calls": []any{map[string]any{
					"index": 0, "function": map[string]any{"arguments": call.ArgumentsJSON()},
				}}},
				"finish_reason": nil,
			}})},
		)
	}
	events = append(events,
		SSEEvent{Data: chatChunk(model, []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": finish}})},
		SSEEvent{Data: map[string]any{
			"id": "chatcmpl_ref_0001", "object": "chat.completion.chunk", "created": 1700000000,
			"model": model, "choices": []any{},
			"usage": map[string]any{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
		}},
		SSEEvent{RawData: []byte("[DONE]"), Terminal: true},
	)
	return events
}

func chatChunk(model string, choices []any) map[string]any {
	return map[string]any{
		"id": "chatcmpl_ref_0001", "object": "chat.completion.chunk", "created": 1700000000,
		"model": model, "choices": choices,
	}
}
