// Package synthetictools defines inert, deterministic tool fixtures.  The
// package performs no process execution, file access, or network access.
package synthetictools

import (
	"encoding/json"
	"errors"
)

const (
	EchoName = "synthetic_echo"
	CallID   = "call_ref_0001"
)

type Call struct {
	ID        string
	Name      string
	Arguments map[string]any
}

func NewCall(name string) Call {
	if name == "" {
		name = EchoName
	}
	return Call{ID: CallID, Name: name, Arguments: map[string]any{"text": "fixture"}}
}

func (call Call) ArgumentsJSON() string {
	raw, _ := json.Marshal(call.Arguments)
	return string(raw)
}

// Execute is intentionally limited to the inert echo fixture.
func Execute(call Call) (map[string]any, error) {
	if call.Name == "" {
		return nil, errors.New("synthetic tool name is required")
	}
	text, _ := call.Arguments["text"].(string)
	return map[string]any{"echo": text, "tool": call.Name}, nil
}

func OpenAIDefinition() map[string]any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        EchoName,
			"description": "inert deterministic local echo fixture",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"text": map[string]any{"type": "string"}},
				"required":   []string{"text"},
			},
		},
	}
}

func AnthropicDefinition() map[string]any {
	definition := OpenAIDefinition()["function"].(map[string]any)
	return map[string]any{
		"name":         definition["name"],
		"description":  definition["description"],
		"input_schema": definition["parameters"],
	}
}
