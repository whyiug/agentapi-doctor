// Package server implements a deterministic local protocol fixture.  It only
// represents this project's current pack interpretation and is not a claim of
// protocol authority.
package server

import (
	"errors"
	"net/http"
)

// ErrTransformerNotApplicable indicates that a transformer deliberately does
// not target the current exchange. The handler preserves the unmodified
// reference response and does not advertise the transformer ID. Other errors
// are treated as transformer failures.
var ErrTransformerNotApplicable = errors.New("transformer not applicable")

type Protocol string

const (
	ProtocolOpenAIChat      Protocol = "openai-chat"
	ProtocolOpenAIResponses Protocol = "openai-responses"
	ProtocolAnthropic       Protocol = "anthropic-messages"
)

type Scenario string

const (
	ScenarioText Scenario = "text"
	ScenarioTool Scenario = "tool"
)

type SSEEvent struct {
	Event    string
	Data     any
	RawData  []byte
	Terminal bool
}

type Exchange struct {
	Protocol   Protocol
	Scenario   Scenario
	Streaming  bool
	Status     int
	Headers    http.Header
	JSON       map[string]any
	Events     []SSEEvent
	RawSuffix  []byte
	MutationID string
}

func cloneExchange(source Exchange) Exchange {
	result := source
	result.Headers = source.Headers.Clone()
	result.RawSuffix = append([]byte(nil), source.RawSuffix...)
	if source.JSON != nil {
		result.JSON = cloneFixtureValue(source.JSON).(map[string]any)
	}
	result.Events = make([]SSEEvent, len(source.Events))
	for index, event := range source.Events {
		result.Events[index] = event
		result.Events[index].RawData = append([]byte(nil), event.RawData...)
		result.Events[index].Data = cloneFixtureValue(event.Data)
	}
	return result
}

func cloneFixtureValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		copyValue := make(map[string]any, len(typed))
		for key, item := range typed {
			copyValue[key] = cloneFixtureValue(item)
		}
		return copyValue
	case []any:
		copyValue := make([]any, len(typed))
		for index, item := range typed {
			copyValue[index] = cloneFixtureValue(item)
		}
		return copyValue
	case []byte:
		return append([]byte(nil), typed...)
	default:
		return value
	}
}

type Transformer interface {
	ID() string
	Apply(*Exchange) error
}
