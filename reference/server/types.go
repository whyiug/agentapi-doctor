// Package server implements a deterministic local protocol fixture.  It only
// represents this project's current pack interpretation and is not a claim of
// protocol authority.
package server

import "net/http"

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

type Transformer interface {
	ID() string
	Apply(*Exchange) error
}
