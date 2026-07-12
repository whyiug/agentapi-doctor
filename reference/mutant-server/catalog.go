// Package mutantserver applies one explicit primary fault to the deterministic
// reference fixture.  Mutation IDs are stable evidence identifiers.
package mutantserver

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

type ID string

const (
	ArgumentsObjectInsteadOfString ID = "arguments-object-instead-of-string"
	MissingOutputIndex             ID = "missing-output-index"
	DuplicateOutputIndex           ID = "duplicate-output-index"
	DroppedStreamingToolCall       ID = "dropped-streaming-tool-call"
	InvalidFinishReason            ID = "invalid-finish-reason"
	MissingTerminalEvent           ID = "missing-terminal-event"
	DuplicateTerminalEvent         ID = "duplicate-terminal-event"
	ToolCallIDChanged              ID = "tool-call-id-changed"
	UnknownEventCrashesClient      ID = "unknown-event-crashes-client"
	UnclosedReasoningBlock         ID = "unclosed-reasoning-block"
	UsageInconsistent              ID = "usage-inconsistent"
	TruncatedUTF8                  ID = "truncated-utf8"
)

type Entry struct {
	ID          ID
	Description string
	Protocols   []referenceserver.Protocol
}

var catalog = []Entry{
	{ArgumentsObjectInsteadOfString, "function arguments use an object where the wire requires a JSON string", []referenceserver.Protocol{referenceserver.ProtocolOpenAIChat, referenceserver.ProtocolOpenAIResponses}},
	{MissingOutputIndex, "a Responses stream event omits output_index", []referenceserver.Protocol{referenceserver.ProtocolOpenAIResponses}},
	{DuplicateOutputIndex, "two Responses output items claim the same output_index", []referenceserver.Protocol{referenceserver.ProtocolOpenAIResponses}},
	{DroppedStreamingToolCall, "the streaming tool-call item or block is omitted", allProtocols()},
	{InvalidFinishReason, "the terminal status or stop reason is outside the fixture interpretation", allProtocols()},
	{MissingTerminalEvent, "the SSE terminal event is omitted", allProtocols()},
	{DuplicateTerminalEvent, "the SSE terminal event is emitted twice", allProtocols()},
	{ToolCallIDChanged, "a streaming tool call changes ID after creation", []referenceserver.Protocol{referenceserver.ProtocolOpenAIChat, referenceserver.ProtocolOpenAIResponses}},
	{UnknownEventCrashesClient, "an unknown forward-compatible event is injected", allProtocols()},
	{UnclosedReasoningBlock, "a reasoning or thinking block remains open at terminal", []referenceserver.Protocol{referenceserver.ProtocolOpenAIResponses, referenceserver.ProtocolAnthropic}},
	{UsageInconsistent, "usage components disagree with their total or cumulative value", allProtocols()},
	{TruncatedUTF8, "an SSE data field ends inside a UTF-8 code point", allProtocols()},
}

func allProtocols() []referenceserver.Protocol {
	return []referenceserver.Protocol{
		referenceserver.ProtocolOpenAIChat,
		referenceserver.ProtocolOpenAIResponses,
		referenceserver.ProtocolAnthropic,
	}
}

func Catalog() []Entry {
	result := make([]Entry, len(catalog))
	for index, entry := range catalog {
		result[index] = entry
		result[index].Protocols = slices.Clone(entry.Protocols)
	}
	return result
}

type Component interface {
	ID() string
	Primary() bool
	Apply(*referenceserver.Exchange) error
}

type mutation struct{ id ID }

func Mutation(id ID) (Component, error) {
	for _, entry := range catalog {
		if entry.ID == id {
			return mutation{id: id}, nil
		}
	}
	return nil, fmt.Errorf("unknown mutation ID %q", id)
}

func (value mutation) ID() string    { return string(value.id) }
func (value mutation) Primary() bool { return true }
func (value mutation) Apply(exchange *referenceserver.Exchange) error {
	return applyMutation(value.id, exchange)
}

type annotation struct {
	id, key, value string
}

// Annotation is a non-fault metadata decorator, allowing composition without
// weakening the exactly-one-primary invariant.
func Annotation(id, key, value string) (Component, error) {
	if id == "" || key == "" || value == "" {
		return nil, errors.New("annotation ID, header, and value are required")
	}
	return annotation{id: id, key: key, value: value}, nil
}

func (value annotation) ID() string    { return value.id }
func (value annotation) Primary() bool { return false }
func (value annotation) Apply(exchange *referenceserver.Exchange) error {
	if exchange.Headers == nil {
		exchange.Headers = make(http.Header)
	}
	exchange.Headers.Set(value.key, value.value)
	return nil
}

type Plan struct {
	components []Component
	primaryID  string
}

func New(id ID) (*Plan, error) {
	primary, err := Mutation(id)
	if err != nil {
		return nil, err
	}
	return Compose(primary)
}

func Compose(components ...Component) (*Plan, error) {
	primaryCount := 0
	primaryID := ""
	seen := make(map[string]struct{}, len(components))
	for _, component := range components {
		if component == nil || component.ID() == "" {
			return nil, errors.New("mutation component and ID are required")
		}
		if _, duplicate := seen[component.ID()]; duplicate {
			return nil, fmt.Errorf("duplicate mutation component %q", component.ID())
		}
		seen[component.ID()] = struct{}{}
		if component.Primary() {
			primaryCount++
			primaryID = component.ID()
		}
	}
	if primaryCount != 1 {
		return nil, fmt.Errorf("mutation plan requires exactly one primary fault, got %d", primaryCount)
	}
	return &Plan{components: slices.Clone(components), primaryID: primaryID}, nil
}

func (plan *Plan) ID() string { return plan.primaryID }

func (plan *Plan) Apply(exchange *referenceserver.Exchange) error {
	for _, component := range plan.components {
		if err := component.Apply(exchange); err != nil {
			return fmt.Errorf("apply %s: %w", component.ID(), err)
		}
	}
	return nil
}
