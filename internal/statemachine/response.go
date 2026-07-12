// Package statemachine validates strict typed stream and tool lifecycles.
package statemachine

import (
	"fmt"
)

type EventType string

const (
	EventResponseCreated    EventType = "response.created"
	EventResponseInProgress EventType = "response.in_progress"
	EventOutputItemAdded    EventType = "response.output_item.added"
	EventArgumentsDelta     EventType = "response.function_call_arguments.delta"
	EventArgumentsDone      EventType = "response.function_call_arguments.done"
	EventOutputItemDone     EventType = "response.output_item.done"
	EventToolResult         EventType = "tool.result"
	EventResponseCompleted  EventType = "response.completed"
	EventResponseFailed     EventType = "response.failed"
	EventResponseIncomplete EventType = "response.incomplete"
)

type Event struct {
	Sequence    uint64
	Type        EventType
	ItemID      string
	ItemKind    string
	OutputIndex int
	CallID      string
	Delta       string
	Arguments   string
}

type Violation struct {
	Code     string
	Expected string
	Observed string
}

func (violation *Violation) Error() string {
	return fmt.Sprintf("%s: expected %s, observed %s", violation.Code, violation.Expected, violation.Observed)
}

type itemState struct {
	kind          string
	callID        string
	arguments     string
	argumentsDone bool
	done          bool
}

type Machine struct {
	nextSequence uint64
	created      bool
	inProgress   bool
	terminal     EventType
	items        map[string]*itemState
	indexes      map[int]string
	calls        map[string]string
	toolResults  map[string]struct{}
}

func New() *Machine {
	return &Machine{
		nextSequence: 1,
		items:        make(map[string]*itemState),
		indexes:      make(map[int]string),
		calls:        make(map[string]string),
		toolResults:  make(map[string]struct{}),
	}
}

// Apply accepts one semantic event. Transport read chunks must be assembled
// into logical events before reaching this state machine.
func (machine *Machine) Apply(event Event) error {
	if event.Sequence != machine.nextSequence {
		return violation("non_monotonic_sequence", fmt.Sprintf("sequence %d", machine.nextSequence), fmt.Sprintf("sequence %d", event.Sequence))
	}
	if machine.terminal != "" {
		return violation("event_after_terminal", "no semantic event", string(event.Type))
	}
	var err error
	switch event.Type {
	case EventResponseCreated:
		err = machine.create()
	case EventResponseInProgress:
		err = machine.markInProgress()
	case EventOutputItemAdded:
		err = machine.addItem(event)
	case EventArgumentsDelta:
		err = machine.addArguments(event)
	case EventArgumentsDone:
		err = machine.finishArguments(event)
	case EventOutputItemDone:
		err = machine.finishItem(event)
	case EventToolResult:
		err = machine.acceptToolResult(event)
	case EventResponseCompleted, EventResponseFailed, EventResponseIncomplete:
		err = machine.finishResponse(event.Type)
	default:
		err = violation("unknown_semantic_event", "known versioned event", string(event.Type))
	}
	if err != nil {
		return err
	}
	machine.nextSequence++
	return nil
}

func (machine *Machine) Finish() error {
	if machine.terminal == "" {
		return violation("missing_terminal_event", "one completed, failed, or incomplete event", "end of evidence")
	}
	return nil
}

func (machine *Machine) Terminal() EventType { return machine.terminal }

func (machine *Machine) ReconstructedArguments(itemID string) (string, bool) {
	item, exists := machine.items[itemID]
	if !exists {
		return "", false
	}
	return item.arguments, true
}

func (machine *Machine) create() error {
	if machine.created {
		return violation("duplicate_response_created", "one response.created", "duplicate response.created")
	}
	machine.created = true
	return nil
}

func (machine *Machine) requireActive(event EventType) error {
	if !machine.created {
		return violation("event_before_response_created", "response.created", string(event))
	}
	return nil
}

func (machine *Machine) markInProgress() error {
	if err := machine.requireActive(EventResponseInProgress); err != nil {
		return err
	}
	if machine.inProgress {
		return violation("duplicate_in_progress", "at most one response.in_progress", "duplicate response.in_progress")
	}
	if len(machine.items) != 0 {
		return violation("in_progress_after_output", "response.in_progress before output items", "output item already added")
	}
	machine.inProgress = true
	return nil
}

func (machine *Machine) addItem(event Event) error {
	if err := machine.requireActive(event.Type); err != nil {
		return err
	}
	if event.ItemID == "" || event.ItemKind == "" || event.OutputIndex < 0 {
		return violation("invalid_output_item", "nonempty item ID/kind and nonnegative index", fmt.Sprintf("id=%q kind=%q index=%d", event.ItemID, event.ItemKind, event.OutputIndex))
	}
	if _, exists := machine.items[event.ItemID]; exists {
		return violation("duplicate_item_id", "unique item ID", event.ItemID)
	}
	if prior, exists := machine.indexes[event.OutputIndex]; exists {
		return violation("duplicate_output_index", "unique output index", fmt.Sprintf("index %d already used by %s", event.OutputIndex, prior))
	}
	if event.ItemKind == "function_call" {
		if event.CallID == "" {
			return violation("missing_call_id", "function call ID", "empty")
		}
		if prior, exists := machine.calls[event.CallID]; exists {
			return violation("duplicate_call_id", "unique call ID", fmt.Sprintf("%s already used by %s", event.CallID, prior))
		}
		machine.calls[event.CallID] = event.ItemID
	} else if event.CallID != "" {
		return violation("call_id_for_non_function_item", "empty call ID", event.CallID)
	}
	machine.items[event.ItemID] = &itemState{kind: event.ItemKind, callID: event.CallID}
	machine.indexes[event.OutputIndex] = event.ItemID
	return nil
}

func (machine *Machine) addArguments(event Event) error {
	item, err := machine.openFunctionCall(event)
	if err != nil {
		return err
	}
	if item.argumentsDone {
		return violation("arguments_delta_after_done", "no delta after arguments.done", event.ItemID)
	}
	item.arguments += event.Delta
	return nil
}

func (machine *Machine) finishArguments(event Event) error {
	item, err := machine.openFunctionCall(event)
	if err != nil {
		return err
	}
	if item.argumentsDone {
		return violation("duplicate_arguments_done", "one arguments.done", event.ItemID)
	}
	if event.Arguments != item.arguments {
		return violation("arguments_reconstruction_mismatch", "arguments.done equal to accumulated deltas", "different argument value")
	}
	item.argumentsDone = true
	return nil
}

func (machine *Machine) openFunctionCall(event Event) (*itemState, error) {
	if err := machine.requireActive(event.Type); err != nil {
		return nil, err
	}
	item, exists := machine.items[event.ItemID]
	if !exists {
		return nil, violation("unknown_item_reference", "previously added item", event.ItemID)
	}
	if item.done {
		return nil, violation("event_for_closed_item", "open item", event.ItemID)
	}
	if item.kind != "function_call" {
		return nil, violation("arguments_for_non_function_item", "function_call", item.kind)
	}
	if event.CallID != "" && event.CallID != item.callID {
		return nil, violation("call_id_changed", "stable call ID", "changed call ID")
	}
	return item, nil
}

func (machine *Machine) finishItem(event Event) error {
	if err := machine.requireActive(event.Type); err != nil {
		return err
	}
	item, exists := machine.items[event.ItemID]
	if !exists {
		return violation("unknown_item_reference", "previously added item", event.ItemID)
	}
	if item.done {
		return violation("duplicate_output_item_done", "one output_item.done", event.ItemID)
	}
	if item.kind == "function_call" && !item.argumentsDone {
		return violation("function_item_done_before_arguments", "arguments.done", event.ItemID)
	}
	if event.CallID != "" && event.CallID != item.callID {
		return violation("call_id_changed", "stable call ID", "changed call ID")
	}
	item.done = true
	return nil
}

func (machine *Machine) acceptToolResult(event Event) error {
	if err := machine.requireActive(event.Type); err != nil {
		return err
	}
	itemID, exists := machine.calls[event.CallID]
	if !exists {
		return violation("tool_result_unknown_call", "known call ID", event.CallID)
	}
	if !machine.items[itemID].done {
		return violation("tool_result_before_call_done", "closed function call", event.CallID)
	}
	if _, exists := machine.toolResults[event.CallID]; exists {
		return violation("duplicate_tool_result", "one result per call ID", event.CallID)
	}
	machine.toolResults[event.CallID] = struct{}{}
	return nil
}

func (machine *Machine) finishResponse(terminal EventType) error {
	if err := machine.requireActive(terminal); err != nil {
		return err
	}
	if terminal == EventResponseCompleted {
		for itemID, item := range machine.items {
			if !item.done {
				return violation("completed_with_open_item", "all output items done", itemID)
			}
		}
	}
	machine.terminal = terminal
	return nil
}

func violation(code, expected, observed string) error {
	return &Violation{Code: code, Expected: expected, Observed: observed}
}
