package statemachine

import (
	"errors"
	"testing"
)

func TestValidFunctionCallStreamReconstructsArguments(t *testing.T) {
	machine := New()
	events := []Event{
		{Sequence: 1, Type: EventResponseCreated},
		{Sequence: 2, Type: EventResponseInProgress},
		{Sequence: 3, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "function_call", OutputIndex: 0, CallID: "call-1"},
		{Sequence: 4, Type: EventArgumentsDelta, ItemID: "item-1", CallID: "call-1", Delta: `{"city":`},
		{Sequence: 5, Type: EventArgumentsDelta, ItemID: "item-1", CallID: "call-1", Delta: `"Paris"}`},
		{Sequence: 6, Type: EventArgumentsDone, ItemID: "item-1", CallID: "call-1", Arguments: `{"city":"Paris"}`},
		{Sequence: 7, Type: EventOutputItemDone, ItemID: "item-1"},
		{Sequence: 8, Type: EventToolResult, CallID: "call-1"},
		{Sequence: 9, Type: EventResponseCompleted},
	}
	for _, event := range events {
		if err := machine.Apply(event); err != nil {
			t.Fatalf("apply %#v: %v", event, err)
		}
	}
	if err := machine.Finish(); err != nil {
		t.Fatal(err)
	}
	arguments, ok := machine.ReconstructedArguments("item-1")
	if !ok || arguments != `{"city":"Paris"}` {
		t.Fatalf("unexpected reconstructed arguments %q", arguments)
	}
}

func TestDeltaRequiresPreviouslyOpenedFunctionCall(t *testing.T) {
	machine := New()
	if err := machine.Apply(Event{Sequence: 1, Type: EventResponseCreated}); err != nil {
		t.Fatal(err)
	}
	err := machine.Apply(Event{Sequence: 2, Type: EventArgumentsDelta, ItemID: "missing", Delta: "x"})
	requireViolation(t, err, "unknown_item_reference")
}

func TestArgumentsDoneMustEqualAccumulatedDeltas(t *testing.T) {
	machine := New()
	apply(t, machine,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "function_call", OutputIndex: 0, CallID: "call-1"},
		Event{Sequence: 3, Type: EventArgumentsDelta, ItemID: "item-1", Delta: `{"ok":true}`},
	)
	err := machine.Apply(Event{Sequence: 4, Type: EventArgumentsDone, ItemID: "item-1", Arguments: `{"ok":false}`})
	requireViolation(t, err, "arguments_reconstruction_mismatch")
}

func TestCompletedRejectsOpenItemButFailedPermitsTerminalFailure(t *testing.T) {
	completed := New()
	apply(t, completed,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "message", OutputIndex: 0},
	)
	requireViolation(t, completed.Apply(Event{Sequence: 3, Type: EventResponseCompleted}), "completed_with_open_item")

	failed := New()
	apply(t, failed,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "message", OutputIndex: 0},
		Event{Sequence: 3, Type: EventResponseFailed},
	)
	if err := failed.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestNoSemanticEventAfterTerminal(t *testing.T) {
	machine := New()
	apply(t, machine,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventResponseCompleted},
	)
	requireViolation(t, machine.Apply(Event{Sequence: 3, Type: EventResponseInProgress}), "event_after_terminal")
}

func TestInProgressCannotArriveAfterOutput(t *testing.T) {
	machine := New()
	apply(t, machine,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "message", OutputIndex: 0},
	)
	requireViolation(t, machine.Apply(Event{Sequence: 3, Type: EventResponseInProgress}), "in_progress_after_output")
}

func TestToolResultMustReferenceClosedUniqueCall(t *testing.T) {
	machine := New()
	apply(t, machine,
		Event{Sequence: 1, Type: EventResponseCreated},
		Event{Sequence: 2, Type: EventOutputItemAdded, ItemID: "item-1", ItemKind: "function_call", OutputIndex: 0, CallID: "call-1"},
		Event{Sequence: 3, Type: EventArgumentsDone, ItemID: "item-1", Arguments: ""},
	)
	requireViolation(t, machine.Apply(Event{Sequence: 4, Type: EventToolResult, CallID: "call-1"}), "tool_result_before_call_done")
	apply(t, machine, Event{Sequence: 4, Type: EventOutputItemDone, ItemID: "item-1"}, Event{Sequence: 5, Type: EventToolResult, CallID: "call-1"})
	requireViolation(t, machine.Apply(Event{Sequence: 6, Type: EventToolResult, CallID: "call-1"}), "duplicate_tool_result")
}

func TestInvalidEventDoesNotConsumeSequence(t *testing.T) {
	machine := New()
	requireViolation(t, machine.Apply(Event{Sequence: 2, Type: EventResponseCreated}), "non_monotonic_sequence")
	if err := machine.Apply(Event{Sequence: 1, Type: EventResponseCreated}); err != nil {
		t.Fatal(err)
	}
}

func apply(t *testing.T, machine *Machine, events ...Event) {
	t.Helper()
	for _, event := range events {
		if err := machine.Apply(event); err != nil {
			t.Fatalf("apply %#v: %v", event, err)
		}
	}
}

func requireViolation(t *testing.T, err error, code string) {
	t.Helper()
	var violation *Violation
	if !errors.As(err, &violation) || violation.Code != code {
		t.Fatalf("expected violation %s, got %v", code, err)
	}
}
