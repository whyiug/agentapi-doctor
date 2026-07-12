package oracle

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/normalizer"
	"github.com/whyiug/agentapi-doctor/internal/statemachine"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestSchemaOraclePassesReferenceAndFailsTargetedMutant(t *testing.T) {
	expected := Schema{
		Types: []JSONType{TypeObject},
		Properties: map[string]Schema{
			"type":  {Types: []JSONType{TypeString}},
			"index": {Types: []JSONType{TypeNumber}},
		},
		Required:     []string{"type", "index"},
		AllowUnknown: true,
	}
	reference := EvaluateSchema(completeJSON(`{"index":0,"type":"response.output_item.added"}`), expected)
	if reference.Verdict != schema.VerdictPass || reference.TargetFailure {
		t.Fatalf("reference did not pass: %#v", reference)
	}
	mutant := EvaluateSchema(completeJSON(`{"index":"zero","type":"response.output_item.added"}`), expected)
	if mutant.Verdict != schema.VerdictFail || !mutant.TargetFailure || mutant.Code != "json_type_mismatch" {
		t.Fatalf("targeted type mutant not killed: %#v", mutant)
	}
}

func TestMissingEvidenceAndHarnessErrorsNeverBecomeTargetFail(t *testing.T) {
	expected := Schema{Types: []JSONType{TypeObject}}
	missing := EvaluateSchema(Input[json.RawMessage]{Value: json.RawMessage(`not-json`), Complete: true}, expected)
	if missing.Verdict != schema.VerdictInconclusive || missing.ReasonCode != schema.ReasonNotObserved || missing.TargetFailure {
		t.Fatalf("missing evidence became target result: %#v", missing)
	}
	harnessFailure := EvaluateSchema(Input[json.RawMessage]{
		Value:        json.RawMessage(`not-json`),
		EvidenceRefs: evidenceRefs(),
		Complete:     true,
		HarnessError: errors.New("fixture setup failed with sensitive detail"),
	}, expected)
	if harnessFailure.Verdict != schema.VerdictInconclusive || harnessFailure.ReasonCode != schema.ReasonHarnessError || harnessFailure.TargetFailure {
		t.Fatalf("harness error became target fail: %#v", harnessFailure)
	}
}

func TestInvalidOracleSchemaAndPartialJSONAreInconclusive(t *testing.T) {
	invalidSchema := EvaluateSchema(completeJSON(`{"ok":true}`), Schema{})
	if invalidSchema.Verdict != schema.VerdictInconclusive || invalidSchema.ReasonCode != schema.ReasonHarnessError || invalidSchema.TargetFailure {
		t.Fatalf("invalid harness schema became target fail: %#v", invalidSchema)
	}
	partial := EvaluateSchema(Input[json.RawMessage]{
		Value:        json.RawMessage(`{"ok":`),
		EvidenceRefs: evidenceRefs(),
		Complete:     false,
	}, Schema{Types: []JSONType{TypeObject}})
	if partial.Verdict != schema.VerdictInconclusive || partial.ReasonCode != schema.ReasonInsufficientSamples || partial.TargetFailure {
		t.Fatalf("partial JSON became target fail: %#v", partial)
	}
}

func TestRelationalOracleChecksToolReferencesAndReturnsInconclusiveOnLoss(t *testing.T) {
	call := normalizedItem(t, "call-item", schema.IRToolCall, "call-1", []byte(`{"name":"weather"}`), normalizer.TransformIdentity)
	result := normalizedItem(t, "result-item", schema.IRToolResult, "call-1", []byte(`{"temperature":20}`), normalizer.TransformIdentity)
	passed := EvaluateRelations(Input[[]schema.IRItem]{Value: []schema.IRItem{call, result}, EvidenceRefs: evidenceRefs(), Complete: true})
	if passed.Verdict != schema.VerdictPass {
		t.Fatalf("valid relation failed: %#v", passed)
	}
	unknown := result
	unknown.CallID = "missing"
	failed := EvaluateRelations(Input[[]schema.IRItem]{Value: []schema.IRItem{call, unknown}, EvidenceRefs: evidenceRefs(), Complete: true})
	if failed.Verdict != schema.VerdictFail || failed.Code != "tool_result_unknown_call" || !failed.TargetFailure {
		t.Fatalf("unknown call did not fail: %#v", failed)
	}
	duplicate := EvaluateRelations(Input[[]schema.IRItem]{Value: []schema.IRItem{call, result, result}, EvidenceRefs: evidenceRefs(), Complete: true})
	if duplicate.Verdict != schema.VerdictFail || duplicate.Code != "duplicate_item_id" || !duplicate.TargetFailure {
		t.Fatalf("duplicate result item not rejected: %#v", duplicate)
	}
	lossy := call
	lossy.LossMarkers = []schema.LossMarker{{TransformID: "identity", Reason: "synthetic loss"}}
	inconclusive := EvaluateRelations(Input[[]schema.IRItem]{Value: []schema.IRItem{lossy}, EvidenceRefs: evidenceRefs(), Complete: true})
	if inconclusive.Verdict != schema.VerdictInconclusive || inconclusive.ReasonCode != schema.ReasonInsufficientSamples || inconclusive.TargetFailure {
		t.Fatalf("normalization loss was treated as target fail: %#v", inconclusive)
	}
}

func TestEmptyRelationalEvidenceIsInconclusive(t *testing.T) {
	outcome := EvaluateRelations(Input[[]schema.IRItem]{EvidenceRefs: evidenceRefs(), Complete: true})
	if outcome.Verdict != schema.VerdictInconclusive || outcome.Code != "empty_interaction" || outcome.TargetFailure {
		t.Fatalf("empty relation set was treated as established: %#v", outcome)
	}
}

func TestStateMachineOracleSeparatesIncompleteEvidenceFromViolation(t *testing.T) {
	prefix := []statemachine.Event{
		{Sequence: 1, Type: statemachine.EventResponseCreated},
		{Sequence: 2, Type: statemachine.EventOutputItemAdded, ItemID: "item-1", ItemKind: "function_call", OutputIndex: 0, CallID: "call-1"},
	}
	incomplete := EvaluateStateMachine(Input[[]statemachine.Event]{Value: prefix, EvidenceRefs: evidenceRefs(), Complete: false})
	if incomplete.Verdict != schema.VerdictInconclusive || incomplete.TargetFailure {
		t.Fatalf("partial stream became target fail: %#v", incomplete)
	}
	completeButTruncated := EvaluateStateMachine(Input[[]statemachine.Event]{Value: prefix, EvidenceRefs: evidenceRefs(), Complete: true})
	if completeButTruncated.Verdict != schema.VerdictFail || completeButTruncated.Code != "missing_terminal_event" || !completeButTruncated.TargetFailure {
		t.Fatalf("complete evidence did not expose missing terminal: %#v", completeButTruncated)
	}
	invalid := append(append([]statemachine.Event(nil), prefix...), statemachine.Event{Sequence: 3, Type: statemachine.EventArgumentsDelta, ItemID: "missing", Delta: "x"})
	violation := EvaluateStateMachine(Input[[]statemachine.Event]{Value: invalid, EvidenceRefs: evidenceRefs(), Complete: true})
	if violation.Verdict != schema.VerdictFail || violation.Code != "unknown_item_reference" || !violation.TargetFailure {
		t.Fatalf("state violation not reported: %#v", violation)
	}
}

func TestStateMachineOraclePassesCompleteReference(t *testing.T) {
	outcome := EvaluateStateMachine(Input[[]statemachine.Event]{
		Value: []statemachine.Event{
			{Sequence: 1, Type: statemachine.EventResponseCreated},
			{Sequence: 2, Type: statemachine.EventResponseCompleted},
		},
		EvidenceRefs: evidenceRefs(),
		Complete:     true,
	})
	if outcome.Verdict != schema.VerdictPass || outcome.TargetFailure {
		t.Fatalf("complete reference stream did not pass: %#v", outcome)
	}
}

func TestStateMachineHarnessFailureIsNotTargetFail(t *testing.T) {
	outcome := EvaluateStateMachine(Input[[]statemachine.Event]{
		Value:        []statemachine.Event{{Sequence: 99, Type: statemachine.EventResponseCompleted}},
		EvidenceRefs: evidenceRefs(),
		Complete:     true,
		HarnessError: errors.New("decoder setup failed"),
	})
	if outcome.Verdict != schema.VerdictInconclusive || outcome.ReasonCode != schema.ReasonHarnessError || outcome.TargetFailure {
		t.Fatalf("harness failure became target fail: %#v", outcome)
	}
}

func completeJSON(value string) Input[json.RawMessage] {
	return Input[json.RawMessage]{Value: json.RawMessage(value), EvidenceRefs: evidenceRefs(), Complete: true}
}

func normalizedItem(t *testing.T, itemID string, itemType schema.IRType, callID string, native []byte, transform normalizer.Transform) schema.IRItem {
	t.Helper()
	item, err := normalizer.Normalize(normalizer.Request{
		ItemID:         itemID,
		IRType:         itemType,
		SourceProtocol: "synthetic",
		InteractionID:  "interaction-1",
		CallID:         callID,
		NativeValue:    native,
		EvidenceRefs:   evidenceRefs(),
		Transform:      transform,
		Version:        "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func evidenceRefs() []schema.ObjectRef {
	return []schema.ObjectRef{{Kind: "Evidence", ContentDigest: schema.NewDigest([]byte("evidence"))}}
}
