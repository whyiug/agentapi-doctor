package oracle

import (
	"errors"

	"github.com/whyiug/agentapi-doctor/internal/statemachine"
)

func EvaluateStateMachine(input Input[[]statemachine.Event]) Outcome {
	if result := preflight(input); result != nil {
		return *result
	}
	machine := statemachine.New()
	for _, event := range input.Value {
		if err := machine.Apply(event); err != nil {
			var violation *statemachine.Violation
			if !errors.As(err, &violation) {
				return harness(input.EvidenceRefs, "state_machine_internal_error", err)
			}
			return targetFail(input.EvidenceRefs, violation.Code, violation.Expected, violation.Observed)
		}
	}
	if !input.Complete {
		return insufficient(input.EvidenceRefs, "incomplete_stream_evidence", "terminal logical event", "stream evidence ended before completeness was established")
	}
	if err := machine.Finish(); err != nil {
		var violation *statemachine.Violation
		if !errors.As(err, &violation) {
			return harness(input.EvidenceRefs, "state_machine_internal_error", err)
		}
		return targetFail(input.EvidenceRefs, violation.Code, violation.Expected, violation.Observed)
	}
	return pass(input.EvidenceRefs)
}
