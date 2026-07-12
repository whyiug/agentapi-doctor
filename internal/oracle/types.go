// Package oracle evaluates schema, relational, and state-machine properties
// while keeping harness failures and insufficient evidence out of target FAIL.
package oracle

import "github.com/whyiug/agentapi-doctor/pkg/schema"

type Input[T any] struct {
	Value        T
	EvidenceRefs []schema.ObjectRef
	Complete     bool
	HarnessError error
}

type Outcome struct {
	Verdict       schema.Verdict
	ReasonCode    schema.ReasonCode
	Code          string
	Expected      any
	Observed      any
	EvidenceRefs  []schema.ObjectRef
	TargetFailure bool
}

func preflight[T any](input Input[T]) *Outcome {
	refs := append([]schema.ObjectRef(nil), input.EvidenceRefs...)
	if input.HarnessError != nil {
		return &Outcome{
			Verdict:       schema.VerdictInconclusive,
			ReasonCode:    schema.ReasonHarnessError,
			Code:          "harness_precondition_failed",
			Expected:      "valid harness precondition",
			Observed:      "harness error",
			EvidenceRefs:  refs,
			TargetFailure: false,
		}
	}
	if len(refs) == 0 {
		return &Outcome{
			Verdict:       schema.VerdictInconclusive,
			ReasonCode:    schema.ReasonNotObserved,
			Code:          "missing_evidence",
			Expected:      "at least one digest-bound evidence reference",
			Observed:      "none",
			TargetFailure: false,
		}
	}
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return &Outcome{
				Verdict:       schema.VerdictInconclusive,
				ReasonCode:    schema.ReasonHarnessError,
				Code:          "invalid_evidence_reference",
				Expected:      "valid digest-bound evidence reference",
				Observed:      "invalid evidence reference",
				EvidenceRefs:  refs,
				TargetFailure: false,
			}
		}
	}
	return nil
}

func pass(refs []schema.ObjectRef) Outcome {
	return Outcome{Verdict: schema.VerdictPass, Code: "assertion_satisfied", EvidenceRefs: append([]schema.ObjectRef(nil), refs...)}
}

func targetFail(refs []schema.ObjectRef, code string, expected, observed any) Outcome {
	return Outcome{
		Verdict:       schema.VerdictFail,
		Code:          code,
		Expected:      expected,
		Observed:      observed,
		EvidenceRefs:  append([]schema.ObjectRef(nil), refs...),
		TargetFailure: true,
	}
}

func insufficient(refs []schema.ObjectRef, code string, expected, observed any) Outcome {
	return Outcome{
		Verdict:       schema.VerdictInconclusive,
		ReasonCode:    schema.ReasonInsufficientSamples,
		Code:          code,
		Expected:      expected,
		Observed:      observed,
		EvidenceRefs:  append([]schema.ObjectRef(nil), refs...),
		TargetFailure: false,
	}
}

func harness(refs []schema.ObjectRef, code string, err error) Outcome {
	_ = err
	return Outcome{
		Verdict:       schema.VerdictInconclusive,
		ReasonCode:    schema.ReasonHarnessError,
		Code:          code,
		Expected:      "valid harness input",
		Observed:      "harness validation failed",
		EvidenceRefs:  append([]schema.ObjectRef(nil), refs...),
		TargetFailure: false,
	}
}
