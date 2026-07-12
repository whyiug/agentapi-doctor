package report

import (
	"errors"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func baselineWith(states map[string]CaseState) Baseline {
	if states == nil {
		states = map[string]CaseState{}
	}
	return Baseline{Name: "main", ProfileDigest: testDigest("profile"), PackDigest: testDigest("pack"), SupportLockDigest: testDigest("support"), DenominatorDigest: testDigest("denominator"), Cases: states}
}

func TestCompareClassifiesRegressionAndFixed(t *testing.T) {
	pass, fail := schema.VerdictPass, schema.VerdictFail
	before := baselineWith(map[string]CaseState{"regress": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &pass}, "fixed": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &fail}})
	after := baselineWith(map[string]CaseState{"regress": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &fail}, "fixed": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &pass}})
	diffs, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, diff := range diffs {
		got[diff.ScenarioID] = diff.Change
	}
	if got["regress"] != Regression || got["fixed"] != Fixed {
		t.Fatalf("unexpected diffs: %#v", diffs)
	}
}

func TestCompareRejectsChangedDenominator(t *testing.T) {
	before, after := baselineWith(nil), baselineWith(nil)
	after.DenominatorDigest = testDigest("other")
	if _, err := Compare(before, after); !errors.Is(err, ErrIncomparable) {
		t.Fatalf("expected ErrIncomparable, got %v", err)
	}
}
