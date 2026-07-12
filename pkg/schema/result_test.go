package schema

import "testing"

func TestCaseResultTruthTable(t *testing.T) {
	attempt := InstanceID("00000000-0000-7000-8000-000000000000")
	pass := VerdictPass
	tests := []struct {
		name    string
		value   CaseResult
		wantErr bool
	}{
		{
			name:  "completed with verdict",
			value: CaseResult{ScenarioID: "case.one", PlanDisposition: DispositionExecute, AttemptIDs: []InstanceID{attempt}, ExecutionStatus: ExecutionCompleted, Verdict: &pass},
		},
		{
			name:  "errored has no verdict",
			value: CaseResult{ScenarioID: "case.one", PlanDisposition: DispositionExecute, AttemptIDs: []InstanceID{attempt}, ExecutionStatus: ExecutionErrored, ReasonCode: ReasonHarnessError},
		},
		{
			name:    "harness error cannot become target fail",
			value:   CaseResult{ScenarioID: "case.one", PlanDisposition: DispositionExecute, AttemptIDs: []InstanceID{attempt}, ExecutionStatus: ExecutionErrored, ReasonCode: ReasonHarnessError, Verdict: &pass},
			wantErr: true,
		},
		{
			name:  "not applicable has reason and no attempt",
			value: CaseResult{ScenarioID: "case.one", PlanDisposition: DispositionNotApplicable, ReasonCode: ReasonUnsupportedCapability},
		},
		{
			name:    "skip cannot invent verdict",
			value:   CaseResult{ScenarioID: "case.one", PlanDisposition: DispositionSkip, ReasonCode: ReasonBudgetExhausted, Verdict: &pass},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.value.Validate()
			if test.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}
