package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func digest(label string) schema.Digest { return schema.NewDigest([]byte(label)) }
func instance(number int) schema.InstanceID {
	return schema.InstanceID(fmt.Sprintf("00000000-0000-7000-8000-%012x", number))
}

func idSource(start int) IDSource {
	var mu sync.Mutex
	next := start
	return func() (schema.InstanceID, error) {
		mu.Lock()
		defer mu.Unlock()
		value := instance(next)
		next++
		return value, nil
	}
}

func driver() schema.ArtifactPin {
	return schema.ArtifactPin{Kind: "Driver", Name: "raw-http", Version: "1.0.0", Digest: digest("driver")}
}

func hard(requests int64) schema.HardBudget {
	return schema.HardBudget{MaxRequests: requests, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxArtifactBytes: 1 << 20, MaxProcesses: 4, MaxDuration: schema.NewDuration(time.Minute)}
}

func testPlan(t *testing.T, decisions []schema.ScenarioDecision, finalizers []schema.FinalizerPlan) schema.ResolvedRunPlan {
	t.Helper()
	created := schema.NewUTCTime(time.Unix(1, 0))
	producer := schema.Producer{Name: "doctor", Version: "0.1.0", ArtifactDigest: digest("doctor")}
	id := instance(10)
	intent := schema.ObjectRef{Kind: "IntentPlan", InstanceID: instance(9), ContentDigest: digest("intent")}
	resolver := schema.ArtifactPin{Kind: "Resolver", Name: "core", Version: "1.0.0", Digest: digest("resolver")}
	policy := schema.BudgetPolicy{Hard: hard(20), Reservation: schema.TokenBudget{MaxInputTokens: 1000, MaxOutputTokens: 1000}, Cleanup: hard(10)}
	runtime := schema.RuntimePolicy{Concurrency: 1, Retries: 1, Timeout: schema.NewDuration(time.Second), Capture: schema.CaptureStandard, Sandbox: "process", Network: schema.NetworkTargetOnly}
	denominator := digest("denominator")
	support := digest("support")
	target := schema.TargetResolution{IdentityLevel: "version-pinned", ObservedFingerprint: digest("target")}
	artifacts := []schema.ArtifactPin{driver()}
	projection := struct {
		SchemaVersion             string                    `json:"schema_version"`
		Kind                      string                    `json:"kind"`
		ResolvedPlanID            schema.InstanceID         `json:"resolved_plan_id"`
		IntentPlanRef             schema.ObjectRef          `json:"intent_plan_ref"`
		Resolver                  schema.ArtifactPin        `json:"resolver"`
		CapabilityObservationRefs []schema.ObjectRef        `json:"capability_observation_refs"`
		SupportLockDigest         schema.Digest             `json:"support_lock_digest"`
		Artifacts                 []schema.ArtifactPin      `json:"artifacts"`
		Target                    schema.TargetResolution   `json:"target"`
		Scenarios                 []schema.ScenarioDecision `json:"scenarios"`
		DenominatorDigest         schema.Digest             `json:"denominator_digest"`
		Budget                    schema.BudgetPolicy       `json:"budget"`
		Runtime                   schema.RuntimePolicy      `json:"runtime"`
		Finalizers                []schema.FinalizerPlan    `json:"finalizers,omitempty"`
		Producer                  schema.Producer           `json:"producer"`
		CreatedAt                 schema.UTCTime            `json:"created_at"`
	}{"urn:agentapi-doctor:resolved-run-plan:v1alpha1", "ResolvedRunPlan", id, intent, resolver, nil, support, artifacts, target, decisions, denominator, policy, runtime, finalizers, producer, created}
	meta, err := schema.SealMeta(projection.SchemaVersion, projection.Kind, id, producer, created, projection)
	if err != nil {
		t.Fatal(err)
	}
	plan := schema.ResolvedRunPlan{EnvelopeMeta: meta, ResolvedPlanID: id, IntentPlanRef: intent, Resolver: resolver, SupportLockDigest: support, Artifacts: artifacts, Target: target, Scenarios: decisions, DenominatorDigest: denominator, Budget: policy, Runtime: runtime, Finalizers: finalizers}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

type scriptedRunner struct {
	mu            sync.Mutex
	outcomes      []Outcome
	errors        []error
	estimate      *budget.Usage
	calls         int
	finalized     []string
	finalizeError map[string]error
}

func (runner *scriptedRunner) Estimate(schema.ScenarioDecision) (budget.Usage, error) {
	if runner.estimate != nil {
		return *runner.estimate, nil
	}
	return budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 100, ArtifactBytes: 100}, nil
}
func (runner *scriptedRunner) Run(_ context.Context, _ Invocation) (Outcome, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	index := runner.calls
	runner.calls++
	var outcome Outcome
	if index < len(runner.outcomes) {
		outcome = runner.outcomes[index]
	}
	if index < len(runner.errors) && runner.errors[index] != nil {
		return Outcome{}, runner.errors[index]
	}
	return outcome, nil
}
func (runner *scriptedRunner) Finalize(_ context.Context, plan schema.FinalizerPlan) (budget.Usage, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.finalized = append(runner.finalized, plan.LeaseID)
	return budget.Usage{Requests: 1}, runner.finalizeError[plan.LeaseID]
}

type resolver struct {
	runner  Runner
	missing bool
}

func (value resolver) Resolve(schema.ArtifactPin) (Runner, error) {
	if value.missing {
		return nil, errors.New("missing driver")
	}
	return value.runner, nil
}
func (value resolver) ResolveFinalizer(schema.FinalizerPlan) (Runner, error) {
	return value.runner, nil
}

type contextWaitingRunner struct {
	started chan struct{}
}

func (runner *contextWaitingRunner) Estimate(schema.ScenarioDecision) (budget.Usage, error) {
	return budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 100, ArtifactBytes: 100}, nil
}

func (runner *contextWaitingRunner) Run(ctx context.Context, _ Invocation) (Outcome, error) {
	close(runner.started)
	<-ctx.Done()
	usage := budget.Usage{Requests: 1, RequestBytes: 10}
	return Outcome{}, &RunError{Class: ErrorHarness, Err: ctx.Err(), Usage: usage, UsageKnown: true}
}

func (*contextWaitingRunner) Finalize(context.Context, schema.FinalizerPlan) (budget.Usage, error) {
	return budget.Usage{}, nil
}

func passOutcome() Outcome {
	return Outcome{Verdict: schema.VerdictPass, EvidenceRefs: []schema.ObjectRef{{Kind: "Payload", ContentDigest: digest("evidence")}}, Usage: budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 20, ArtifactBytes: 20}}
}

func TestExecutePreservesDispositionAndEndpointVerdict(t *testing.T) {
	decisions := []schema.ScenarioDecision{{ScenarioID: "execute.case", Disposition: schema.DispositionExecute, Driver: driver()}, {ScenarioID: "unsupported.case", Disposition: schema.DispositionNotApplicable, ReasonCode: string(schema.ReasonUnsupportedCapability), Driver: driver()}}
	plan := testPlan(t, decisions, nil)
	runner := &scriptedRunner{outcomes: []Outcome{passOutcome()}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(100), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 1 || len(result.Cases) != 2 || result.Cases[0].Verdict == nil || *result.Cases[0].Verdict != schema.VerdictPass {
		t.Fatalf("result=%#v", result)
	}
	if result.Cases[1].Verdict != nil || result.Cases[1].ApplicableMember {
		t.Fatalf("not-applicable case gained a verdict: %#v", result.Cases[1])
	}
}

func TestExecutePreservesUnknownTokenUsage(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "unknown-usage.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	outcome := passOutcome()
	outcome.Usage.InputTokens = 7
	outcome.UnknownUsage = []string{"output_tokens"}
	estimate := budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 100, ArtifactBytes: 100, OutputTokens: 64}
	runner := &scriptedRunner{outcomes: []Outcome{outcome}, estimate: &estimate}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(180), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 1 {
		t.Fatalf("attempts = %#v", result.Attempts)
	}
	consumed := result.Attempts[0].ConsumedBudget
	if consumed.InputTokens == nil || *consumed.InputTokens != 7 || consumed.OutputTokens != nil || fmt.Sprint(consumed.Unknown) != "[output_tokens]" {
		t.Fatalf("unknown token usage was converted to zero: %#v", consumed)
	}
	if result.Budget.Consumed.InputTokens != 7 || result.Budget.Consumed.OutputTokens != 64 || fmt.Sprint(result.Budget.Unknown) != "[output_tokens]" {
		t.Fatalf("unknown token usage was not conservatively accounted: %#v", result.Budget)
	}
}

func TestExecutePreservesObservedZeroTokenUsage(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "observed-zero-usage.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	runner := &scriptedRunner{outcomes: []Outcome{passOutcome()}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(182), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	consumed := result.Attempts[0].ConsumedBudget
	if consumed.InputTokens == nil || *consumed.InputTokens != 0 || consumed.OutputTokens == nil || *consumed.OutputTokens != 0 || len(consumed.Unknown) != 0 {
		t.Fatalf("observed zero usage was converted to unknown: %#v", consumed)
	}
}

func TestExecutePreservesUnknownTokenUsageOnError(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "unknown-error-usage.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	estimate := budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 100, ArtifactBytes: 100, OutputTokens: 64}
	runner := &scriptedRunner{
		estimate: &estimate,
		errors:   []error{&RunError{Class: ErrorAuthentication, Err: errors.New("401"), UsageKnown: false}},
	}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(185), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].ReasonCode != schema.ReasonAuthenticationFailed {
		t.Fatalf("error attempts = %#v", result.Attempts)
	}
	consumed := result.Attempts[0].ConsumedBudget
	if consumed.InputTokens != nil || consumed.OutputTokens != nil || fmt.Sprint(consumed.Unknown) != "[input_tokens output_tokens]" {
		t.Fatalf("unknown error usage was presented as observed: %#v", consumed)
	}
	if result.Budget.Consumed != estimate || fmt.Sprint(result.Budget.Unknown) != "[input_tokens output_tokens]" {
		t.Fatalf("unknown error usage was not conservatively accounted: %#v", result.Budget)
	}
}

func TestExecuteReservationOvershootWithinRunBudgetPreservesVerdict(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "reservation-overshoot.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	estimate := budget.Usage{Requests: 1, RequestBytes: 10, ResponseBytes: 100, ArtifactBytes: 100, OutputTokens: 512}
	outcome := passOutcome()
	outcome.Usage.OutputTokens = 513
	runner := &scriptedRunner{outcomes: []Outcome{outcome}, estimate: &estimate}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(188), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Cases) != 1 || result.Cases[0].Verdict == nil || *result.Cases[0].Verdict != schema.VerdictPass || result.Cases[0].ReasonCode == schema.ReasonBudgetExhausted {
		t.Fatalf("in-budget reservation overshoot changed the target verdict: %#v", result.Cases)
	}
	if result.Budget.Exhausted || result.Budget.Overshoot.OutputTokens != 1 || result.Budget.Consumed.OutputTokens != 513 {
		t.Fatalf("in-budget reservation overshoot accounting = %#v", result.Budget)
	}
}

func TestExecuteRejectsInvalidUnknownUsageMetadata(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "invalid-unknown-usage.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	outcome := passOutcome()
	outcome.UnknownUsage = []string{"tokens"}
	runner := &scriptedRunner{outcomes: []Outcome{outcome}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(190), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Cases) != 1 || result.Cases[0].ExecutionStatus != schema.ExecutionErrored || result.Cases[0].ReasonCode != schema.ReasonHarnessError {
		t.Fatalf("invalid unknown usage metadata was accepted: %#v", result.Cases)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].ConsumedBudget.InputTokens != nil || result.Attempts[0].ConsumedBudget.OutputTokens != nil || fmt.Sprint(result.Attempts[0].ConsumedBudget.Unknown) != "[input_tokens output_tokens]" {
		t.Fatalf("invalid outcome usage was trusted: %#v", result.Attempts)
	}
	if fmt.Sprint(result.Budget.Unknown) != "[input_tokens output_tokens]" {
		t.Fatalf("invalid outcome lost conservative accounting metadata: %#v", result.Budget)
	}
}

func TestTransientRetriesButDriverErrorNeverBecomesTargetFail(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "retry.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	runner := &scriptedRunner{outcomes: []Outcome{{}, passOutcome()}, errors: []error{&RunError{Class: ErrorTransient, Err: errors.New("503")}, nil}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(200), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 2 || result.Cases[0].Verdict == nil || *result.Cases[0].Verdict != schema.VerdictPass {
		t.Fatalf("retry result=%#v", result)
	}
	brokenPlan := testPlan(t, []schema.ScenarioDecision{{ScenarioID: "driver.case", Disposition: schema.DispositionExecute, Driver: driver()}}, nil)
	broken, err := Execute(context.Background(), brokenPlan, brokenPlan.ContentDigest, Config{Runners: resolver{missing: true}, NewID: idSource(300), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if broken.Cases[0].Verdict != nil || broken.Cases[0].ExecutionStatus != schema.ExecutionErrored || len(broken.Cases[0].Findings) != 0 {
		t.Fatalf("driver error became target result: %#v", broken.Cases[0])
	}
}

func TestErrorEvidenceSurvivesRetryAndNonVerdictCase(t *testing.T) {
	decision := schema.ScenarioDecision{ScenarioID: "evidence.case", Disposition: schema.DispositionExecute, Driver: driver()}
	plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	firstRef := schema.ObjectRef{Kind: "Evidence", ContentDigest: digest("first-error-evidence")}
	final := passOutcome()
	finalRef := schema.ObjectRef{Kind: "Evidence", ContentDigest: digest("final-evidence")}
	final.EvidenceRefs = []schema.ObjectRef{finalRef}
	runner := &scriptedRunner{
		outcomes: []Outcome{{}, final},
		errors:   []error{&RunError{Class: ErrorTransient, Err: errors.New("503"), EvidenceRefs: []schema.ObjectRef{firstRef}}, nil},
	}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(250), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 2 || fmt.Sprint(result.Attempts[0].EvidenceRefs) != fmt.Sprint([]schema.ObjectRef{firstRef}) || fmt.Sprint(result.Attempts[1].EvidenceRefs) != fmt.Sprint([]schema.ObjectRef{finalRef}) {
		t.Fatalf("attempt evidence was lost or crossed attempts: %#v", result.Attempts)
	}
	if fmt.Sprint(result.Cases[0].EvidenceRefs) != fmt.Sprint([]schema.ObjectRef{firstRef, finalRef}) {
		t.Fatalf("case did not retain all attempt evidence: %#v", result.Cases[0])
	}

	authPlan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
	authRunner := &scriptedRunner{errors: []error{&RunError{Class: ErrorAuthentication, Err: errors.New("401"), EvidenceRefs: []schema.ObjectRef{firstRef}}}}
	authResult, err := Execute(context.Background(), authPlan, authPlan.ContentDigest, Config{Runners: resolver{runner: authRunner}, NewID: idSource(280), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(authResult.Cases) != 1 || authResult.Cases[0].Verdict != nil || fmt.Sprint(authResult.Cases[0].EvidenceRefs) != fmt.Sprint([]schema.ObjectRef{firstRef}) {
		t.Fatalf("authentication evidence was not preserved: %#v", authResult.Cases)
	}
}

func TestDependencyFailureSkipsDependentWithAttemptIdentity(t *testing.T) {
	fail := passOutcome()
	fail.Verdict = schema.VerdictFail
	decisions := []schema.ScenarioDecision{{ScenarioID: "parent", Disposition: schema.DispositionExecute, Driver: driver()}, {ScenarioID: "child", Disposition: schema.DispositionExecute, Driver: driver(), DependsOn: []string{"parent"}}}
	plan := testPlan(t, decisions, nil)
	runner := &scriptedRunner{outcomes: []Outcome{fail}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(400), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Cases[1].ExecutionStatus != schema.ExecutionSkipped || result.Cases[1].Verdict != nil || len(result.Cases[1].AttemptIDs) != 1 {
		t.Fatalf("dependent=%#v", result.Cases[1])
	}
}

func TestFinalizersAreLIFOAndFailuresRemainResidual(t *testing.T) {
	finalizers := []schema.FinalizerPlan{{LeaseID: "first", ResourceType: "fixture", Operation: "delete", CleanupBudget: hard(1)}, {LeaseID: "second", ResourceType: "fixture", Operation: "delete", CleanupBudget: hard(1)}}
	plan := testPlan(t, []schema.ScenarioDecision{{ScenarioID: "one", Disposition: schema.DispositionExecute, Driver: driver()}}, finalizers)
	runner := &scriptedRunner{outcomes: []Outcome{passOutcome()}, finalizeError: map[string]error{"first": errors.New("still present")}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(500), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(runner.finalized) != "[second first]" || fmt.Sprint(result.ResidualLeases) != "[first]" {
		t.Fatalf("order=%v residual=%v", runner.finalized, result.ResidualLeases)
	}
}

func TestExecuteRejectsUnapprovedDigest(t *testing.T) {
	plan := testPlan(t, []schema.ScenarioDecision{{ScenarioID: "one", Disposition: schema.DispositionExecute, Driver: driver()}}, nil)
	_, err := Execute(context.Background(), plan, digest("different"), Config{Runners: resolver{runner: &scriptedRunner{}}, NewID: idSource(600)})
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
}

func TestInvalidRunnerOutcomeIsHarnessErrorWithoutFinding(t *testing.T) {
	plan := testPlan(t, []schema.ScenarioDecision{{ScenarioID: "one", Disposition: schema.DispositionExecute, Driver: driver()}}, nil)
	runner := &scriptedRunner{outcomes: []Outcome{{Verdict: schema.VerdictFail, Findings: []schema.Finding{{Category: "invented"}}, Usage: budget.Usage{Requests: 1}}}}
	result, err := Execute(context.Background(), plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(700), Now: func() time.Time { return time.Unix(2, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Cases[0].Verdict != nil || len(result.Cases[0].Findings) != 0 || result.Cases[0].ReasonCode != schema.ReasonHarnessError {
		t.Fatalf("invalid outcome escaped: %#v", result.Cases[0])
	}
}

func TestCancellationStillRunsBoundedFinalizers(t *testing.T) {
	plan := testPlan(t, []schema.ScenarioDecision{{ScenarioID: "one", Disposition: schema.DispositionExecute, Driver: driver()}}, []schema.FinalizerPlan{{LeaseID: "lease", ResourceType: "fixture", Operation: "delete", CleanupBudget: hard(1)}})
	runner := &scriptedRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Execute(ctx, plan, plan.ContentDigest, Config{Runners: resolver{runner: runner}, NewID: idSource(800), Now: func() time.Time { return time.Unix(2, 0) }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if fmt.Sprint(runner.finalized) != "[lease]" || len(result.ResidualLeases) != 0 {
		t.Fatalf("finalized=%v residual=%v", runner.finalized, result.ResidualLeases)
	}
	if result.Cases[0].ExecutionStatus != schema.ExecutionCancelled || result.Cases[0].Verdict != nil {
		t.Fatalf("case=%#v", result.Cases[0])
	}
}

func TestActiveFinalScenarioPropagatesCancellationAndDeadline(t *testing.T) {
	tests := []struct {
		name       string
		newContext func(<-chan struct{}) (context.Context, context.CancelFunc)
		wantError  error
		wantReason schema.ReasonCode
	}{
		{
			name: "caller cancellation",
			newContext: func(started <-chan struct{}) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					<-started
					cancel()
				}()
				return ctx, cancel
			},
			wantError: context.Canceled, wantReason: schema.ReasonCancelledByUser,
		},
		{
			name: "run deadline",
			newContext: func(<-chan struct{}) (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			wantError: context.DeadlineExceeded, wantReason: schema.ReasonBudgetExhausted,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := schema.ScenarioDecision{ScenarioID: "final", Disposition: schema.DispositionExecute, Driver: driver()}
			plan := testPlan(t, []schema.ScenarioDecision{decision}, nil)
			runner := &contextWaitingRunner{started: make(chan struct{})}
			ctx, cancel := test.newContext(runner.started)
			defer cancel()
			result, err := Execute(ctx, plan, plan.ContentDigest, Config{
				Runners: resolver{runner: runner}, NewID: idSource(900), Now: func() time.Time { return time.Unix(2, 0) },
			})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("terminal error = %v, want %v", err, test.wantError)
			}
			if len(result.Cases) != 1 || result.Cases[0].ExecutionStatus != schema.ExecutionCancelled || result.Cases[0].ReasonCode != test.wantReason || result.Cases[0].Verdict != nil {
				t.Fatalf("final cancelled case = %#v", result.Cases)
			}
		})
	}
}
