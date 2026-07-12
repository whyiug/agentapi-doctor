// Package executor runs an exact ResolvedRunPlan. It owns lifecycle, budget,
// retry, and finalizer semantics while protocol-specific work is delegated to
// a Runner selected by an exact driver digest.
package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type ErrorClass string

const (
	ErrorTransient      ErrorClass = "transient"
	ErrorAuthentication ErrorClass = "authentication"
	ErrorPermission     ErrorClass = "permission"
	ErrorDriver         ErrorClass = "driver"
	ErrorHarness        ErrorClass = "harness"
)

type RunError struct {
	Class      ErrorClass
	Err        error
	Usage      budget.Usage
	UsageKnown bool
	// EvidenceRefs preserves observations already committed before a
	// non-verdict terminal condition such as authentication or transport
	// failure. The executor validates and carries them into the attempt/case.
	EvidenceRefs []schema.ObjectRef
}

func (runError *RunError) Error() string {
	if runError == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %v", runError.Class, runError.Err)
}
func (runError *RunError) Unwrap() error {
	if runError == nil {
		return nil
	}
	return runError.Err
}

type Invocation struct {
	RunID         schema.InstanceID
	InvocationID  schema.InstanceID
	AttemptID     schema.InstanceID
	PlanDigest    schema.Digest
	Scenario      schema.ScenarioDecision
	AttemptNumber int64
}

// Outcome is returned only after the runner has completed the target
// observation path. Harness/driver failures are returned as errors and cannot
// carry endpoint findings.
type Outcome struct {
	Verdict          schema.Verdict
	ReasonCode       schema.ReasonCode
	EvidenceRefs     []schema.ObjectRef
	AssertionResults []schema.AssertionResult
	Findings         []schema.Finding
	Usage            budget.Usage
}

type Runner interface {
	Estimate(schema.ScenarioDecision) (budget.Usage, error)
	Run(context.Context, Invocation) (Outcome, error)
	Finalize(context.Context, schema.FinalizerPlan) (budget.Usage, error)
}

type RunnerResolver interface {
	Resolve(schema.ArtifactPin) (Runner, error)
}

type IDSource func() (schema.InstanceID, error)

type Config struct {
	Runners RunnerResolver
	NewID   IDSource
	Now     func() time.Time
}

type Result struct {
	RunID           schema.InstanceID   `json:"run_id"`
	ResolvedPlanRef schema.ObjectRef    `json:"resolved_plan_ref"`
	Attempts        []schema.Attempt    `json:"attempts"`
	Cases           []schema.CaseResult `json:"cases"`
	Budget          budget.Snapshot     `json:"budget"`
	ResidualLeases  []string            `json:"residual_leases,omitempty"`
	StartedAt       schema.UTCTime      `json:"started_at"`
	FinishedAt      schema.UTCTime      `json:"finished_at"`
}

func Execute(ctx context.Context, plan schema.ResolvedRunPlan, expectedDigest schema.Digest, config Config) (Result, error) {
	if err := plan.Validate(); err != nil {
		return Result{}, fmt.Errorf("resolved plan: %w", err)
	}
	if expectedDigest != plan.ContentDigest {
		return Result{}, errors.New("resolved plan digest does not match the approved digest")
	}
	if config.Runners == nil {
		return Result{}, errors.New("runner resolver is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = func() (schema.InstanceID, error) { return schema.NewInstanceID(config.Now, nil) }
	}
	runID, err := config.NewID()
	if err != nil {
		return Result{}, err
	}
	ledger, err := budget.New(plan.Budget, config.Now)
	if err != nil {
		return Result{}, err
	}
	result := Result{RunID: runID, ResolvedPlanRef: plan.ObjectRef, StartedAt: schema.NewUTCTime(config.Now())}
	states := make(map[string]schema.CaseResult, len(plan.Scenarios))
	var executionErr error
	for _, decision := range plan.Scenarios {
		if err := ctx.Err(); err != nil {
			executionErr = err
			if decision.Disposition == schema.DispositionExecute {
				caseResult, attempt := nonRunAttempt(runID, decision, schema.ExecutionCancelled, contextReason(err), config.NewID)
				result.Attempts = append(result.Attempts, attempt)
				result.Cases = append(result.Cases, caseResult)
				states[decision.ScenarioID] = caseResult
			} else {
				caseResult := plannedOnlyCase(decision)
				result.Cases = append(result.Cases, caseResult)
				states[decision.ScenarioID] = caseResult
			}
			continue
		}
		if decision.Disposition != schema.DispositionExecute {
			caseResult := plannedOnlyCase(decision)
			result.Cases = append(result.Cases, caseResult)
			states[decision.ScenarioID] = caseResult
			continue
		}
		if dependency := failedDependency(decision, states); dependency != "" {
			caseResult, attempt := nonRunAttempt(runID, decision, schema.ExecutionSkipped, schema.ReasonHarnessError, config.NewID)
			result.Attempts = append(result.Attempts, attempt)
			result.Cases = append(result.Cases, caseResult)
			states[decision.ScenarioID] = caseResult
			continue
		}
		runner, resolveErr := config.Runners.Resolve(decision.Driver)
		if resolveErr != nil {
			caseResult, attempt := nonRunAttempt(runID, decision, schema.ExecutionErrored, schema.ReasonDriverError, config.NewID)
			result.Attempts = append(result.Attempts, attempt)
			result.Cases = append(result.Cases, caseResult)
			states[decision.ScenarioID] = caseResult
			continue
		}
		caseResult, attempts := runScenario(ctx, runID, plan, decision, runner, ledger, config)
		result.Attempts = append(result.Attempts, attempts...)
		result.Cases = append(result.Cases, caseResult)
		states[decision.ScenarioID] = caseResult
		// A cancellation that occurs while the final scenario is running has no
		// subsequent loop iteration in which to observe ctx.Err(). Preserve it
		// immediately so callers receive the same terminal error regardless of
		// which scenario was active when the run stopped.
		if caseResult.ExecutionStatus == schema.ExecutionCancelled {
			if err := ctx.Err(); err != nil {
				executionErr = err
			}
		}
	}
	// The optional resolver extension below runs finalizers without weakening
	// the required Runner interface for simple built-in drivers.
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), plan.Budget.Cleanup.MaxDuration.Duration())
	result.ResidualLeases = finalize(cleanupContext, plan.Finalizers, config.Runners, ledger)
	cancelCleanup()
	result.Budget = ledger.Snapshot()
	result.FinishedAt = schema.NewUTCTime(config.Now())
	return result, executionErr
}

// finalizerResolver allows one resolver to route leases independently from a
// scenario driver. Implementations that do not provide it leave leases as
// residual rather than pretending cleanup succeeded.
type finalizerResolver interface {
	ResolveFinalizer(schema.FinalizerPlan) (Runner, error)
}

// ResolveFinalizer is provided through this helper to keep the public
// RunnerResolver interface minimal. It is not a method on RunnerResolver.
func resolveFinalizer(resolver RunnerResolver, plan schema.FinalizerPlan) (Runner, error) {
	typed, ok := resolver.(finalizerResolver)
	if !ok {
		return nil, errors.New("no finalizer resolver")
	}
	return typed.ResolveFinalizer(plan)
}

func finalize(ctx context.Context, plans []schema.FinalizerPlan, resolver RunnerResolver, ledger *budget.Ledger) []string {
	residual := []string{}
	for index := len(plans) - 1; index >= 0; index-- {
		plan := plans[index]
		runner, err := resolveFinalizer(resolver, plan)
		if err != nil {
			residual = append(residual, plan.LeaseID)
			continue
		}
		usage, err := runner.Finalize(ctx, plan)
		if err != nil {
			residual = append(residual, plan.LeaseID)
			continue
		}
		if err := ledger.ConsumeCleanup(usage); err != nil {
			residual = append(residual, plan.LeaseID)
		}
	}
	return residual
}

func runScenario(ctx context.Context, runID schema.InstanceID, plan schema.ResolvedRunPlan, decision schema.ScenarioDecision, runner Runner, ledger *budget.Ledger, config Config) (schema.CaseResult, []schema.Attempt) {
	invocationID, idErr := config.NewID()
	if idErr != nil {
		caseResult, attempt := nonRunAttempt(runID, decision, schema.ExecutionErrored, schema.ReasonHarnessError, config.NewID)
		return caseResult, []schema.Attempt{attempt}
	}
	attempts := []schema.Attempt{}
	attemptIDs := []schema.InstanceID{}
	caseEvidenceRefs := []schema.ObjectRef{}
	maxAttempts := plan.Runtime.Retries + 1
	for number := int64(1); number <= maxAttempts; number++ {
		attemptID, err := config.NewID()
		if err != nil {
			break
		}
		attemptIDs = append(attemptIDs, attemptID)
		estimate, err := runner.Estimate(decision)
		if err != nil {
			attempts = append(attempts, erroredAttempt(invocationID, attemptID, decision.Driver, schema.ReasonHarnessError))
			return caseForAttempts(decision, attemptIDs, schema.ExecutionErrored, nil, schema.ReasonHarnessError, nil, nil), attempts
		}
		reservation, err := ledger.Reserve(estimate)
		if err != nil {
			attempts = append(attempts, skippedAttempt(invocationID, attemptID, decision.Driver, schema.ReasonBudgetExhausted))
			return caseForAttempts(decision, attemptIDs, schema.ExecutionSkipped, nil, schema.ReasonBudgetExhausted, nil, nil), attempts
		}
		outcome, runErr := runner.Run(ctx, Invocation{RunID: runID, InvocationID: invocationID, AttemptID: attemptID, PlanDigest: plan.ContentDigest, Scenario: decision, AttemptNumber: number})
		if runErr != nil {
			actual := estimate
			var typed *RunError
			attemptEvidenceRefs := []schema.ObjectRef{}
			if errors.As(runErr, &typed) {
				if typed.UsageKnown {
					actual = typed.Usage
				}
				if err := validateEvidenceRefs(typed.EvidenceRefs); err != nil {
					runErr = &RunError{Class: ErrorHarness, Err: fmt.Errorf("runner returned invalid error evidence: %w", err), Usage: actual, UsageKnown: typed.UsageKnown}
				} else {
					attemptEvidenceRefs = append([]schema.ObjectRef(nil), typed.EvidenceRefs...)
					caseEvidenceRefs = appendUniqueEvidenceRefs(caseEvidenceRefs, typed.EvidenceRefs...)
				}
			}
			_ = reservation.Commit(actual)
			reason, class := reasonForError(ctx, runErr)
			status := schema.ExecutionErrored
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				status = schema.ExecutionCancelled
			}
			attempts = append(attempts, schema.Attempt{AttemptID: attemptID, InvocationID: invocationID, ExecutionStatus: status, ReasonCode: reason, EvidenceRefs: attemptEvidenceRefs, Driver: decision.Driver, ConsumedBudget: consumption(actual)})
			if class == ErrorTransient && number < maxAttempts {
				continue
			}
			result := caseForAttempts(decision, attemptIDs, status, nil, reason, nil, nil)
			result.EvidenceRefs = append([]schema.ObjectRef(nil), caseEvidenceRefs...)
			return result, attempts
		}
		if validationErr := validateOutcome(outcome); validationErr != nil {
			_ = reservation.Commit(outcome.Usage)
			attemptEvidenceRefs := []schema.ObjectRef{}
			if validateEvidenceRefs(outcome.EvidenceRefs) == nil {
				attemptEvidenceRefs = append([]schema.ObjectRef(nil), outcome.EvidenceRefs...)
				caseEvidenceRefs = appendUniqueEvidenceRefs(caseEvidenceRefs, outcome.EvidenceRefs...)
			}
			attempt := erroredAttempt(invocationID, attemptID, decision.Driver, schema.ReasonHarnessError)
			attempt.EvidenceRefs = attemptEvidenceRefs
			attempts = append(attempts, attempt)
			result := caseForAttempts(decision, attemptIDs, schema.ExecutionErrored, nil, schema.ReasonHarnessError, nil, nil)
			result.EvidenceRefs = append([]schema.ObjectRef(nil), caseEvidenceRefs...)
			return result, attempts
		}
		caseEvidenceRefs = appendUniqueEvidenceRefs(caseEvidenceRefs, outcome.EvidenceRefs...)
		commitErr := reservation.Commit(outcome.Usage)
		attempt := schema.Attempt{AttemptID: attemptID, InvocationID: invocationID, ExecutionStatus: schema.ExecutionCompleted, ReasonCode: outcome.ReasonCode, EvidenceRefs: append([]schema.ObjectRef(nil), outcome.EvidenceRefs...), Driver: decision.Driver, ConsumedBudget: consumption(outcome.Usage)}
		attempts = append(attempts, attempt)
		if commitErr != nil {
			result := caseForAttempts(decision, attemptIDs, schema.ExecutionCompleted, &outcome.Verdict, schema.ReasonBudgetExhausted, outcome.AssertionResults, outcome.Findings)
			result.EvidenceRefs = append([]schema.ObjectRef(nil), caseEvidenceRefs...)
			return result, attempts
		}
		result := caseForAttempts(decision, attemptIDs, schema.ExecutionCompleted, &outcome.Verdict, outcome.ReasonCode, outcome.AssertionResults, outcome.Findings)
		result.EvidenceRefs = append([]schema.ObjectRef(nil), caseEvidenceRefs...)
		return result, attempts
	}
	return caseForAttempts(decision, attemptIDs, schema.ExecutionErrored, nil, schema.ReasonHarnessError, nil, nil), attempts
}

func plannedOnlyCase(decision schema.ScenarioDecision) schema.CaseResult {
	applicable := decision.Disposition == schema.DispositionSkip
	return schema.CaseResult{ScenarioID: decision.ScenarioID, PlanDisposition: decision.Disposition, ExecutionStatus: schema.ExecutionSkipped, ReasonCode: schema.ReasonCode(decision.ReasonCode), CandidateMember: true, ApplicableMember: applicable, ExecutedMember: false, AttemptAggregation: "none"}
}

func failedDependency(decision schema.ScenarioDecision, states map[string]schema.CaseResult) string {
	for _, dependency := range decision.DependsOn {
		state := states[dependency]
		if state.ExecutionStatus != schema.ExecutionCompleted || state.Verdict == nil || *state.Verdict == schema.VerdictFail || *state.Verdict == schema.VerdictInconclusive {
			return dependency
		}
	}
	return ""
}

func nonRunAttempt(_ schema.InstanceID, decision schema.ScenarioDecision, status schema.ExecutionStatus, reason schema.ReasonCode, newID IDSource) (schema.CaseResult, schema.Attempt) {
	invocationID, _ := newID()
	attemptID, _ := newID()
	attempt := schema.Attempt{AttemptID: attemptID, InvocationID: invocationID, ExecutionStatus: status, ReasonCode: reason, Driver: decision.Driver, ConsumedBudget: schema.BudgetConsumption{}}
	return caseForAttempts(decision, []schema.InstanceID{attemptID}, status, nil, reason, nil, nil), attempt
}
func erroredAttempt(invocationID, attemptID schema.InstanceID, driver schema.ArtifactPin, reason schema.ReasonCode) schema.Attempt {
	return schema.Attempt{AttemptID: attemptID, InvocationID: invocationID, ExecutionStatus: schema.ExecutionErrored, ReasonCode: reason, Driver: driver, ConsumedBudget: schema.BudgetConsumption{}}
}
func skippedAttempt(invocationID, attemptID schema.InstanceID, driver schema.ArtifactPin, reason schema.ReasonCode) schema.Attempt {
	return schema.Attempt{AttemptID: attemptID, InvocationID: invocationID, ExecutionStatus: schema.ExecutionSkipped, ReasonCode: reason, Driver: driver, ConsumedBudget: schema.BudgetConsumption{}}
}
func caseForAttempts(decision schema.ScenarioDecision, ids []schema.InstanceID, status schema.ExecutionStatus, verdict *schema.Verdict, reason schema.ReasonCode, assertions []schema.AssertionResult, findings []schema.Finding) schema.CaseResult {
	return schema.CaseResult{ScenarioID: decision.ScenarioID, PlanDisposition: decision.Disposition, AttemptIDs: append([]schema.InstanceID(nil), ids...), ExecutionStatus: status, Verdict: verdict, ReasonCode: reason, AssertionResults: append([]schema.AssertionResult(nil), assertions...), Findings: append([]schema.Finding(nil), findings...), CandidateMember: true, ApplicableMember: true, ExecutedMember: status == schema.ExecutionCompleted, AttemptAggregation: "last_completed"}
}
func reasonForError(ctx context.Context, err error) (schema.ReasonCode, ErrorClass) {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextReason(contextErr), ErrorHarness
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return schema.ReasonBudgetExhausted, ErrorHarness
	}
	if errors.Is(err, context.Canceled) {
		return schema.ReasonCancelledByUser, ErrorHarness
	}
	var typed *RunError
	if !errors.As(err, &typed) {
		return schema.ReasonHarnessError, ErrorHarness
	}
	switch typed.Class {
	case ErrorAuthentication:
		return schema.ReasonAuthenticationFailed, typed.Class
	case ErrorPermission:
		return schema.ReasonPermissionDenied, typed.Class
	case ErrorTransient:
		return schema.ReasonTransientError, typed.Class
	case ErrorDriver:
		return schema.ReasonDriverError, typed.Class
	default:
		return schema.ReasonHarnessError, typed.Class
	}
}

func contextReason(err error) schema.ReasonCode {
	if errors.Is(err, context.DeadlineExceeded) {
		return schema.ReasonBudgetExhausted
	}
	return schema.ReasonCancelledByUser
}
func consumption(usage budget.Usage) schema.BudgetConsumption {
	return schema.BudgetConsumption{Requests: usage.Requests, RequestBytes: usage.RequestBytes, ResponseBytes: usage.ResponseBytes, ArtifactBytes: usage.ArtifactBytes, InputTokens: pointerIfKnown(usage.InputTokens), OutputTokens: pointerIfKnown(usage.OutputTokens)}
}
func pointerIfKnown(value int64) *int64 { result := value; return &result }

func validateOutcome(outcome Outcome) error {
	if outcome.Verdict != schema.VerdictPass && outcome.Verdict != schema.VerdictFail && outcome.Verdict != schema.VerdictWarn && outcome.Verdict != schema.VerdictInconclusive {
		return fmt.Errorf("invalid completed verdict %q", outcome.Verdict)
	}
	if len(outcome.EvidenceRefs) == 0 {
		return errors.New("completed outcome requires evidence")
	}
	if err := validateEvidenceRefs(outcome.EvidenceRefs); err != nil {
		return err
	}
	for _, assertion := range outcome.AssertionResults {
		if err := assertion.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceRefs(refs []schema.ObjectRef) error {
	for index, ref := range refs {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("evidence ref %d: %w", index, err)
		}
	}
	return nil
}

func appendUniqueEvidenceRefs(destination []schema.ObjectRef, refs ...schema.ObjectRef) []schema.ObjectRef {
	seen := make(map[schema.ObjectRef]struct{}, len(destination)+len(refs))
	for _, ref := range destination {
		seen[ref] = struct{}{}
	}
	for _, ref := range refs {
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		destination = append(destination, ref)
	}
	return destination
}
