package productrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/executor"
	"github.com/whyiug/agentapi-doctor/internal/rawdriver"
	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
	"github.com/whyiug/agentapi-doctor/internal/secret"
	"github.com/whyiug/agentapi-doctor/internal/transport"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type SecretResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}

type ExecuteRequest struct {
	Planned     PlannedRun
	DataRoot    string
	Secrets     SecretResolver
	NetworkMode transport.NetworkMode
	Now         func() time.Time
	NewID       IDSource
}

type Execution struct {
	ExecutorResult executor.Result `json:"executor_result"`
	Report         report.Bundle   `json:"report"`
	ReportJSON     []byte          `json:"report_json"`
	RecordDigest   schema.Digest   `json:"record_digest"`
}

// Execute validates and re-derives the offline plan before making any
// request, then runs only the frozen exact-origin scenarios. It persists the
// canonical report bundle after redaction and returns any cancellation error
// only after preserving the partial run record.
func Execute(ctx context.Context, request ExecuteRequest) (Execution, error) {
	if ctx == nil {
		return Execution{}, errors.New("context is required")
	}
	derived, route, err := validatePlanned(request.Planned)
	if err != nil {
		return Execution{}, err
	}
	if err := ensureDataRoot(request.DataRoot); err != nil {
		return Execution{}, err
	}
	mode := request.NetworkMode
	if mode == "" {
		mode = transport.NetworkLocalTarget
	}

	headers, secretValue, sensitiveNames, err := resolveAuth(ctx, request.Planned.Target, request.Secrets)
	if err != nil {
		return Execution{}, err
	}
	if len(secretValue) > 0 {
		defer secret.Wipe(secretValue)
	}
	canaries := [][]byte(nil)
	if len(secretValue) > 0 {
		if len(secretValue) < 8 {
			return Execution{}, errors.New("resolved credential must contain at least 8 bytes for exact redaction-canary enforcement")
		}
		canaries = append(canaries, secretValue)
	}
	redactorInstance, err := redaction.New(sensitiveNames, canaries)
	if err != nil {
		return Execution{}, fmt.Errorf("configure redaction: %w", err)
	}

	scenarios := materializeScenarios(derived, request.Planned.Resolved.ContentDigest, headers)
	registry, err := rawdriver.NewMemoryRegistry(scenarios...)
	if err != nil {
		return Execution{}, fmt.Errorf("register exact scenarios: %w", err)
	}
	defer registry.Clear()

	evidenceStore, err := cas.Open(filepath.Join(request.DataRoot, "evidence"), max(2<<20, request.Planned.Resolved.Budget.Hard.MaxResponseBytes+1<<20))
	if err != nil {
		return Execution{}, fmt.Errorf("open evidence store: %w", err)
	}
	responseLimit := maxMaterialResponse(derived.materials)
	if responseLimit > request.Planned.Resolved.Budget.Hard.MaxResponseBytes {
		responseLimit = request.Planned.Resolved.Budget.Hard.MaxResponseBytes
	}
	parsedOrigin, _ := url.Parse(route.origin)
	client, err := transport.New(transport.Policy{
		AllowedOrigin: route.origin, Mode: mode, Redirects: transport.RedirectNone,
		AllowPlainHTTP:   parsedOrigin.Scheme == "http",
		MaxRequestBytes:  request.Planned.Resolved.Budget.Hard.MaxRequestBytes,
		MaxResponseBytes: responseLimit, Timeout: request.Planned.Resolved.Runtime.Timeout.Duration(),
	})
	if err != nil {
		return Execution{}, fmt.Errorf("create origin-bound transport: %w", err)
	}
	defer client.CloseIdleConnections()

	now := request.Now
	if now == nil {
		now = time.Now
	}
	newID := request.NewID
	if newID == nil {
		newID = func() (schema.InstanceID, error) { return schema.NewInstanceID(now, nil) }
	}
	runner, err := rawdriver.New(rawdriver.Config{
		Registry: registry, Transport: client, Store: evidenceStore,
		Redactor: redactorInstance, Producer: request.Planned.Intent.Producer,
		NewID: rawdriver.IDSource(newID), Now: now,
	})
	if err != nil {
		return Execution{}, fmt.Errorf("create raw driver: %w", err)
	}
	classifiedRunner := newClassifyingRunner(runner)
	resolver, err := NewExactResolver(derived.driver, classifiedRunner)
	if err != nil {
		return Execution{}, err
	}
	executionContext, cancel := context.WithTimeout(ctx, request.Planned.Resolved.Runtime.Timeout.Duration())
	result, executionErr := executor.Execute(executionContext, request.Planned.Resolved, request.Planned.Resolved.ContentDigest, executor.Config{
		Runners: resolver, NewID: executor.IDSource(newID), Now: now,
	})
	cancel()
	if result.RunID == "" {
		if executionErr == nil {
			executionErr = errors.New("executor returned no run identity")
		}
		return Execution{}, executionErr
	}
	bundle, err := buildReport(request.Planned, derived, result, classifiedRunner.snapshot())
	if err != nil {
		return Execution{}, fmt.Errorf("build report: %w", err)
	}
	encoded, err := report.JSON(bundle)
	if err != nil {
		return Execution{}, fmt.Errorf("encode report: %w", err)
	}
	if err := redactorInstance.AssertNoCanary(encoded); err != nil {
		return Execution{}, errors.New("report failed the credential-canary persistence invariant")
	}
	redactedReport, _, err := redactorInstance.RedactJSON(encoded)
	if err != nil {
		return Execution{}, fmt.Errorf("verify report redaction invariant: %w", err)
	}
	if !bytes.Equal(encoded, redactedReport) {
		return Execution{}, errors.New("report contains material that was not redacted before serialization")
	}
	runs, err := runstore.Open(filepath.Join(request.DataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if err != nil {
		return Execution{}, fmt.Errorf("open run store: %w", err)
	}
	recordDigest, err := runs.Put(result.RunID, encoded)
	if err != nil {
		return Execution{}, fmt.Errorf("persist report: %w", err)
	}
	execution := Execution{ExecutorResult: result, Report: bundle, ReportJSON: encoded, RecordDigest: recordDigest}
	if executionErr != nil {
		return execution, executionErr
	}
	return execution, nil
}

func materializeScenarios(derived artifacts, planDigest schema.Digest, auth http.Header) []rawdriver.Scenario {
	result := make([]rawdriver.Scenario, 0, len(derived.materials))
	for _, material := range derived.materials {
		headers := material.Headers.Clone()
		for name, values := range auth {
			headers[name] = slices.Clone(values)
		}
		result = append(result, rawdriver.Scenario{
			PlanDigest: planDigest, ID: material.Descriptor.ID, Driver: derived.driver,
			Protocol: material.Descriptor.Protocol, Method: material.Method, Path: material.Path,
			Headers: headers, Body: slices.Clone(material.Body), Streaming: material.Descriptor.Streaming,
			ExpectedStatus: material.ExpectedStatus, Budget: material.Budget,
			Assertion: rawdriver.AssertionSpec{
				AssertionID:   "builtin." + material.Descriptor.ID,
				RequirementID: material.Descriptor.RequirementID, Role: schema.AssertionNormative,
				Oracle: derived.oracle, EvaluatorDigest: derived.evaluator,
				Check: material.Descriptor.Check, AllowedValues: slices.Clone(material.Descriptor.AllowedValues),
			},
		})
	}
	return result
}

func resolveAuth(ctx context.Context, target config.Target, resolver SecretResolver) (http.Header, []byte, []string, error) {
	headers := make(http.Header)
	if target.Auth == nil {
		return headers, nil, nil, nil
	}
	if resolver == nil {
		return nil, nil, nil, errors.New("target authentication requires an explicit secret resolver")
	}
	value, err := resolver.Resolve(ctx, target.Auth.Token.Ref)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve target credential: %w", err)
	}
	if len(value) == 0 {
		return nil, nil, nil, errors.New("resolved credential is empty")
	}
	headerName, err := authHeaderName(target)
	if err != nil {
		secret.Wipe(value)
		return nil, nil, nil, err
	}
	headerValue := "Bearer " + string(value)
	if target.Auth.Type == "header" {
		headerValue = string(value)
	}
	headers.Set(headerName, headerValue)
	return headers, value, []string{headerName}, nil
}

func validateAuthConfig(target config.Target) error {
	if target.Auth == nil {
		return nil
	}
	_, err := authHeaderName(target)
	return err
}

func authHeaderName(target config.Target) (string, error) {
	name := "Authorization"
	if target.Auth != nil && target.Auth.Type == "header" {
		name = target.Auth.Header
	}
	if name == "" {
		return "", errors.New("authentication header name is required")
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return "", fmt.Errorf("authentication header %q is not a valid HTTP field name", name)
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "upgrade", "content-type", "accept", "anthropic-version":
		return "", fmt.Errorf("authentication header %q conflicts with a transport or protocol-controlled header", name)
	}
	return name, nil
}

func buildReport(planned PlannedRun, derived artifacts, result executor.Result, classes map[string]executor.ErrorClass) (report.Bundle, error) {
	candidateIDs := make([]string, 0, len(result.Cases))
	applicableIDs := make([]string, 0, len(result.Cases))
	executedIDs := make([]string, 0, len(result.Cases))
	for _, item := range result.Cases {
		if item.CandidateMember {
			candidateIDs = append(candidateIDs, item.ScenarioID)
		}
		if item.ApplicableMember {
			applicableIDs = append(applicableIDs, item.ScenarioID)
		}
		if item.ExecutedMember {
			executedIDs = append(executedIDs, item.ScenarioID)
		}
	}
	for _, values := range [][]string{candidateIDs, applicableIDs, executedIDs} {
		sort.Strings(values)
	}
	candidateDigest, err := schema.CanonicalDigest(candidateIDs)
	if err != nil {
		return report.Bundle{}, err
	}
	applicableDigest, err := schema.CanonicalDigest(applicableIDs)
	if err != nil {
		return report.Bundle{}, err
	}
	executedDigest, err := schema.CanonicalDigest(executedIDs)
	if err != nil {
		return report.Bundle{}, err
	}
	if candidateDigest != planned.Intent.CandidateDenominatorDigest || applicableDigest != planned.Resolved.DenominatorDigest {
		return report.Bundle{}, errors.New("executor denominator membership differs from the resolved plan")
	}
	outcome, dimension, exitCode := aggregate(result.Cases, classes)
	conditions := []report.Condition{{
		Code:    "candidate_interpretations_pending_review",
		Message: "This local raw-wire slice uses candidate Requirement Catalog interpretations pending independent review; it does not establish a support tier or vendor certification.",
	}}
	classIDs := make([]string, 0, len(classes))
	for scenarioID := range classes {
		classIDs = append(classIDs, scenarioID)
	}
	sort.Strings(classIDs)
	for _, scenarioID := range classIDs {
		class := classes[scenarioID]
		code, message := "execution_error", "The scenario ended before a target verdict."
		switch class {
		case executor.ErrorAuthentication:
			code, message = "authentication_failed", "The target rejected authentication; no protocol verdict was produced."
		case executor.ErrorPermission:
			code, message = "permission_failed", "The target denied permission; no protocol verdict was produced."
		case executor.ErrorTransient:
			code, message = "transient_error", "The target returned a transient status; no protocol verdict was produced."
		case executor.ErrorDriver:
			code, message = "driver_error", "The raw transport failed before a target verdict was produced."
		case executor.ErrorHarness:
			code, message = "harness_error", "The local harness failed before a target verdict was produced."
		}
		conditions = append(conditions, report.Condition{Code: code, Message: "Scenario " + scenarioID + ": " + message})
	}
	bundle := report.Bundle{
		SchemaVersion: report.SchemaVersion, RunID: result.RunID,
		IntentPlanRef: planned.Intent.ObjectRef, ResolvedPlanRef: planned.Resolved.ObjectRef,
		Profile: derived.profile, Artifacts: slices.Clone(planned.Resolved.Artifacts), SupportLock: planned.Resolved.SupportLockDigest,
		Denominators: schema.DenominatorSummary{
			CandidateDigest: candidateDigest, CandidateCount: int64(len(candidateIDs)),
			ApplicableDigest: applicableDigest, ApplicableCount: int64(len(applicableIDs)),
			ExecutedDigest: executedDigest, ExecutedCount: int64(len(executedIDs)),
		},
		Outcome: outcome, Dimensions: map[string]schema.DimensionOutcome{"protocol": dimension},
		Cases: slices.Clone(result.Cases), Conditions: conditions,
		PrimaryExitCode: exitCode,
	}
	if err := bundle.Validate(); err != nil {
		return report.Bundle{}, err
	}
	return bundle, nil
}

func aggregate(cases []schema.CaseResult, classes map[string]executor.ErrorClass) (schema.ProfileOutcome, schema.DimensionOutcome, int) {
	hasFailure, hasWarning, hasIncomplete, hasInfrastructure, hasPermission, interrupted := false, false, false, false, false, false
	for _, class := range classes {
		if class == executor.ErrorAuthentication || class == executor.ErrorPermission {
			hasPermission = true
		}
	}
	for _, item := range cases {
		if item.ExecutionStatus == schema.ExecutionCancelled {
			interrupted = true
		}
		if item.ExecutionStatus == schema.ExecutionErrored {
			hasInfrastructure = true
		}
		if item.PlanDisposition != schema.DispositionExecute || item.ExecutionStatus == schema.ExecutionSkipped || item.Verdict == nil {
			hasIncomplete = true
			continue
		}
		switch *item.Verdict {
		case schema.VerdictFail:
			hasFailure = true
		case schema.VerdictWarn:
			hasWarning = true
		case schema.VerdictInconclusive:
			hasIncomplete = true
		}
	}
	switch {
	case interrupted:
		return schema.ProfileInconclusive, schema.DimensionInconclusive, 130
	case hasPermission:
		return schema.ProfileInconclusive, schema.DimensionInconclusive, 5
	case hasInfrastructure:
		return schema.ProfileInconclusive, schema.DimensionInconclusive, 3
	case hasIncomplete:
		return schema.ProfileInconclusive, schema.DimensionInconclusive, 4
	case hasFailure:
		return schema.ProfileIncompatible, schema.DimensionFail, 1
	case hasWarning:
		return schema.ProfileDegraded, schema.DimensionDegraded, 0
	default:
		return schema.ProfileCompatible, schema.DimensionPass, 0
	}
}

type classifyingRunner struct {
	inner   executor.Runner
	mu      sync.Mutex
	classes map[string]executor.ErrorClass
}

func newClassifyingRunner(inner executor.Runner) *classifyingRunner {
	return &classifyingRunner{inner: inner, classes: make(map[string]executor.ErrorClass)}
}

func (runner *classifyingRunner) Estimate(decision schema.ScenarioDecision) (budget.Usage, error) {
	return runner.inner.Estimate(decision)
}

func (runner *classifyingRunner) Run(ctx context.Context, invocation executor.Invocation) (executor.Outcome, error) {
	outcome, err := runner.inner.Run(ctx, invocation)
	var classified *executor.RunError
	if errors.As(err, &classified) {
		runner.mu.Lock()
		runner.classes[invocation.Scenario.ScenarioID] = classified.Class
		runner.mu.Unlock()
	}
	return outcome, err
}

func (runner *classifyingRunner) Finalize(ctx context.Context, plan schema.FinalizerPlan) (budget.Usage, error) {
	return runner.inner.Finalize(ctx, plan)
}

func (runner *classifyingRunner) snapshot() map[string]executor.ErrorClass {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := make(map[string]executor.ErrorClass, len(runner.classes))
	for scenarioID, class := range runner.classes {
		result[scenarioID] = class
	}
	return result
}

func ensureDataRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("data root must be an absolute path")
	}
	clean := filepath.Clean(root)
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("create data root: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("data root must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(clean, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func maxMaterialResponse(materials []scenarioMaterial) int64 {
	var result int64
	for _, material := range materials {
		if material.Budget.ResponseBytes > result {
			result = material.Budget.ResponseBytes
		}
	}
	return result
}
