package rawdriver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/attribution"
	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/executor"
	"github.com/whyiug/agentapi-doctor/internal/oracle"
	"github.com/whyiug/agentapi-doctor/internal/recorder"
	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/internal/transport"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type IDSource func() (schema.InstanceID, error)

// A response body is already byte-bounded, but a valid SSE stream can encode
// an extreme number of tiny logical events. Limit per-event persistence so a
// target cannot turn that byte allowance into unbounded CAS inode creation.
const maxPersistedSSEEvents = 512

type Config struct {
	Registry            Registry
	Transport           *transport.Client
	Store               *cas.Store
	Redactor            *redaction.Redactor
	Producer            schema.Producer
	NewID               IDSource
	Now                 func() time.Time
	MaxObservationBytes int
}

// Runner implements executor.Runner. It owns no endpoint URL and therefore
// cannot bypass the exact origin already frozen into transport.Client.
type Runner struct {
	registry            Registry
	transport           *transport.Client
	store               *cas.Store
	redactor            *redaction.Redactor
	producer            schema.Producer
	newID               IDSource
	now                 func() time.Time
	maxObservationBytes int
}

var _ executor.Runner = (*Runner)(nil)

func New(config Config) (*Runner, error) {
	if config.Registry == nil {
		return nil, errors.New("scenario registry is required")
	}
	if config.Transport == nil {
		return nil, errors.New("origin-bound transport is required")
	}
	if config.Store == nil {
		return nil, errors.New("evidence CAS is required")
	}
	if config.Redactor == nil {
		return nil, errors.New("redactor is required")
	}
	if err := config.Producer.Validate(); err != nil {
		return nil, fmt.Errorf("producer: %w", err)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = func() (schema.InstanceID, error) {
			return schema.NewInstanceID(config.Now, nil)
		}
	}
	if config.MaxObservationBytes <= 0 {
		config.MaxObservationBytes = recorder.DefaultMaxObservationBytes
	}
	return &Runner{
		registry:            config.Registry,
		transport:           config.Transport,
		store:               config.Store,
		redactor:            config.Redactor,
		producer:            config.Producer,
		newID:               config.NewID,
		now:                 config.Now,
		maxObservationBytes: config.MaxObservationBytes,
	}, nil
}

func (runner *Runner) Estimate(decision schema.ScenarioDecision) (budget.Usage, error) {
	if runner == nil || runner.registry == nil {
		return budget.Usage{}, errors.New("raw driver is not initialized")
	}
	usage, err := runner.registry.Estimate(decision)
	if err != nil {
		return budget.Usage{}, err
	}
	if err := usage.Validate(); err != nil {
		return budget.Usage{}, fmt.Errorf("registry estimate: %w", err)
	}
	if usage.Requests != 1 || usage.RequestBytes <= 0 || usage.ResponseBytes <= 0 || usage.ArtifactBytes <= 0 || usage.Processes != 0 {
		return budget.Usage{}, errors.New("registry estimate is not a bounded single-request raw HTTP estimate")
	}
	return usage, nil
}

func (runner *Runner) Run(ctx context.Context, invocation executor.Invocation) (executor.Outcome, error) {
	if ctx == nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, errors.New("context is required"), budget.Usage{}, false)
	}
	if err := ctx.Err(); err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, err, budget.Usage{}, false)
	}
	if runner == nil || runner.registry == nil || runner.transport == nil || runner.store == nil || runner.redactor == nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, errors.New("raw driver is not initialized"), budget.Usage{}, false)
	}
	if err := validateInvocation(invocation); err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, err, budget.Usage{}, false)
	}
	scenario, err := runner.registry.Lookup(invocation.PlanDigest, invocation.Scenario)
	if err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, fmt.Errorf("resolve exact scenario: %w", err), budget.Usage{}, false)
	}
	scenario, err = validateAndCloneScenario(scenario)
	if err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, fmt.Errorf("validate registered scenario: %w", err), budget.Usage{}, false)
	}
	if scenario.PlanDigest != invocation.PlanDigest || scenario.ID != invocation.Scenario.ScenarioID || scenario.Driver != invocation.Scenario.Driver {
		return executor.Outcome{}, runError(executor.ErrorHarness, errors.New("registry lookup returned content outside the exact invocation key"), budget.Usage{}, false)
	}

	capture, err := recorder.New(recorder.Config{
		RunID:               invocation.RunID,
		InvocationID:        invocation.InvocationID,
		AttemptID:           invocation.AttemptID,
		Producer:            runner.producer,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		MaxObservationBytes: runner.maxObservationBytes,
		Now:                 runner.now,
	}, runner.redactor, runner.store)
	if err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, fmt.Errorf("create recorder: %w", err), budget.Usage{}, false)
	}

	started := time.Now()
	requestPayload, err := marshalRequestObservation(scenario)
	if err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, fmt.Errorf("encode request observation: %w", err), budget.Usage{}, false)
	}
	evidence := make([]schema.Evidence, 0, 3)
	requestEvidence, err := capture.Record(ctx, recorder.Observation{
		Sequence:            1,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		Direction:           schema.DirectionCoreToTarget,
		Kind:                "http_request",
		MonotonicOffsetNS:   elapsedNS(started),
		Payload:             requestPayload,
		Format:              recorder.PayloadJSON,
	})
	if err != nil {
		return executor.Outcome{}, runError(executor.ErrorHarness, fmt.Errorf("record request: %w", err), budget.Usage{}, false)
	}
	evidence = append(evidence, requestEvidence)
	usage := budget.Usage{Requests: 1, RequestBytes: int64(len(scenario.Body))}
	unknownUsage := []string{"input_tokens", "output_tokens"}

	response, err := runner.transport.Do(ctx, scenario.Method, scenario.Path, scenario.Headers, scenario.Body)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, ctxErr, usage, true, unknownUsage, evidence)
		}
		class := executor.ErrorDriver
		if errors.Is(err, transport.ErrBodyLimit) {
			class = executor.ErrorHarness
		}
		return executor.Outcome{}, runErrorWithEvidence(class, fmt.Errorf("raw HTTP transport: %w", err), usage, true, unknownUsage, evidence)
	}
	usage.ResponseBytes = int64(len(response.Body))

	responseMetadata, err := marshalResponseMetadata(response)
	if err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("encode response metadata: %w", err), usage, true, unknownUsage, evidence)
	}
	metadataEvidence, err := capture.Record(ctx, recorder.Observation{
		Sequence:            2,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		Direction:           schema.DirectionTargetToCore,
		Kind:                "http_response_metadata",
		MonotonicOffsetNS:   elapsedNS(started),
		Payload:             responseMetadata,
		Format:              recorder.PayloadJSON,
	})
	if err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("record response metadata: %w", err), usage, true, unknownUsage, evidence)
	}
	evidence = append(evidence, metadataEvidence)

	if int64(len(response.Body)) > scenario.Budget.ResponseBytes {
		usage.ArtifactBytes, _ = runner.artifactBytes(ctx, evidence)
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, errors.New("response body exceeds the registered scenario budget"), usage, true, unknownUsage, evidence)
	}
	if len(response.Body) > 0 {
		bodyEvidence, recordErr := runner.recordResponseBody(ctx, capture, scenario, response.Body, started)
		evidence = append(evidence, bodyEvidence...)
		if recordErr != nil {
			usage.ArtifactBytes, _ = runner.artifactBytes(ctx, evidence)
			return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("record response body: %w", recordErr), usage, true, unknownUsage, evidence)
		}
	}
	usage.ArtifactBytes, err = runner.artifactBytes(ctx, evidence)
	if err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("measure evidence artifacts: %w", err), usage, true, unknownUsage, evidence)
	}

	if class, classified := classifyHTTPStatus(response.StatusCode); classified {
		return executor.Outcome{}, runErrorWithEvidence(class, fmt.Errorf("HTTP status %d", response.StatusCode), usage, true, unknownUsage, evidence)
	}

	refs := evidenceRefs(evidence)
	evaluation, err := evaluate(scenario, response.StatusCode, response.Header, response.Body, refs)
	if err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("evaluate response: %w", err), usage, true, unknownUsage, evidence)
	}
	if err := sanitizeOutcome(runner.redactor, &evaluation.Outcome); err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("sanitize oracle outcome: %w", err), usage, true, unknownUsage, evidence)
	}
	usage.InputTokens = evaluation.Usage.Input
	usage.OutputTokens = evaluation.Usage.Output
	unknownUsage = unknownUsage[:0]
	if !evaluation.Usage.HasInput {
		unknownUsage = append(unknownUsage, "input_tokens")
	}
	if !evaluation.Usage.HasOutput {
		unknownUsage = append(unknownUsage, "output_tokens")
	}
	if evaluation.Outcome.ReasonCode == schema.ReasonHarnessError {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, errors.New("oracle reported a harness precondition failure"), usage, true, unknownUsage, evidence)
	}

	assertionID, err := runner.newID()
	if err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("create assertion result ID: %w", err), usage, true, unknownUsage, evidence)
	}
	assertion := schema.AssertionResult{
		AssertionResultID: assertionID,
		AssertionID:       scenario.Assertion.AssertionID,
		RequirementID:     scenario.Assertion.RequirementID,
		Role:              scenario.Assertion.Role,
		Oracle:            scenario.Assertion.Oracle,
		Verdict:           evaluation.Outcome.Verdict,
		ReasonCode:        evaluation.Outcome.ReasonCode,
		Expected:          evaluation.Outcome.Expected,
		Observed:          evaluation.Outcome.Observed,
		EvidenceRefs:      slices.Clone(evaluation.Outcome.EvidenceRefs),
		Deterministic:     true,
		EvaluatorDigest:   scenario.Assertion.EvaluatorDigest,
	}
	if err := assertion.Validate(); err != nil {
		return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("validate assertion result: %w", err), usage, true, unknownUsage, evidence)
	}

	findings := []schema.Finding{}
	if evaluation.Outcome.TargetFailure {
		finding, findingErr := runner.finding(scenario, assertion, evaluation.Outcome)
		if findingErr != nil {
			return executor.Outcome{}, runErrorWithEvidence(executor.ErrorHarness, fmt.Errorf("construct finding: %w", findingErr), usage, true, unknownUsage, evidence)
		}
		findings = append(findings, finding)
	}
	return executor.Outcome{
		Verdict:          evaluation.Outcome.Verdict,
		ReasonCode:       evaluation.Outcome.ReasonCode,
		EvidenceRefs:     refs,
		AssertionResults: []schema.AssertionResult{assertion},
		Findings:         findings,
		Usage:            usage,
		UnknownUsage:     unknownUsage,
	}, nil
}

func sanitizeOutcome(redactorInstance *redaction.Redactor, outcome *oracle.Outcome) error {
	if redactorInstance == nil || outcome == nil {
		return errors.New("redactor and oracle outcome are required")
	}
	fields := struct {
		Expected any `json:"expected"`
		Observed any `json:"observed"`
	}{Expected: outcome.Expected, Observed: outcome.Observed}
	raw, err := schema.CanonicalMarshal(fields)
	if err != nil {
		return fmt.Errorf("encode typed outcome fields: %w", err)
	}
	sanitized, _, err := redactorInstance.RedactJSON(raw)
	if err != nil {
		return fmt.Errorf("redact typed outcome fields: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(sanitized))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return fmt.Errorf("decode typed outcome fields: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("sanitized outcome contains trailing JSON")
	}
	outcome.Expected = fields.Expected
	outcome.Observed = fields.Observed
	return nil
}

func (runner *Runner) recordResponseBody(ctx context.Context, capture *recorder.Recorder, scenario Scenario, body []byte, started time.Time) ([]schema.Evidence, error) {
	if !scenario.Streaming {
		payload := body
		kind := "http_response_body"
		if !json.Valid(body) {
			var err error
			payload, err = marshalOmittedContent("non_json_http_response_body", len(body))
			if err != nil {
				return nil, err
			}
			kind = "http_response_body_omitted"
		}
		evidence, err := capture.Record(ctx, recorder.Observation{
			Sequence:            3,
			CaptureLayer:        schema.LayerUpstreamApplication,
			InstrumentationMode: schema.InstrumentationDirect,
			Direction:           schema.DirectionTargetToCore,
			Kind:                kind,
			MonotonicOffsetNS:   elapsedNS(started),
			Payload:             payload,
			Format:              recorder.PayloadJSON,
		})
		if err != nil {
			return nil, err
		}
		return []schema.Evidence{evidence}, nil
	}

	assembler := recorder.NewSSEAssembler(max(len(body)+1, 1024))
	events, err := assembler.Feed(recorder.ReadChunk{Sequence: 1, ByteOffset: 0, Data: body})
	if err != nil {
		return recordSSEWireSummary(ctx, capture, started, "sse_invalid_wire", "invalid_sse_wire", len(body), 0, recorder.StreamTail{})
	}
	tail := assembler.Finish()
	if len(events) == 0 {
		return recordSSEWireSummary(ctx, capture, started, "sse_invalid_wire", "no_complete_sse_events", len(body), 0, tail)
	}
	if len(events) > maxPersistedSSEEvents {
		// Evaluation still receives the complete byte-bounded in-memory body.
		// Persist one typed JSON projection so nested sensitive fields still pass
		// through field-aware JSON redaction without per-event CAS amplification.
		return recordSSEEventLimitFallback(ctx, capture, events, len(body), started)
	}
	result := make([]schema.Evidence, 0, len(events)+1)
	sequence := uint64(3)
	for _, event := range events {
		payload, kind, encodeErr := marshalSSEObservation(event)
		if encodeErr != nil {
			return result, encodeErr
		}
		offset := event.EventOffset
		evidence, recordErr := capture.Record(ctx, recorder.Observation{
			Sequence:            sequence,
			CaptureLayer:        schema.LayerUpstreamApplication,
			InstrumentationMode: schema.InstrumentationDirect,
			Direction:           schema.DirectionTargetToCore,
			Kind:                kind,
			MonotonicOffsetNS:   elapsedNS(started),
			EventOffset:         &offset,
			Payload:             payload,
			Format:              recorder.PayloadJSON,
		})
		if recordErr != nil {
			return result, recordErr
		}
		result = append(result, evidence)
		sequence++
	}
	if tail.BufferedBytes != 0 || tail.PendingFieldCount != 0 {
		partial, recordErr := recordSSEWireSummaryAtSequence(ctx, capture, sequence, started, "sse_incomplete_wire", "incomplete_sse_tail", len(body), len(events), tail)
		if recordErr != nil {
			return result, recordErr
		}
		result = append(result, partial...)
	}
	return result, nil
}

func recordSSEWireSummary(ctx context.Context, capture *recorder.Recorder, started time.Time, kind, reason string, wireBytes, completeEvents int, tail recorder.StreamTail) ([]schema.Evidence, error) {
	return recordSSEWireSummaryAtSequence(ctx, capture, 3, started, kind, reason, wireBytes, completeEvents, tail)
}

func recordSSEWireSummaryAtSequence(ctx context.Context, capture *recorder.Recorder, sequence uint64, started time.Time, kind, reason string, wireBytes, completeEvents int, tail recorder.StreamTail) ([]schema.Evidence, error) {
	payload, err := schema.CanonicalMarshal(struct {
		Representation string `json:"representation"`
		OmittedReason  string `json:"omitted_reason"`
		WireBytes      int    `json:"wire_bytes"`
		CompleteEvents int    `json:"complete_event_count"`
		PendingBytes   int    `json:"pending_bytes,omitempty"`
		PendingFields  int    `json:"pending_field_count,omitempty"`
	}{
		Representation: "sse_wire_summary_v1",
		OmittedReason:  reason,
		WireBytes:      wireBytes,
		CompleteEvents: completeEvents,
		PendingBytes:   tail.BufferedBytes,
		PendingFields:  tail.PendingFieldCount,
	})
	if err != nil {
		return nil, err
	}
	evidence, err := capture.Record(ctx, recorder.Observation{
		Sequence:            sequence,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		Direction:           schema.DirectionTargetToCore,
		Kind:                kind,
		MonotonicOffsetNS:   elapsedNS(started),
		Payload:             payload,
		Format:              recorder.PayloadJSON,
	})
	if err != nil {
		return nil, err
	}
	return []schema.Evidence{evidence}, nil
}

func recordSSEEventLimitFallback(ctx context.Context, capture *recorder.Recorder, events []recorder.SSELogicalEvent, wireBytes int, started time.Time) ([]schema.Evidence, error) {
	payload, err := marshalSSEEventLimitFallback(events, wireBytes)
	if err != nil {
		return nil, err
	}
	evidence, err := capture.Record(ctx, recorder.Observation{
		Sequence:            3,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		Direction:           schema.DirectionTargetToCore,
		Kind:                "sse_event_limit_fallback",
		MonotonicOffsetNS:   elapsedNS(started),
		Payload:             payload,
		Format:              recorder.PayloadJSON,
	})
	if err != nil {
		return nil, err
	}
	return []schema.Evidence{evidence}, nil
}

func marshalSSEEventLimitFallback(events []recorder.SSELogicalEvent, wireBytes int) ([]byte, error) {
	orderedJSONData := make([]json.RawMessage, 0, len(events))
	omittedCount := 0
	omittedBytes := 0
	doneCount := 0
	for _, event := range events {
		switch {
		case event.Data == "[DONE]":
			doneCount++
		case json.Valid([]byte(event.Data)):
			orderedJSONData = append(orderedJSONData, json.RawMessage(event.Data))
		default:
			omittedCount++
			omittedBytes += len(event.Data)
		}
	}
	projection := struct {
		Representation  string            `json:"representation"`
		WireBytes       int               `json:"wire_bytes"`
		CompleteEvents  int               `json:"complete_event_count"`
		JSONEvents      int               `json:"json_event_count"`
		DoneEvents      int               `json:"done_event_count,omitempty"`
		NonJSONOmitted  int               `json:"non_json_data_omitted,omitempty"`
		NonJSONBytes    int               `json:"non_json_data_bytes,omitempty"`
		OrderedJSONData []json.RawMessage `json:"ordered_json_data"`
	}{
		Representation:  "bounded_sse_json_projection_v1",
		WireBytes:       wireBytes,
		CompleteEvents:  len(events),
		JSONEvents:      len(orderedJSONData),
		DoneEvents:      doneCount,
		NonJSONOmitted:  omittedCount,
		NonJSONBytes:    omittedBytes,
		OrderedJSONData: orderedJSONData,
	}
	return schema.CanonicalMarshal(projection)
}

func marshalSSEObservation(event recorder.SSELogicalEvent) ([]byte, string, error) {
	if event.Data == "[DONE]" {
		payload, err := schema.CanonicalMarshal(struct {
			TerminalMarker string `json:"terminal_marker"`
		}{TerminalMarker: "[DONE]"})
		return payload, "sse_logical_event", err
	}
	if !json.Valid([]byte(event.Data)) {
		payload, err := marshalOmittedContent("non_json_sse_data", len(event.Data))
		return payload, "sse_non_json_data_omitted", err
	}
	type observation struct {
		Data json.RawMessage `json:"data"`
	}
	payload, err := schema.CanonicalMarshal(observation{Data: json.RawMessage(event.Data)})
	return payload, "sse_logical_event", err
}

func marshalOmittedContent(reason string, byteCount int) ([]byte, error) {
	return schema.CanonicalMarshal(struct {
		Representation string `json:"representation"`
		OmittedReason  string `json:"omitted_reason"`
		ByteCount      int    `json:"byte_count"`
	}{
		Representation: "opaque_content_omitted_v1",
		OmittedReason:  reason,
		ByteCount:      byteCount,
	})
}

func (runner *Runner) Finalize(_ context.Context, plan schema.FinalizerPlan) (budget.Usage, error) {
	return budget.Usage{}, runError(executor.ErrorDriver, fmt.Errorf("raw HTTP driver does not own finalizer lease %q", plan.LeaseID), budget.Usage{}, false)
}

func validateInvocation(invocation executor.Invocation) error {
	for name, id := range map[string]schema.InstanceID{
		"run": invocation.RunID, "invocation": invocation.InvocationID, "attempt": invocation.AttemptID,
	} {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("%s ID: %w", name, err)
		}
	}
	if err := invocation.PlanDigest.Validate(); err != nil {
		return fmt.Errorf("plan digest: %w", err)
	}
	if invocation.AttemptNumber <= 0 {
		return errors.New("attempt number must be positive")
	}
	return validateDecision(invocation.Scenario)
}

func marshalRequestObservation(scenario Scenario) ([]byte, error) {
	return json.Marshal(struct {
		Method  string          `json:"method"`
		Path    string          `json:"path"`
		Headers http.Header     `json:"headers"`
		Body    json.RawMessage `json:"body"`
	}{scenario.Method, scenario.Path, scenario.Headers, scenario.Body})
}

func marshalResponseMetadata(response transport.Response) ([]byte, error) {
	return json.Marshal(struct {
		StatusCode int         `json:"status_code"`
		Headers    http.Header `json:"headers"`
		Protocol   string      `json:"protocol"`
		DurationNS int64       `json:"duration_ns"`
	}{response.StatusCode, response.Header, response.Protocol, response.Duration.Nanoseconds()})
}

func classifyHTTPStatus(status int) (executor.ErrorClass, bool) {
	switch {
	case status == http.StatusUnauthorized:
		return executor.ErrorAuthentication, true
	case status == http.StatusForbidden:
		return executor.ErrorPermission, true
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500:
		return executor.ErrorTransient, true
	default:
		return "", false
	}
}

func runError(class executor.ErrorClass, err error, usage budget.Usage, known bool) error {
	return &executor.RunError{Class: class, Err: err, Usage: usage, UsageKnown: known}
}

func runErrorWithEvidence(class executor.ErrorClass, err error, usage budget.Usage, known bool, unknownUsage []string, evidence []schema.Evidence) error {
	return &executor.RunError{Class: class, Err: err, Usage: usage, UsageKnown: known, UnknownUsage: append([]string(nil), unknownUsage...), EvidenceRefs: evidenceRefs(evidence)}
}

func elapsedNS(started time.Time) int64 {
	value := time.Since(started).Nanoseconds()
	if value < 0 {
		return 0
	}
	return value
}

func evidenceRefs(evidence []schema.Evidence) []schema.ObjectRef {
	refs := make([]schema.ObjectRef, 0, len(evidence))
	for _, item := range evidence {
		refs = append(refs, item.ObjectRef)
	}
	return refs
}

func (runner *Runner) artifactBytes(ctx context.Context, evidence []schema.Evidence) (int64, error) {
	var total int64
	for _, item := range evidence {
		if item.PayloadDigest == nil {
			continue
		}
		payload, err := runner.store.Get(ctx, *item.PayloadDigest)
		if err != nil {
			return 0, err
		}
		total += int64(len(payload))
		for index := range payload {
			payload[index] = 0
		}
		envelope, err := schema.CanonicalMarshal(item)
		if err != nil {
			return 0, err
		}
		total += int64(len(envelope))
	}
	return total, nil
}

func (runner *Runner) finding(scenario Scenario, assertion schema.AssertionResult, outcome oracle.Outcome) (schema.Finding, error) {
	id, err := runner.newID()
	if err != nil {
		return schema.Finding{}, err
	}
	domain, family := findingDomain(scenario.Assertion.Check)
	fingerprint, err := attribution.Fingerprint(scenario.ID, scenario.Assertion.AssertionID, outcome.Code, outcome.Expected, outcome.Observed)
	if err != nil {
		return schema.Finding{}, err
	}
	return schema.Finding{
		FindingID:           id,
		AssertionResultID:   assertion.AssertionResultID,
		FaultDomain:         string(domain),
		FaultFamily:         family,
		Category:            outcome.Code,
		Severity:            "medium",
		Confidence:          0.9,
		CalibrationVersion:  attribution.CalibrationVersion,
		MinimalEvidenceRefs: slices.Clone(outcome.EvidenceRefs),
		RequirementID:       scenario.Assertion.RequirementID,
		RemediationHint:     "conform the emitted response to the cited requirement and preserve the failing exchange as a regression fixture",
		FingerprintVersion:  "failure-fingerprint-v1",
		Fingerprint:         fingerprint,
	}, nil
}

func findingDomain(check CheckKind) (attribution.Domain, schema.FaultFamily) {
	domain := attribution.DomainProtocolSerializer
	switch check {
	case CheckArgumentsString, CheckStreamingToolCall, CheckStableToolCallID:
		domain = attribution.DomainToolParser
	case CheckTerminalEvent, CheckOutputIndexes, CheckStreamMediaType, CheckNoPostTerminal:
		domain = attribution.DomainStreamStateMachine
	case CheckClosedReasoning:
		domain = attribution.DomainReasoningParser
	}
	family, _ := attribution.Family(domain)
	return domain, family
}
