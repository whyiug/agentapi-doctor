// Package recorder captures bounded application-layer observations and commits
// only sanitized payloads to the evidence CAS.
package recorder

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type PayloadFormat string

const (
	PayloadText PayloadFormat = "text"
	PayloadJSON PayloadFormat = "json"
)

const DefaultMaxObservationBytes = 1 << 20

// Config freezes the observation point for a recorder. A caller cannot change
// capture layer or instrumentation mode on individual observations.
type Config struct {
	RunID               schema.InstanceID
	InvocationID        schema.InstanceID
	AttemptID           schema.InstanceID
	Producer            schema.Producer
	CaptureLayer        schema.CaptureLayer
	InstrumentationMode schema.InstrumentationMode
	MaxObservationBytes int
	Now                 func() time.Time
}

// Observation is source-faithful only at its declared application capture
// layer. Payload remains in memory until redaction succeeds.
type Observation struct {
	Sequence            uint64
	CaptureLayer        schema.CaptureLayer
	InstrumentationMode schema.InstrumentationMode
	Direction           schema.Direction
	Kind                string
	MonotonicOffsetNS   int64
	ByteOffset          *int64
	EventOffset         *int64
	Payload             []byte
	Format              PayloadFormat
	Relations           []schema.EvidenceRelation
}

type Recorder struct {
	config   Config
	redactor *redaction.Redactor
	store    *cas.Store

	mu           sync.Mutex
	nextSequence uint64
}

func New(config Config, redactorInstance *redaction.Redactor, store *cas.Store) (*Recorder, error) {
	if redactorInstance == nil {
		return nil, errors.New("redactor is required")
	}
	if store == nil {
		return nil, errors.New("CAS store is required")
	}
	for name, id := range map[string]schema.InstanceID{
		"run":        config.RunID,
		"invocation": config.InvocationID,
		"attempt":    config.AttemptID,
	} {
		if err := id.Validate(); err != nil {
			return nil, fmt.Errorf("%s ID: %w", name, err)
		}
	}
	if err := config.Producer.Validate(); err != nil {
		return nil, fmt.Errorf("producer: %w", err)
	}
	if !sourceCaptureLayer(config.CaptureLayer) {
		return nil, fmt.Errorf("capture layer %q is not a source observation layer", config.CaptureLayer)
	}
	if !validLayerMode(config.CaptureLayer, config.InstrumentationMode) {
		return nil, fmt.Errorf("instrumentation mode %q cannot observe capture layer %q", config.InstrumentationMode, config.CaptureLayer)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxObservationBytes <= 0 {
		config.MaxObservationBytes = DefaultMaxObservationBytes
	}
	return &Recorder{config: config, redactor: redactorInstance, store: store, nextSequence: 1}, nil
}

// Record sanitizes an in-memory observation, commits the sanitized bytes to
// CAS, constructs digest-bound evidence, and persists that typed envelope.
// Sequence advances only after both immutable objects validate and commit.
func (recorder *Recorder) Record(ctx context.Context, observation Observation) (schema.Evidence, error) {
	if ctx == nil {
		return schema.Evidence{}, errors.New("context is required")
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	if err := recorder.validateObservation(observation); err != nil {
		return schema.Evidence{}, err
	}

	inMemory := append([]byte(nil), observation.Payload...)
	defer zero(inMemory)

	var (
		payload redaction.SanitizedPayload
		err     error
	)
	switch observation.Format {
	case PayloadText:
		payload, err = recorder.redactor.SanitizeText(inMemory)
	case PayloadJSON:
		payload, err = recorder.redactor.SanitizeJSON(inMemory)
	default:
		err = fmt.Errorf("unsupported payload format %q", observation.Format)
	}
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("sanitize observation before persistence: %w", err)
	}

	payloadRef, err := recorder.store.Put(ctx, payload)
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("persist sanitized observation: %w", err)
	}
	payloadDigest := payloadRef.ContentDigest
	redactions := redactionRecords(payload.Report())
	evidence := schema.Evidence{
		RunID:               recorder.config.RunID,
		InvocationID:        recorder.config.InvocationID,
		AttemptID:           recorder.config.AttemptID,
		Sequence:            observation.Sequence,
		CaptureLayer:        observation.CaptureLayer,
		InstrumentationMode: observation.InstrumentationMode,
		Direction:           observation.Direction,
		EvidenceKind:        observation.Kind,
		MonotonicOffsetNS:   observation.MonotonicOffsetNS,
		ByteOffset:          cloneInt64(observation.ByteOffset),
		EventOffset:         cloneInt64(observation.EventOffset),
		PayloadRef:          &payloadRef,
		PayloadDigest:       &payloadDigest,
		Redactions:          redactions,
		Relations:           append([]schema.EvidenceRelation(nil), observation.Relations...),
	}
	meta, err := cas.SealEvidenceMeta(recorder.config.Producer, schema.NewUTCTime(recorder.config.Now()), evidence)
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("seal evidence: %w", err)
	}
	evidence.EnvelopeMeta = meta
	evidence.EvidenceID = meta.ContentDigest
	if err := evidence.Validate(); err != nil {
		return schema.Evidence{}, fmt.Errorf("validate committed evidence: %w", err)
	}
	persistedRef, err := recorder.store.PutEvidence(ctx, evidence)
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("persist Evidence envelope: %w", err)
	}
	if persistedRef != evidence.ObjectRef {
		return schema.Evidence{}, errors.New("persisted Evidence reference differs from the sealed envelope")
	}
	recorder.nextSequence++
	return evidence, nil
}

func (recorder *Recorder) validateObservation(observation Observation) error {
	if observation.Sequence != recorder.nextSequence {
		return fmt.Errorf("observation sequence must be %d, got %d", recorder.nextSequence, observation.Sequence)
	}
	if observation.CaptureLayer != recorder.config.CaptureLayer {
		return fmt.Errorf("observation cannot impersonate capture layer %q from recorder layer %q", observation.CaptureLayer, recorder.config.CaptureLayer)
	}
	if observation.InstrumentationMode != recorder.config.InstrumentationMode {
		return fmt.Errorf("observation cannot change instrumentation mode from %q to %q", recorder.config.InstrumentationMode, observation.InstrumentationMode)
	}
	if !validDirection(observation.CaptureLayer, observation.Direction) {
		return fmt.Errorf("direction %q is invalid for capture layer %q", observation.Direction, observation.CaptureLayer)
	}
	if observation.Kind == "" {
		return errors.New("observation kind is required")
	}
	if observation.MonotonicOffsetNS < 0 {
		return errors.New("monotonic offset cannot be negative")
	}
	if len(observation.Payload) == 0 {
		return errors.New("observation payload cannot be empty")
	}
	if len(observation.Payload) > recorder.config.MaxObservationBytes {
		return fmt.Errorf("observation payload exceeds %d bytes", recorder.config.MaxObservationBytes)
	}
	if observation.ByteOffset != nil && *observation.ByteOffset < 0 {
		return errors.New("byte offset cannot be negative")
	}
	if observation.EventOffset != nil && *observation.EventOffset < 0 {
		return errors.New("event offset cannot be negative")
	}
	return nil
}

func sourceCaptureLayer(layer schema.CaptureLayer) bool {
	return slices.Contains([]schema.CaptureLayer{
		schema.LayerUpstreamApplication,
		schema.LayerProxyForwarded,
		schema.LayerClientSDK,
	}, layer)
}

func validLayerMode(layer schema.CaptureLayer, mode schema.InstrumentationMode) bool {
	switch layer {
	case schema.LayerUpstreamApplication:
		return mode == schema.InstrumentationDirect || mode == schema.InstrumentationFixture
	case schema.LayerProxyForwarded:
		return mode == schema.InstrumentationProxy
	case schema.LayerClientSDK:
		return mode == schema.InstrumentationClient || mode == schema.InstrumentationFixture
	default:
		return false
	}
}

func validDirection(layer schema.CaptureLayer, direction schema.Direction) bool {
	switch layer {
	case schema.LayerUpstreamApplication:
		return direction == schema.DirectionCoreToTarget || direction == schema.DirectionTargetToCore
	case schema.LayerProxyForwarded:
		return direction == schema.DirectionProxyToClient || direction == schema.DirectionClientToProxy
	case schema.LayerClientSDK:
		return direction == schema.DirectionDriverToCore
	default:
		return false
	}
}

func redactionRecords(report redaction.Report) []schema.RedactionRecord {
	records := make([]schema.RedactionRecord, 0, len(report.Findings))
	for _, finding := range report.Findings {
		records = append(records, schema.RedactionRecord{
			RuleID:     finding.RuleID,
			FieldClass: "secret",
			Count:      int64(finding.Count),
		})
	}
	return records
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
