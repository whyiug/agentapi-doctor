package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type CaptureLayer string

const (
	LayerUpstreamApplication CaptureLayer = "upstream_application_observation"
	LayerProxyForwarded      CaptureLayer = "proxy_forwarded_observation"
	LayerClientSDK           CaptureLayer = "client_sdk_observation"
	LayerSanitizedPersisted  CaptureLayer = "sanitized_persisted_evidence"
)

type InstrumentationMode string

const (
	InstrumentationDirect  InstrumentationMode = "direct_transport"
	InstrumentationProxy   InstrumentationMode = "recording_proxy"
	InstrumentationFixture InstrumentationMode = "fixture_replay"
	InstrumentationClient  InstrumentationMode = "client_native"
)

type Direction string

const (
	DirectionCoreToTarget  Direction = "core_to_target"
	DirectionTargetToCore  Direction = "target_to_core"
	DirectionProxyToClient Direction = "proxy_to_client"
	DirectionClientToProxy Direction = "client_to_proxy"
	DirectionDriverToCore  Direction = "driver_to_core"
)

type RedactionRecord struct {
	RuleID     string `json:"rule_id"`
	FieldClass string `json:"field_class"`
	Count      int64  `json:"count"`
}

type EvidenceRelation struct {
	Relation string    `json:"relation"`
	Target   ObjectRef `json:"target"`
}

// Evidence is the sanitized persisted projection for one capture layer.  It
// never claims transport bytes or another layer's chunk boundaries.
type Evidence struct {
	EnvelopeMeta
	EvidenceID          Digest              `json:"evidence_id"`
	RunID               InstanceID          `json:"run_id"`
	InvocationID        InstanceID          `json:"invocation_id"`
	AttemptID           InstanceID          `json:"attempt_id"`
	Sequence            uint64              `json:"sequence"`
	CaptureLayer        CaptureLayer        `json:"capture_layer"`
	InstrumentationMode InstrumentationMode `json:"instrumentation_mode"`
	Direction           Direction           `json:"direction"`
	EvidenceKind        string              `json:"evidence_kind"`
	MonotonicOffsetNS   int64               `json:"monotonic_offset_ns"`
	ByteOffset          *int64              `json:"byte_offset,omitempty"`
	EventOffset         *int64              `json:"event_offset,omitempty"`
	PayloadRef          *ObjectRef          `json:"payload_ref,omitempty"`
	PayloadDigest       *Digest             `json:"payload_digest,omitempty"`
	UnavailableReason   string              `json:"unavailable_reason,omitempty"`
	Redactions          []RedactionRecord   `json:"redactions"`
	Relations           []EvidenceRelation  `json:"relations,omitempty"`
}

func (evidence Evidence) Validate() error {
	if err := evidence.EnvelopeMeta.Validate(); err != nil {
		return err
	}
	if evidence.EnvelopeMeta.Kind != "Evidence" || evidence.EvidenceID != evidence.ContentDigest {
		return errors.New("evidence identity does not match its envelope")
	}
	for name, id := range map[string]InstanceID{"run": evidence.RunID, "invocation": evidence.InvocationID, "attempt": evidence.AttemptID} {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("%s ID: %w", name, err)
		}
	}
	if !slices.Contains([]CaptureLayer{LayerUpstreamApplication, LayerProxyForwarded, LayerClientSDK, LayerSanitizedPersisted}, evidence.CaptureLayer) {
		return fmt.Errorf("invalid capture layer %q", evidence.CaptureLayer)
	}
	if !slices.Contains([]InstrumentationMode{InstrumentationDirect, InstrumentationProxy, InstrumentationFixture, InstrumentationClient}, evidence.InstrumentationMode) {
		return fmt.Errorf("invalid instrumentation mode %q", evidence.InstrumentationMode)
	}
	if !slices.Contains([]Direction{DirectionCoreToTarget, DirectionTargetToCore, DirectionProxyToClient, DirectionClientToProxy, DirectionDriverToCore}, evidence.Direction) {
		return fmt.Errorf("invalid evidence direction %q", evidence.Direction)
	}
	if !validEvidenceObservationPoint(evidence.CaptureLayer, evidence.InstrumentationMode, evidence.Direction) {
		return fmt.Errorf("instrumentation mode %q and direction %q cannot describe capture layer %q", evidence.InstrumentationMode, evidence.Direction, evidence.CaptureLayer)
	}
	if evidence.Sequence == 0 || evidence.MonotonicOffsetNS < 0 || evidence.EvidenceKind == "" {
		return errors.New("evidence requires a positive sequence, nonnegative offset, and kind")
	}
	if evidence.ByteOffset != nil && *evidence.ByteOffset < 0 {
		return errors.New("evidence byte_offset cannot be negative")
	}
	if evidence.EventOffset != nil && *evidence.EventOffset < 0 {
		return errors.New("evidence event_offset cannot be negative")
	}
	if (evidence.PayloadRef == nil) != (evidence.PayloadDigest == nil) {
		return errors.New("payload_ref and payload_digest must be present together")
	}
	if evidence.PayloadRef == nil && evidence.UnavailableReason == "" {
		return errors.New("missing payload requires unavailable_reason")
	}
	if evidence.PayloadRef != nil && evidence.UnavailableReason != "" {
		return errors.New("available payload cannot also declare unavailable_reason")
	}
	if evidence.PayloadRef != nil {
		if err := evidence.PayloadRef.Validate(); err != nil {
			return fmt.Errorf("payload ref: %w", err)
		}
		if evidence.PayloadRef.Kind != "Payload" || evidence.PayloadRef.InstanceID != "" {
			return errors.New("payload_ref must be a content-addressed Payload ref")
		}
		if *evidence.PayloadDigest != evidence.PayloadRef.ContentDigest {
			return errors.New("payload digest does not match payload_ref")
		}
	}
	for _, redaction := range evidence.Redactions {
		if redaction.RuleID == "" || redaction.FieldClass == "" || redaction.Count <= 0 {
			return errors.New("redaction records require rule, field class, and positive count")
		}
	}
	for _, relation := range evidence.Relations {
		if strings.TrimSpace(relation.Relation) == "" {
			return errors.New("evidence relation name is required")
		}
		if err := relation.Target.Validate(); err != nil {
			return fmt.Errorf("evidence relation target: %w", err)
		}
	}
	return nil
}

func validEvidenceObservationPoint(layer CaptureLayer, mode InstrumentationMode, direction Direction) bool {
	// A sanitized projection retains the source observation's mode/direction,
	// so every otherwise valid pair is meaningful at this derived layer.
	if layer == LayerSanitizedPersisted {
		return true
	}
	switch layer {
	case LayerUpstreamApplication:
		return (mode == InstrumentationDirect || mode == InstrumentationFixture) &&
			(direction == DirectionCoreToTarget || direction == DirectionTargetToCore)
	case LayerProxyForwarded:
		return mode == InstrumentationProxy &&
			(direction == DirectionProxyToClient || direction == DirectionClientToProxy)
	case LayerClientSDK:
		return (mode == InstrumentationClient || mode == InstrumentationFixture) && direction == DirectionDriverToCore
	default:
		return false
	}
}

type IRType string

const (
	IRMessage           IRType = "message"
	IRContentPart       IRType = "content_part"
	IRToolCall          IRType = "tool_call"
	IRToolResult        IRType = "tool_result"
	IRReasoningArtifact IRType = "reasoning_artifact"
	IRUsage             IRType = "usage"
	IRError             IRType = "error"
	IRLifecycleEvent    IRType = "lifecycle_event"
	IRProviderExtension IRType = "provider_extension"
)

type LossMarker struct {
	TransformID string `json:"transform_id"`
	Reason      string `json:"reason"`
}

// IRItem preserves the provider-native JSON type alongside its normalized
// form and exact evidence references.  Normalization never overwrites raw
// evidence.
type IRItem struct {
	ItemID           string          `json:"item_id"`
	IRType           IRType          `json:"ir_type"`
	SourceProtocol   string          `json:"source_protocol"`
	SourceType       string          `json:"source_type"`
	InteractionID    string          `json:"interaction_id"`
	ParentItemID     string          `json:"parent_item_id,omitempty"`
	CallID           string          `json:"call_id,omitempty"`
	NativeValue      json.RawMessage `json:"native_value"`
	NormalizedValue  json.RawMessage `json:"normalized_value,omitempty"`
	EvidenceRefs     []ObjectRef     `json:"evidence_refs"`
	Extension        string          `json:"extension_namespace,omitempty"`
	TransformID      string          `json:"normalization_transform_id"`
	TransformVersion string          `json:"normalization_transform_version"`
	LossMarkers      []LossMarker    `json:"loss_markers,omitempty"`
	Unavailable      []string        `json:"unavailable,omitempty"`
}

func (item IRItem) Validate() error {
	if item.ItemID == "" || item.InteractionID == "" || item.SourceProtocol == "" || item.SourceType == "" {
		return errors.New("IR item identity and source fields are required")
	}
	if !slices.Contains([]IRType{IRMessage, IRContentPart, IRToolCall, IRToolResult, IRReasoningArtifact, IRUsage, IRError, IRLifecycleEvent, IRProviderExtension}, item.IRType) {
		return fmt.Errorf("invalid IR type %q", item.IRType)
	}
	if len(item.NativeValue) == 0 || !json.Valid(item.NativeValue) {
		return errors.New("IR native_value must be valid typed JSON")
	}
	if len(item.EvidenceRefs) == 0 || item.TransformID == "" || item.TransformVersion == "" {
		return errors.New("IR item requires evidence and normalization identity")
	}
	for _, ref := range item.EvidenceRefs {
		if err := ref.Validate(); err != nil {
			return err
		}
	}
	if item.IRType == IRProviderExtension && item.Extension == "" {
		return errors.New("provider extension item requires a namespace")
	}
	return nil
}

type Interaction struct {
	EnvelopeMeta
	InteractionID string   `json:"interaction_id"`
	Items         []IRItem `json:"items"`
}
