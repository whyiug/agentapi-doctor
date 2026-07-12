package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceRequiresDigestBoundPayloadOrUnavailableReason(t *testing.T) {
	digest := Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	id := InstanceID("00000000-0000-7000-8000-000000000000")
	base := Evidence{
		EnvelopeMeta: EnvelopeMeta{
			SchemaVersion: "urn:agentapi-doctor:evidence:v1alpha2",
			Kind:          "Evidence",
			ContentDigest: digest,
			ObjectRef:     ObjectRef{Kind: "Evidence", ContentDigest: digest},
			Producer:      Producer{Name: "doctor", Version: "0.1.0", ArtifactDigest: digest},
			CreatedAt:     NewUTCTime(time.Unix(0, 0)),
		},
		EvidenceID:          digest,
		RunID:               id,
		InvocationID:        id,
		AttemptID:           id,
		Sequence:            1,
		CaptureLayer:        LayerSanitizedPersisted,
		InstrumentationMode: InstrumentationDirect,
		Direction:           DirectionTargetToCore,
		EvidenceKind:        "sse.data",
		MonotonicOffsetNS:   1,
		Redactions:          []RedactionRecord{},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("accepted missing payload without reason")
	}
	base.UnavailableReason = "source_bytes_not_retained"
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.UnavailableReason = ""
	ref := ObjectRef{Kind: "Payload", ContentDigest: digest}
	other := Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	base.PayloadRef, base.PayloadDigest = &ref, &other
	if err := base.Validate(); err == nil {
		t.Fatal("accepted mismatched payload digest")
	}
	base.PayloadDigest = &digest
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRejectsInvalidObservationAndGraphBindings(t *testing.T) {
	digest := Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	id := InstanceID("00000000-0000-7000-8000-000000000000")
	ref := ObjectRef{Kind: "Payload", ContentDigest: digest}
	base := Evidence{
		EnvelopeMeta: EnvelopeMeta{
			SchemaVersion: "urn:agentapi-doctor:evidence:v1alpha2", Kind: "Evidence", ContentDigest: digest,
			ObjectRef: ObjectRef{Kind: "Evidence", ContentDigest: digest},
			Producer:  Producer{Name: "doctor", Version: "0.1.0", ArtifactDigest: digest}, CreatedAt: NewUTCTime(time.Unix(0, 0)),
		},
		EvidenceID: digest, RunID: id, InvocationID: id, AttemptID: id, Sequence: 1,
		CaptureLayer: LayerUpstreamApplication, InstrumentationMode: InstrumentationDirect,
		Direction: DirectionTargetToCore, EvidenceKind: "response", MonotonicOffsetNS: 1,
		PayloadRef: &ref, PayloadDigest: &digest, Redactions: []RedactionRecord{},
	}
	negative := int64(-1)
	tests := map[string]func(*Evidence){
		"unknown direction":     func(value *Evidence) { value.Direction = Direction("sideways") },
		"wrong layer mode":      func(value *Evidence) { value.InstrumentationMode = InstrumentationProxy },
		"wrong layer direction": func(value *Evidence) { value.Direction = DirectionProxyToClient },
		"negative byte offset":  func(value *Evidence) { value.ByteOffset = &negative },
		"negative event offset": func(value *Evidence) { value.EventOffset = &negative },
		"payload instance": func(value *Evidence) {
			value.PayloadRef = &ObjectRef{Kind: "Payload", InstanceID: id, ContentDigest: digest}
		},
		"payload wrong kind":       func(value *Evidence) { value.PayloadRef = &ObjectRef{Kind: "Evidence", ContentDigest: digest} },
		"payload also unavailable": func(value *Evidence) { value.UnavailableReason = "not available" },
		"empty relation":           func(value *Evidence) { value.Relations = []EvidenceRelation{{Target: ref}} },
		"invalid relation target": func(value *Evidence) {
			value.Relations = []EvidenceRelation{{Relation: "derived_from", Target: ObjectRef{Kind: "Payload"}}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid Evidence was accepted")
			}
		})
	}
}

func TestIRPreservesProviderNativeType(t *testing.T) {
	digest := Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ref := ObjectRef{Kind: "Evidence", ContentDigest: digest}
	stringArguments := IRItem{ItemID: "item-1", IRType: IRToolCall, SourceProtocol: "openai-responses", SourceType: "json_string", InteractionID: "interaction-1", NativeValue: json.RawMessage(`"{\"city\":\"Tokyo\"}"`), EvidenceRefs: []ObjectRef{ref}, TransformID: "tool-call-v1", TransformVersion: "1.0.0"}
	objectArguments := stringArguments
	objectArguments.SourceProtocol = "google-generate-content"
	objectArguments.SourceType = "json_object"
	objectArguments.NativeValue = json.RawMessage(`{"city":"Tokyo"}`)
	for _, item := range []IRItem{stringArguments, objectArguments} {
		if err := item.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if string(stringArguments.NativeValue) == string(objectArguments.NativeValue) || stringArguments.SourceType == objectArguments.SourceType {
		t.Fatal("provider-native argument types were collapsed")
	}
}
