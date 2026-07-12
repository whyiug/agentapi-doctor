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
			SchemaVersion: "urn:agentapi-doctor:evidence:v1alpha1",
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
