package normalizer

import (
	"bytes"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestProviderNativeToolArgumentTypesRemainDistinct(t *testing.T) {
	stringItem, err := Normalize(testRequest([]byte(`"{\"city\":\"Paris\"}"`), TransformDecodeJSONString))
	if err != nil {
		t.Fatal(err)
	}
	objectItem, err := Normalize(testRequest([]byte(`{"city":"Paris"}`), TransformIdentity))
	if err != nil {
		t.Fatal(err)
	}
	if stringItem.SourceType != "string" || objectItem.SourceType != "object" {
		t.Fatalf("native types lost: %q and %q", stringItem.SourceType, objectItem.SourceType)
	}
	if bytes.Equal(stringItem.NativeValue, objectItem.NativeValue) {
		t.Fatal("native wire values were overwritten by normalized value")
	}
	if !bytes.Equal(stringItem.NormalizedValue, objectItem.NormalizedValue) {
		t.Fatalf("expected equivalent semantic JSON:\n%s\n%s", stringItem.NormalizedValue, objectItem.NormalizedValue)
	}
}

func TestInvalidJSONStringProducesLossMarkerInsteadOfSilentEquality(t *testing.T) {
	item, err := Normalize(testRequest([]byte(`"{not-json"`), TransformDecodeJSONString))
	if err != nil {
		t.Fatal(err)
	}
	if len(item.NormalizedValue) != 0 || len(item.LossMarkers) != 1 || len(item.Unavailable) != 1 {
		t.Fatalf("missing explicit loss state: %#v", item)
	}
	if item.SourceType != "string" {
		t.Fatalf("native type changed: %q", item.SourceType)
	}
}

func TestMalformedProviderNativeJSONIsRejected(t *testing.T) {
	if _, err := Normalize(testRequest([]byte(`{"broken":`), TransformIdentity)); err == nil {
		t.Fatal("malformed provider-native JSON must be rejected")
	}
}

func TestDecodeJSONStringRejectsObjectWithoutRecasingIt(t *testing.T) {
	if _, err := Normalize(testRequest([]byte(`{"city":"Paris"}`), TransformDecodeJSONString)); err == nil {
		t.Fatal("configured transform mismatch must be explicit")
	}
}

func testRequest(native []byte, transform Transform) Request {
	return Request{
		ItemID:         "item-1",
		IRType:         schema.IRToolCall,
		SourceProtocol: "synthetic-protocol",
		InteractionID:  "interaction-1",
		CallID:         "call-1",
		NativeValue:    native,
		EvidenceRefs: []schema.ObjectRef{{
			Kind:          "Evidence",
			ContentDigest: schema.NewDigest([]byte("evidence")),
		}},
		Transform: transform,
		Version:   "1.0.0",
	}
}
