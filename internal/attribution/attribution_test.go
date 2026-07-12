package attribution

import (
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func pointer(value bool) *bool { return &value }

func TestClassifySDKDifferential(t *testing.T) {
	result := Classify(Evidence{HarnessHealthy: pointer(true), RawWireValid: pointer(true), SDKAccepts: pointer(false)})
	if result.Domain != DomainSDKParser || result.Family != schema.FaultClient || result.Confidence < 0.8 {
		t.Fatalf("unexpected attribution: %#v", result)
	}
}

func TestClassifyMissingEvidenceStaysUnknown(t *testing.T) {
	result := Classify(Evidence{})
	if result.Domain != DomainUnknown || result.Family != schema.FaultUnknown {
		t.Fatalf("unexpected attribution: %#v", result)
	}
}

func TestHarnessPreconditionTakesPriority(t *testing.T) {
	result := Classify(Evidence{HarnessHealthy: pointer(false), RawWireValid: pointer(false)})
	if result.Domain != DomainHarness || result.Family != schema.FaultHarness {
		t.Fatalf("unexpected attribution: %#v", result)
	}
}

func TestValidatePairRejectsNamespaceConfusion(t *testing.T) {
	if err := ValidatePair(DomainStreamStateMachine, schema.FaultProtocol); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestFingerprintCanonicalAndStable(t *testing.T) {
	left, err := Fingerprint("case", "assert", "type", map[string]any{"b": 2, "a": 1}, []any{"x"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Fingerprint("case", "assert", "type", map[string]any{"a": 1, "b": 2}, []any{"x"})
	if err != nil || left != right {
		t.Fatalf("fingerprints differ: %s %s (%v)", left, right, err)
	}
}
