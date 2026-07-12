package planner

import (
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func fixtureDigest(char byte) schema.Digest {
	value := make([]byte, 71)
	copy(value, "sha256:")
	for index := 7; index < len(value); index++ {
		value[index] = char
	}
	return schema.Digest(value)
}

func fixtureID(last byte) schema.InstanceID {
	return schema.InstanceID("00000000-0000-7000-8000-00000000000" + string(last))
}

func fixturePolicy() schema.BudgetPolicy {
	return schema.BudgetPolicy{
		Hard:        schema.HardBudget{MaxRequests: 10, MaxRequestBytes: 1000, MaxResponseBytes: 2000, MaxArtifactBytes: 3000, MaxProcesses: 2, MaxDuration: schema.NewDuration(time.Minute)},
		Reservation: schema.TokenBudget{MaxInputTokens: 1000, MaxOutputTokens: 500},
		Cleanup:     schema.HardBudget{MaxRequests: 2, MaxRequestBytes: 100, MaxResponseBytes: 100, MaxArtifactBytes: 100, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Minute)},
	}
}

func fixtureProducer() schema.Producer {
	return schema.Producer{Name: "doctor", Version: "0.1.0", ArtifactDigest: fixtureDigest('a')}
}

func fixtureDriver() schema.ArtifactPin {
	return schema.ArtifactPin{Kind: "Driver", Name: "raw-http", Version: "1.0.0", Digest: fixtureDigest('b')}
}

func TestBuildIntentIsOfflineAndDeterministic(t *testing.T) {
	request := IntentRequest{ID: fixtureID('1'), CreatedAt: schema.NewUTCTime(time.Unix(0, 0)), Producer: fixtureProducer(), ConfigDigest: fixtureDigest('c'), Target: schema.TargetIntent{LogicalRef: "local", ProtocolFamily: "openai-responses", IdentityExpectation: "version-pinned", AllowedOrigin: "http://127.0.0.1:8000"}, Selectors: []schema.ArtifactSelector{{Kind: "ProtocolPack", Name: "openai-responses", Constraint: "2026.07.0", Allowed: []schema.Digest{fixtureDigest('d')}}}, SupportManifestDigest: fixtureDigest('e'), Probe: schema.ProbePolicy{Operations: []string{"models.list"}, Budget: schema.HardBudget{MaxRequests: 1, MaxRequestBytes: 100, MaxResponseBytes: 1000, MaxArtifactBytes: 100, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Second)}, Network: schema.NetworkTargetOnly}, Scenarios: []ScenarioCandidate{{ID: "scenario.one", Capabilities: []string{"streaming"}, Driver: fixtureDriver()}}, Budget: fixturePolicy(), Evidence: schema.EvidencePolicy{Capture: schema.CaptureStandard, Redaction: "strict", Publication: "local"}, Safety: schema.SafetyPolicy{Network: schema.NetworkTargetOnly, Redirects: "same-origin", ToolSideEffects: schema.SideEffectsNone}, Author: "test", ApprovalRequirements: []string{"local"}}
	first, err := BuildIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentDigest != second.ContentDigest || first.CandidateDenominatorDigest != second.CandidateDenominatorDigest {
		t.Fatal("same intent input produced different digests")
	}
}

func TestResolveCannotExpandUnauthorizedBranch(t *testing.T) {
	request := IntentRequest{ID: fixtureID('1'), CreatedAt: schema.NewUTCTime(time.Unix(0, 0)), Producer: fixtureProducer(), ConfigDigest: fixtureDigest('c'), Target: schema.TargetIntent{LogicalRef: "local", ProtocolFamily: "openai-responses", IdentityExpectation: "version-pinned", AllowedOrigin: "http://127.0.0.1:8000"}, Selectors: []schema.ArtifactSelector{{Kind: "ProtocolPack", Name: "openai-responses", Constraint: "2026.07.0", Allowed: []schema.Digest{fixtureDigest('d')}}}, SupportManifestDigest: fixtureDigest('e'), Probe: schema.ProbePolicy{Operations: []string{"models.list"}, Budget: schema.HardBudget{MaxRequests: 1, MaxRequestBytes: 100, MaxResponseBytes: 1000, MaxArtifactBytes: 100, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Second)}, Network: schema.NetworkTargetOnly}, Scenarios: []ScenarioCandidate{{ID: "scenario.one", Capabilities: []string{"streaming"}, Driver: fixtureDriver()}}, Budget: fixturePolicy(), Evidence: schema.EvidencePolicy{Capture: schema.CaptureStandard, Redaction: "strict", Publication: "local"}, Safety: schema.SafetyPolicy{Network: schema.NetworkTargetOnly, Redirects: "same-origin", ToolSideEffects: schema.SideEffectsNone}, Author: "test", ApprovalRequirements: []string{"local"}}
	intent, err := BuildIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	resolution := ResolutionRequest{ID: fixtureID('2'), CreatedAt: schema.NewUTCTime(time.Unix(1, 0)), Producer: fixtureProducer(), Resolver: schema.ArtifactPin{Kind: "Resolver", Name: "core", Version: "1.0.0", Digest: fixtureDigest('f')}, SupportLockDigest: fixtureDigest('1'), Artifacts: []schema.ArtifactPin{fixtureDriver()}, Target: schema.TargetResolution{IdentityLevel: "version-pinned", ObservedFingerprint: fixtureDigest('2')}, Scenarios: []ScenarioCandidate{{ID: "scenario.one", Capabilities: []string{"unapproved"}, Driver: fixtureDriver()}}, Runtime: schema.RuntimePolicy{Concurrency: 1, Timeout: schema.NewDuration(time.Second), Capture: schema.CaptureStandard, Sandbox: "process", Network: schema.NetworkTargetOnly}}
	if _, err := Resolve(intent, resolution); err == nil {
		t.Fatal("resolver expanded an unauthorized capability branch")
	}
}

func TestDefaultTimesSamplesClockOnce(t *testing.T) {
	calls := 0
	instant := time.Unix(1234, 567)
	id, createdAt, err := DefaultTimes(func() time.Time {
		calls++
		return instant.Add(time.Duration(calls-1) * time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("clock sampled %d times", calls)
	}
	if createdAt.Time != instant.UTC() {
		t.Fatalf("created_at=%v", createdAt.Time)
	}
	// The first 48 bits of UUIDv7 encode the same sampled millisecond.
	if id[:8] == "00000000" {
		t.Fatalf("unexpected UUIDv7: %s", id)
	}
}
