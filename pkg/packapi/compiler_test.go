package packapi

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const validScenarioYAML = `apiVersion: urn:agentapi-doctor:scenario:v1beta1
kind: Scenario
metadata:
  id: openai.responses.streaming.parallel-tool-call
  version: 1.2.0
  title: Two scripted calls preserve their evidence links
  labels:
    protocol: openai-responses
    feature: tool-calling
spec:
  protocol:
    family: openai-responses
    snapshot: "2026-07-10"
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  classification:
    type: normative
    stability: stable
    sideEffects: reversible-remote
    idempotent: true
  requirements:
    - id: OAI-RESP-STREAM-FUNC-004
      level: MUST
  requires:
    all:
      - streaming
      - function-calling
  budgets:
    timeout: 45s
    maxRequests: 9
    maxInputTokens: 3000
    maxOutputTokens: 1000
    maxResponseBytes: 8MiB
    maxArtifactBytes: 16MiB
  resources:
    - id: stored-response
      acquireFrom: create.response_id
      sideEffectClass: reversible-remote
      finalizer:
        operation: responses.delete
        idempotent: true
        retry:
          maxAttempts: 3
      cleanupBudget:
        requests: 3
        duration: 10s
  steps:
    - id: create
      invoke:
        operation: responses.create
        driver: raw
        controlledBackend:
          fixture: responses/parallel-two-tools-v1
        request:
          model: "{{ target.model }}"
          stream: true
          tools:
            - fixture: tools/weather.yaml
    - id: collect
      capture:
        stream: create.stream
        as: response-stream
    - id: register
      register_resource:
        resource: stored-response
        acquireFrom: create.response_id
    - id: provide
      provide_tool_result:
        callIdFrom: create.call_id
        result:
          text: synthetic result
    - id: wait
      wait_for:
        source: create.status
        condition: actual == "ready"
        timeout: 1s
    - id: verify
      assert:
        - use: fixture.expected-tool-call-count
          equals: 2
          assertionRole: precondition
          observedAt: controlled-backend-source
        - expression: actual == expected
          assertionRole: normative
        - use: transform.preserves-tool-call-cardinality
          assertionRole: consumer_profile
          requirement: RUNTIME-CONTROLLED-TRANSFORM-001
        - expression: actual == true
          assertionRole: behavioral
        - use: diagnostics.latency
          assertionRole: advisory
    - id: stop
      cancel:
        invocation: create.invocation
        reason: bounded cancellation check
    - id: replay
      replay:
        fixture: traces/response.json
        as: replayed-response
    - id: cleanup
      finalize:
        finalize: stored-response
  finally:
    - finalize: stored-response
  repetition:
    count: 3
    policy: all
  publication:
    dataClass: synthetic-only
`

const validPackYAML = `apiVersion: urn:agentapi-doctor:pack:v1
kind: ProtocolPack
metadata:
  name: openai-responses-http
  version: 2026.07.0
spec:
  engine:
    minVersion: 1.0.0
    maxMajor: 1
  protocolSnapshot:
    ref: specs/openai-responses/2026-07-10.yaml
  scenarios:
    include:
      - scenarios/**/*.yaml
  conformanceSuites:
    core:
      requirements:
        - core
        - streaming
        - errors
    agent:
      requirements:
        - core
        - tools
        - state
  defaultBudget:
    maxRequests: 80
    maxDuration: 15m0s
`

func validCompileOptions() CompileOptions {
	return CompileOptions{
		Requirements: map[string]RequirementRecord{
			"OAI-RESP-STREAM-FUNC-004": {
				ID: "OAI-RESP-STREAM-FUNC-004", Level: LevelMust, Category: ClassNormative,
				SourceDigest: publicschema.NewDigest([]byte("normative-source")),
			},
			"RUNTIME-CONTROLLED-TRANSFORM-001": {
				ID: "RUNTIME-CONTROLLED-TRANSFORM-001", Level: LevelMust, Category: ClassConsumerProfile,
				SourceDigest: publicschema.NewDigest([]byte("consumer-source")),
			},
		},
		Fixtures: map[string]publicschema.Digest{
			"responses/parallel-two-tools-v1": publicschema.NewDigest([]byte("backend-fixture")),
			"tools/weather.yaml":              publicschema.NewDigest([]byte("tool-fixture")),
			"traces/response.json":            publicschema.NewDigest([]byte("trace-fixture")),
		},
	}
}

func validPackOptions() PackCompileOptions {
	return PackCompileOptions{
		ProtocolSnapshots: map[string]publicschema.Digest{
			"specs/openai-responses/2026-07-10.yaml": publicschema.NewDigest([]byte("snapshot")),
		},
		ScenarioFiles: map[string]publicschema.Digest{
			"scenarios/core.yaml":            publicschema.NewDigest([]byte("core")),
			"scenarios/streaming/tools.yaml": publicschema.NewDigest([]byte("tools")),
		},
	}
}

func TestCompileScenarioYAMLCompleteContract(t *testing.T) {
	compiled, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Digest != publicschema.NewDigest(compiled.CanonicalJSON) {
		t.Fatal("digest does not bind canonical IR")
	}
	recanonical, err := publicschema.CanonicalizeJSON(compiled.CanonicalJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recanonical, compiled.CanonicalJSON) {
		t.Fatal("compiler output is not RFC 8785 canonical JSON")
	}
	if got, want := len(compiled.IR.FixturePins), 3; got != want {
		t.Fatalf("want %d fixture pins, got %d", want, got)
	}
	if got, want := len(compiled.IR.RequirementLinks), 2; got != want {
		t.Fatalf("want %d requirement links, got %d", want, got)
	}
	if got, want := len(compiled.IR.CELBindings), 3; got != want {
		t.Fatalf("want %d CEL bindings, got %d", want, got)
	}
	if got, want := len(compiled.IR.TemplateBindings), 1; got != want {
		t.Fatalf("want %d safe template binding, got %d", want, got)
	}
	if compiled.IR.TemplateBindings[0].Variables[0] != "target.model" {
		t.Fatalf("unexpected template binding: %+v", compiled.IR.TemplateBindings[0])
	}
	assertions := *compiled.Authored.Spec.Steps[5].Assert
	if got, want := assertions[1].Requirement, "OAI-RESP-STREAM-FUNC-004"; got != want {
		t.Fatalf("normative requirement was not resolved: want %q, got %q", want, got)
	}
	if compiled.Authored.Spec.Budgets.MaxArtifactBytes != 16*MiB {
		t.Fatal("byte-size budget did not normalize")
	}
	if strings.Contains(string(compiled.CanonicalJSON), "{{ env.") {
		t.Fatal("unsafe variable survived compilation")
	}
}

func TestScenarioDigestIgnoresYAMLPresentation(t *testing.T) {
	first, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	variant := strings.Replace(validScenarioYAML,
		"  labels:\n    protocol: openai-responses\n    feature: tool-calling\n",
		"  labels: # mapping order and comments are not identity\n    feature: tool-calling\n    protocol: openai-responses\n", 1)
	second, err := CompileScenarioYAML([]byte(variant), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !bytes.Equal(first.CanonicalJSON, second.CanonicalJSON) {
		t.Fatalf("presentation changed identity: %s != %s", first.Digest, second.Digest)
	}
}

func TestScenarioSemanticChangeChangesDigest(t *testing.T) {
	first, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	changedYAML := strings.Replace(validScenarioYAML, "synthetic result", "different synthetic result", 1)
	changed, err := CompileScenarioYAML([]byte(changedYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == changed.Digest {
		t.Fatal("semantic mutation did not change digest")
	}
}

func TestCompileProtocolPackResolvesImmutableInputs(t *testing.T) {
	compiled, err := CompileProtocolPackYAML([]byte(validPackYAML), validPackOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(compiled.IR.ScenarioPins), 2; got != want {
		t.Fatalf("want %d scenario pins, got %d", want, got)
	}
	if compiled.IR.ScenarioPins[0].Path != "scenarios/core.yaml" || compiled.IR.ScenarioPins[1].Path != "scenarios/streaming/tools.yaml" {
		t.Fatalf("scenario pins are not canonical: %+v", compiled.IR.ScenarioPins)
	}
	if compiled.Digest != publicschema.NewDigest(compiled.CanonicalJSON) {
		t.Fatal("pack digest does not bind canonical IR")
	}
	withSigning := strings.TrimSuffix(validPackYAML, "\n") + "\n  signing:\n    digest: " + string(compiled.Digest) + "\n"
	declared, err := CompileProtocolPackYAML([]byte(withSigning), validPackOptions())
	if err != nil {
		t.Fatal(err)
	}
	if declared.Digest != compiled.Digest {
		t.Fatal("detached signing expectation changed pack identity")
	}
}

func TestCompileProtocolPackRejectsWrongDeclaredDigest(t *testing.T) {
	withSigning := strings.TrimSuffix(validPackYAML, "\n") + "\n  signing:\n    digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
	_, err := CompileProtocolPackYAML([]byte(withSigning), validPackOptions())
	if err == nil || !IsCompileStage(err, StageCanonical) {
		t.Fatalf("want canonical digest mismatch, got %v", err)
	}
}

func TestCompileErrorUnwrapAndStage(t *testing.T) {
	cause := errors.New("cause")
	err := &CompileError{Stage: StageFixture, Path: "$.fixture", Err: cause}
	if !errors.Is(err, cause) || !IsCompileStage(err, StageFixture) {
		t.Fatal("compile error does not preserve cause/stage")
	}
}
