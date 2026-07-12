package driverprotocol

import (
	"encoding/json"
	"fmt"
	"testing"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	testInvocationOne publicschema.InstanceID = "018f0000-0000-7000-8000-000000000001"
	testAttemptOne    publicschema.InstanceID = "018f0000-0000-7000-8000-000000000002"
	testInvocationTwo publicschema.InstanceID = "018f0000-0000-7000-8000-000000000003"
	testAttemptTwo    publicschema.InstanceID = "018f0000-0000-7000-8000-000000000004"
)

func invokeParams(invocationID, attemptID publicschema.InstanceID) InvokeParams {
	return InvokeParams{
		InvocationID: invocationID,
		AttemptID:    attemptID,
		Operation:    "responses.create",
		Input: ExactInputHandle{
			Kind:  "pipe",
			Value: "invocation-scoped-handle",
		},
	}
}

func observationParams(invocationID, attemptID publicschema.InstanceID, sequence uint64) ObservationParams {
	return ObservationParams{
		InvocationID: invocationID,
		AttemptID:    attemptID,
		Sequence:     sequence,
		Kind:         "sdk.event",
		MonotonicNS:  sequence * 100,
		Payload:      json.RawMessage(`{"type":"delta"}`),
	}
}

func completedParams(invocationID, attemptID publicschema.InstanceID, last *uint64) CompletedParams {
	return CompletedParams{
		InvocationID:  invocationID,
		AttemptID:     attemptID,
		Status:        TerminalCompleted,
		LastSequence:  last,
		SummaryDigest: publicschema.NewDigest([]byte("summary")),
	}
}

func assertState(t *testing.T, machine *Machine, want State) {
	t.Helper()
	if got := machine.State(); got != want {
		t.Fatalf("want state %s, got %s", want, got)
	}
}

func requireClass(t *testing.T, err error, want ErrorClass) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error", want)
	}
	got, ok := ErrorClassOf(err)
	if !ok || got != want {
		t.Fatalf("want class %s, got %s (%v)", want, got, err)
	}
}

func TestMachineCompleteLifecycle(t *testing.T) {
	machine := NewMachine()
	assertState(t, machine, StateNew)
	if _, active := machine.Active(); active {
		t.Fatal("NEW machine has an active invocation")
	}

	if err := machine.AcceptHello(); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StateHello)
	if err := machine.CheckCapabilities(); err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptPrepare(); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StatePrepared)

	if err := machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StateInvoking)
	if err := machine.Observe(observationParams(testInvocationOne, testAttemptOne, 0)); err != nil {
		t.Fatal(err)
	}
	if err := machine.Observe(observationParams(testInvocationOne, testAttemptOne, 2)); err != nil {
		t.Fatal(err)
	}
	if err := machine.RequestCancel(CancelParams{
		InvocationID:   testInvocationOne,
		Reason:         "user requested cancellation",
		DeadlineMillis: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StateInvoking)
	active, ok := machine.Active()
	if !ok || !active.CancelRequested || active.LastSequence != 2 {
		t.Fatalf("unexpected active snapshot: %+v, %v", active, ok)
	}
	if err := machine.Observe(observationParams(testInvocationOne, testAttemptOne, 5)); err != nil {
		t.Fatal(err)
	}
	last := uint64(5)
	if err := machine.Complete(completedParams(testInvocationOne, testAttemptOne, &last)); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StatePrepared)
	if _, active := machine.Active(); active {
		t.Fatal("terminal invocation remained active")
	}

	if err := machine.BeginInvocation(invokeParams(testInvocationTwo, testAttemptTwo)); err != nil {
		t.Fatal(err)
	}
	if err := machine.Complete(completedParams(testInvocationTwo, testAttemptTwo, nil)); err != nil {
		t.Fatal(err)
	}
	if err := machine.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := machine.Shutdown(); err != nil {
		t.Fatal(err)
	}
	assertState(t, machine, StateShutdown)
}

func TestMachineRejectsInvalidTransitions(t *testing.T) {
	machine := NewMachine()
	requireClass(t, machine.AcceptPrepare(), ErrorInvalidState)
	requireClass(t, machine.CheckCapabilities(), ErrorInvalidState)
	requireClass(t, machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)), ErrorInvalidState)
	requireClass(t, machine.Reset(), ErrorInvalidState)
	requireClass(t, machine.Shutdown(), ErrorInvalidState)
	assertState(t, machine, StateNew)

	if err := machine.AcceptHello(); err != nil {
		t.Fatal(err)
	}
	requireClass(t, machine.AcceptHello(), ErrorInvalidState)
	requireClass(t, machine.Shutdown(), ErrorInvalidState)
	if err := machine.AcceptPrepare(); err != nil {
		t.Fatal(err)
	}
	requireClass(t, machine.AcceptPrepare(), ErrorInvalidState)
	if err := machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)); err != nil {
		t.Fatal(err)
	}
	requireClass(t, machine.Reset(), ErrorInvalidState)
	requireClass(t, machine.Shutdown(), ErrorInvalidState)
	requireClass(t, machine.BeginInvocation(invokeParams(testInvocationTwo, testAttemptTwo)), ErrorInvalidState)
}

func TestMachineSequenceIdentityTerminalAndReuse(t *testing.T) {
	machine := preparedMachine(t)
	if err := machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)); err != nil {
		t.Fatal(err)
	}

	wrongAttempt := observationParams(testInvocationOne, testAttemptTwo, 1)
	requireClass(t, machine.Observe(wrongAttempt), ErrorMalformedObservation)
	if err := machine.Observe(observationParams(testInvocationOne, testAttemptOne, 10)); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{10, 9, 0} {
		requireClass(t, machine.Observe(observationParams(testInvocationOne, testAttemptOne, sequence)), ErrorMalformedObservation)
	}
	wrongLast := uint64(9)
	requireClass(t, machine.Complete(completedParams(testInvocationOne, testAttemptOne, &wrongLast)), ErrorMalformedObservation)
	missingLast := completedParams(testInvocationOne, testAttemptOne, nil)
	requireClass(t, machine.Complete(missingLast), ErrorMalformedObservation)
	last := uint64(10)
	terminal := completedParams(testInvocationOne, testAttemptOne, &last)
	if err := machine.Complete(terminal); err != nil {
		t.Fatal(err)
	}
	requireClass(t, machine.Observe(observationParams(testInvocationOne, testAttemptOne, 11)), ErrorInvalidState)
	requireClass(t, machine.Complete(terminal), ErrorInvalidState)
	requireClass(t, machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptTwo)), ErrorInvalidRequest)
}

func TestMachineNoObservationRequiresOmittedLastSequence(t *testing.T) {
	machine := preparedMachine(t)
	if err := machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)); err != nil {
		t.Fatal(err)
	}
	zero := uint64(0)
	requireClass(t, machine.Complete(completedParams(testInvocationOne, testAttemptOne, &zero)), ErrorMalformedObservation)
	if err := machine.Complete(completedParams(testInvocationOne, testAttemptOne, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestMachineMonotonicSequencePropertyLike(t *testing.T) {
	machine := preparedMachine(t)
	if err := machine.BeginInvocation(invokeParams(testInvocationOne, testAttemptOne)); err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	for index := 0; index < 4096; index++ {
		sequence += uint64(index%7 + 1)
		if err := machine.Observe(observationParams(testInvocationOne, testAttemptOne, sequence)); err != nil {
			t.Fatalf("observation %d: %v", index, err)
		}
	}
	if err := machine.Complete(completedParams(testInvocationOne, testAttemptOne, &sequence)); err != nil {
		t.Fatal(err)
	}
}

func TestApplyStrictWireLifecycle(t *testing.T) {
	machine := NewMachine()
	apply := func(method Method, id string, params any) {
		t.Helper()
		rawParams, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		message := Message{JSONRPC: JSONRPCVersion, Method: method, Params: rawParams}
		if id != "" {
			message.ID = json.RawMessage(id)
		}
		encoded, err := EncodeControlFrame(message)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeControlFrame(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := machine.Apply(decoded); err != nil {
			t.Fatalf("apply %s: %v", method, err)
		}
	}

	apply(MethodHello, `1`, HelloParams{CoreVersionRange: VersionRange{Minimum: "1.0.0", Maximum: "1.0.0"}})
	apply(MethodPrepare, `2`, PrepareParams{
		ResolvedPlanDigest:  publicschema.NewDigest([]byte("plan")),
		CapabilityToken:     "ephemeral-test-token",
		ApprovedPermissions: []Permission{"target-only-network"},
	})
	apply(MethodInvoke, `3`, invokeParams(testInvocationOne, testAttemptOne))
	apply(MethodObservation, "", observationParams(testInvocationOne, testAttemptOne, 4))
	last := uint64(4)
	apply(MethodCompleted, "", completedParams(testInvocationOne, testAttemptOne, &last))
	apply(MethodShutdown, `4`, ShutdownParams{})
	assertState(t, machine, StateShutdown)
}

func TestDecoderRejectsUnknownTypedParamBeforeApply(t *testing.T) {
	machine := NewMachine()
	_, err := DecodeControlFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"driver.hello","params":{"core_version_range":{"minimum":"1.0.0","maximum":"1.0.0"},"typo":true}}`))
	requireClass(t, err, ErrorInvalidRequest)
	assertState(t, machine, StateNew)
}

func TestDataFrameHeaderValidation(t *testing.T) {
	header := DataFrameHeader{
		InvocationID: testInvocationOne,
		AttemptID:    testAttemptOne,
		StreamID:     "stream-1",
		Sequence:     7,
		Length:       DefaultMaxDataFrameBytes,
		Final:        true,
	}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	header.Length++
	if err := header.Validate(); err == nil {
		t.Fatal("accepted oversized data frame header")
	}
}

func TestTypedContractValidation(t *testing.T) {
	identity := DriverIdentity{
		Name:           "openai-python",
		Version:        "1.0.0",
		SDKName:        "openai",
		SDKVersion:     "2.0.0",
		RuntimeName:    "python",
		RuntimeVersion: "3.13.0",
		OS:             "linux",
		Architecture:   "amd64",
		ArtifactDigest: publicschema.NewDigest([]byte("driver")),
		LockfileDigest: publicschema.NewDigest([]byte("lock")),
	}
	result := HelloResult{
		DriverVersionRange: VersionRange{Minimum: "1.0.0", Maximum: "1.0.0"},
		Identity:           identity,
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	result.Identity.SDKVersion = ""
	if err := result.Validate(); err == nil {
		t.Fatal("accepted partial SDK identity")
	}

	observation := observationParams(testInvocationOne, testAttemptOne, 1)
	observation.DataStream = &CompanionStreamRef{StreamID: "stream-1"}
	if err := observation.Validate(); err == nil {
		t.Fatal("accepted inline and companion payload together")
	}
	observation.Payload = nil
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
}

func preparedMachine(t *testing.T) *Machine {
	t.Helper()
	machine := NewMachine()
	if err := machine.AcceptHello(); err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptPrepare(); err != nil {
		t.Fatal(err)
	}
	return machine
}

func ExampleMachine() {
	machine := NewMachine()
	_ = machine.AcceptHello()
	_ = machine.AcceptPrepare()
	fmt.Println(machine.State())
	// Output: PREPARED
}
