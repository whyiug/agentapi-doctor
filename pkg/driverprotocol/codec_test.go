package driverprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestDecodeControlFrameKinds(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind MessageKind
	}{
		{
			name: "request",
			raw:  `{"jsonrpc":"2.0","id":"request-1","method":"driver.reset","params":{}}` + "\n",
			kind: MessageRequest,
		},
		{
			name: "notification",
			raw:  `{"jsonrpc":"2.0","method":"driver.observation","params":{"invocation_id":"018f0000-0000-7000-8000-000000000001","attempt_id":"018f0000-0000-7000-8000-000000000002","sequence":1,"kind":"sdk.event","monotonic_ns":1}}` + "\r\n",
			kind: MessageNotification,
		},
		{
			name: "result response",
			raw:  `{"jsonrpc":"2.0","id":7,"result":null}`,
			kind: MessageResponse,
		},
		{
			name: "error response",
			raw:  `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"bad state","data":{"class":"invalid_state"}}}`,
			kind: MessageResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := DecodeControlFrame([]byte(test.raw))
			if err != nil {
				t.Fatal(err)
			}
			kind, err := message.Kind()
			if err != nil {
				t.Fatal(err)
			}
			if kind != test.kind {
				t.Fatalf("want kind %d, got %d", test.kind, kind)
			}
		})
	}
}

func TestDecodeControlFrameRejectsAmbiguousOrInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		class ErrorClass
	}{
		{name: "empty", raw: "", class: ErrorInvalidRequest},
		{name: "only newline", raw: "\n", class: ErrorInvalidRequest},
		{name: "physical multiline", raw: "{\n\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"driver.reset\"}\n", class: ErrorInvalidRequest},
		{name: "concatenated", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.reset"} {}`, class: ErrorInvalidRequest},
		{name: "duplicate root", raw: `{"jsonrpc":"2.0","id":1,"id":2,"method":"driver.reset"}`, class: ErrorInvalidRequest},
		{name: "duplicate nested", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.reset","params":{"a":1,"a":2}}`, class: ErrorInvalidRequest},
		{name: "unknown root", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.reset","extra":true}`, class: ErrorInvalidRequest},
		{name: "array root", raw: `[]`, class: ErrorInvalidRequest},
		{name: "wrong JSON-RPC", raw: `{"jsonrpc":"1.0","id":1,"method":"driver.reset"}`, class: ErrorUnsupportedRPCVersion},
		{name: "unknown method", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.future"}`, class: ErrorInvalidRequest},
		{name: "request missing ID", raw: `{"jsonrpc":"2.0","method":"driver.reset"}`, class: ErrorInvalidRequest},
		{name: "null request ID", raw: `{"jsonrpc":"2.0","id":null,"method":"driver.reset"}`, class: ErrorInvalidRequest},
		{name: "fractional request ID", raw: `{"jsonrpc":"2.0","id":1.5,"method":"driver.reset"}`, class: ErrorInvalidRequest},
		{name: "notification with ID", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.completed","params":{}}`, class: ErrorInvalidRequest},
		{name: "scalar params", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.reset","params":true}`, class: ErrorInvalidRequest},
		{name: "request with result", raw: `{"jsonrpc":"2.0","id":1,"method":"driver.reset","result":{}}`, class: ErrorInvalidRequest},
		{name: "response without result", raw: `{"jsonrpc":"2.0","id":1}`, class: ErrorInvalidRequest},
		{name: "response with result and error", raw: `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x","data":{"class":"driver_internal"}}}`, class: ErrorInvalidRequest},
		{name: "unknown error field", raw: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x","data":{"class":"driver_internal"},"extra":true}}`, class: ErrorInvalidRequest},
		{name: "unknown error class", raw: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x","data":{"class":"future_error"}}}`, class: ErrorInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeControlFrame([]byte(test.raw))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if class, ok := ErrorClassOf(err); !ok || class != test.class {
				t.Fatalf("want class %q, got %q (%v)", test.class, class, err)
			}
		})
	}
}

func TestDecodeParamsStrictRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	type params struct {
		Name string `json:"name"`
	}
	for _, raw := range []string{
		`{"name":"ok","unknown":true}`,
		`{"name":"first","name":"second"}`,
		`{"name":"ok"}{}`,
	} {
		var destination params
		if err := DecodeParamsStrict(json.RawMessage(raw), &destination); err == nil {
			t.Fatalf("accepted ambiguous params %s", raw)
		}
	}
	var destination params
	if err := DecodeParamsStrict(json.RawMessage(`{"name":"ok"}`), &destination); err != nil {
		t.Fatal(err)
	}
	if destination.Name != "ok" {
		t.Fatalf("unexpected decoded value %q", destination.Name)
	}
}

func TestEncodeControlFrameIsCanonicalSingleLine(t *testing.T) {
	message := Message{
		JSONRPC: JSONRPCVersion,
		ID:      json.RawMessage(`"b"`),
		Method:  MethodReset,
		Params:  json.RawMessage(`{}`),
	}
	encoded, err := EncodeControlFrame(message)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"id\":\"b\",\"jsonrpc\":\"2.0\",\"method\":\"driver.reset\",\"params\":{}}\n"
	if string(encoded) != want {
		t.Fatalf("want %q, got %q", want, encoded)
	}
	if _, err := DecodeControlFrame(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestControlFrameBounds(t *testing.T) {
	prefix := `{"jsonrpc":"2.0","method":"driver.observation","params":{"invocation_id":"018f0000-0000-7000-8000-000000000001","attempt_id":"018f0000-0000-7000-8000-000000000002","sequence":0,"kind":"sdk.event","monotonic_ns":0,"payload":"`
	suffix := `"}}`
	padding := MaxControlFrameBytes - len(prefix) - len(suffix)
	if padding <= 0 {
		t.Fatal("test envelope unexpectedly exceeds frame bound")
	}
	exact := []byte(prefix + strings.Repeat("x", padding) + suffix)
	if len(exact) != MaxControlFrameBytes {
		t.Fatalf("constructed frame has %d bytes", len(exact))
	}
	if _, err := DecodeControlFrame(exact); err != nil {
		t.Fatalf("exact-bound frame rejected: %v", err)
	}
	over := append(bytes.Clone(exact[:len(exact)-len(suffix)]), 'x')
	over = append(over, suffix...)
	if _, err := DecodeControlFrame(over); !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("want frame-too-large, got %v", err)
	}
}

func TestStreamingDecoderAndEncoder(t *testing.T) {
	first := Message{JSONRPC: JSONRPCVersion, ID: json.RawMessage(`1`), Method: MethodReset}
	second := Message{JSONRPC: JSONRPCVersion, ID: json.RawMessage(`2`), Method: MethodShutdown, Params: json.RawMessage(`{}`)}
	var wire bytes.Buffer
	encoder := NewEncoder(&wire)
	if err := encoder.Encode(first); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(second); err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder(&wire)
	for index, want := range []Method{MethodReset, MethodShutdown} {
		message, err := decoder.Decode()
		if err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
		if message.Method != want {
			t.Fatalf("frame %d: want %s, got %s", index, want, message.Method)
		}
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestStreamingDecoderDrainsOversizedLine(t *testing.T) {
	valid := `{"jsonrpc":"2.0","id":2,"method":"driver.reset"}` + "\n"
	wire := strings.Repeat("x", MaxControlFrameBytes+17) + "\n" + valid
	decoder := NewDecoder(strings.NewReader(wire))
	if _, err := decoder.Decode(); !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("want oversized-line error, got %v", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if message.Method != MethodReset {
		t.Fatalf("unexpected recovered method %s", message.Method)
	}
}

func TestFrameSizeBoundsPropertyLike(t *testing.T) {
	for size := 0; size <= MaxControlFrameBytes; size += 4093 {
		if err := ValidateControlFrameSize(size); err != nil {
			t.Fatalf("control size %d rejected: %v", size, err)
		}
	}
	if err := ValidateControlFrameSize(MaxControlFrameBytes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateControlFrameSize(MaxControlFrameBytes + 1); !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("unexpected control bound error: %v", err)
	}
	for size := 0; size <= DefaultMaxDataFrameBytes; size += 2053 {
		if err := ValidateDataFrameSize(size); err != nil {
			t.Fatalf("data size %d rejected: %v", size, err)
		}
	}
	if err := ValidateDataFrameSize(DefaultMaxDataFrameBytes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDataFrameSize(DefaultMaxDataFrameBytes + 1); !errors.Is(err, ErrDataFrameTooLarge) {
		t.Fatalf("unexpected data bound error: %v", err)
	}
}

func TestAllStableErrorClassesRoundTrip(t *testing.T) {
	classes := []ErrorClass{
		ErrorUnsupportedRPCVersion,
		ErrorInvalidState,
		ErrorInvalidRequest,
		ErrorPermissionDenied,
		ErrorBudgetExceeded,
		ErrorCapabilityMismatch,
		ErrorDriverInternal,
		ErrorCancellationTimeout,
		ErrorMalformedObservation,
		ErrorArtifactMismatch,
	}
	for index, class := range classes {
		message := Message{
			JSONRPC: JSONRPCVersion,
			ID:      json.RawMessage(`1`),
			Error: &RPCError{
				Code:    -32000 - index,
				Message: "driver failure",
				Data:    &ErrorData{Class: class},
			},
		}
		encoded, err := EncodeControlFrame(message)
		if err != nil {
			t.Fatalf("class %s: %v", class, err)
		}
		decoded, err := DecodeControlFrame(encoded)
		if err != nil {
			t.Fatalf("class %s: %v", class, err)
		}
		if decoded.Error == nil || decoded.Error.Data == nil || decoded.Error.Data.Class != class {
			t.Fatalf("class %s did not round-trip", class)
		}
	}
}

func TestAllRequiredMethodsAndNotificationsRoundTrip(t *testing.T) {
	last := uint64(3)
	messages := []Message{
		requestMessage(t, MethodHello, HelloParams{CoreVersionRange: VersionRange{Minimum: "1.0.0", Maximum: "1.0.0"}}),
		requestMessage(t, MethodPrepare, PrepareParams{
			ResolvedPlanDigest: publicschema.NewDigest([]byte("plan")),
			CapabilityToken:    "ephemeral-token",
		}),
		requestMessage(t, MethodCapabilities, CapabilitiesParams{}),
		requestMessage(t, MethodInvoke, invokeParams(testInvocationOne, testAttemptOne)),
		requestMessage(t, MethodCancel, CancelParams{InvocationID: testInvocationOne, Reason: "cancel", DeadlineMillis: 1}),
		requestMessage(t, MethodReset, ResetParams{}),
		requestMessage(t, MethodShutdown, ShutdownParams{}),
		notificationMessage(t, MethodObservation, observationParams(testInvocationOne, testAttemptOne, 3)),
		notificationMessage(t, MethodCompleted, completedParams(testInvocationOne, testAttemptOne, &last)),
	}
	for _, message := range messages {
		encoded, err := EncodeControlFrame(message)
		if err != nil {
			t.Fatalf("encode %s: %v", message.Method, err)
		}
		decoded, err := DecodeControlFrame(encoded)
		if err != nil {
			t.Fatalf("decode %s: %v", message.Method, err)
		}
		if decoded.Method != message.Method {
			t.Fatalf("want %s, got %s", message.Method, decoded.Method)
		}
	}
}

func requestMessage(t *testing.T, method Method, params any) Message {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return Message{JSONRPC: JSONRPCVersion, ID: json.RawMessage(`1`), Method: method, Params: raw}
}

func notificationMessage(t *testing.T, method Method, params any) Message {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return Message{JSONRPC: JSONRPCVersion, Method: method, Params: raw}
}

func FuzzDecodeControlFrameNeverPanics(fuzz *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"driver.reset"}`),
		[]byte(`{"jsonrpc":"2.0","method":"driver.observation","params":{}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"result":null}`),
		{0xff, '\n'},
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeControlFrame(raw)
	})
}
