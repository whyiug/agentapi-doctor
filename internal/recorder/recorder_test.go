package recorder

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestRecordRedactsBeforeCASCommit(t *testing.T) {
	canary := []byte("synthetic-canary-value")
	redactorInstance, err := redaction.New(nil, [][]byte{canary})
	if err != nil {
		t.Fatal(err)
	}
	store, err := cas.Open(filepath.Join(t.TempDir(), "cas"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	recorderInstance, err := New(testConfig(schema.LayerUpstreamApplication, schema.InstrumentationFixture), redactorInstance, store)
	if err != nil {
		t.Fatal(err)
	}
	offset := int64(0)
	evidence, err := recorderInstance.Record(context.Background(), Observation{
		Sequence:            1,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationFixture,
		Direction:           schema.DirectionTargetToCore,
		Kind:                "sse_logical_event",
		MonotonicOffsetNS:   10,
		EventOffset:         &offset,
		Payload:             []byte(`{"authorization":"Bearer synthetic-secret-value","data":"synthetic-canary-value"}`),
		Format:              PayloadJSON,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Redactions) == 0 {
		t.Fatal("expected redaction records")
	}
	persisted, err := store.Get(context.Background(), *evidence.PayloadDigest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, canary) || bytes.Contains(persisted, []byte("synthetic-secret-value")) {
		t.Fatalf("secret reached CAS: %s", persisted)
	}
	if !bytes.Contains(persisted, []byte(redaction.Replacement)) {
		t.Fatalf("redaction marker missing: %s", persisted)
	}
}

func TestRecorderRejectsCaptureLayerImpersonationWithoutAdvancingSequence(t *testing.T) {
	recorderInstance := newTestRecorder(t, schema.LayerUpstreamApplication, schema.InstrumentationDirect)
	observation := testObservation()
	observation.CaptureLayer = schema.LayerProxyForwarded
	if _, err := recorderInstance.Record(context.Background(), observation); err == nil || !strings.Contains(err.Error(), "impersonate") {
		t.Fatalf("expected capture-layer rejection, got %v", err)
	}
	observation.CaptureLayer = schema.LayerUpstreamApplication
	if _, err := recorderInstance.Record(context.Background(), observation); err != nil {
		t.Fatalf("failed observation must not consume sequence: %v", err)
	}
}

func TestRecorderRejectsSanitizedLayerAsSource(t *testing.T) {
	redactorInstance, _ := redaction.New(nil, nil)
	store, _ := cas.Open(filepath.Join(t.TempDir(), "cas"), 1<<20)
	_, err := New(testConfig(schema.LayerSanitizedPersisted, schema.InstrumentationDirect), redactorInstance, store)
	if err == nil {
		t.Fatal("sanitized persisted layer must not impersonate a source observation")
	}
}

func TestRecorderBoundsPayloadAndCopiesOffsets(t *testing.T) {
	recorderInstance := newTestRecorder(t, schema.LayerUpstreamApplication, schema.InstrumentationDirect)
	recorderInstance.config.MaxObservationBytes = 8
	tooLarge := testObservation()
	tooLarge.Payload = []byte("123456789")
	if _, err := recorderInstance.Record(context.Background(), tooLarge); err == nil {
		t.Fatal("oversized in-memory observation must fail before persistence")
	}

	recorderInstance.config.MaxObservationBytes = 64
	offset := int64(7)
	valid := testObservation()
	valid.ByteOffset = &offset
	evidence, err := recorderInstance.Record(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	offset = 99
	if evidence.ByteOffset == nil || *evidence.ByteOffset != 7 {
		t.Fatalf("caller mutated sealed evidence offset: %#v", evidence.ByteOffset)
	}
}

func TestSSELogicalEventsAreIndependentOfReadChunkBoundaries(t *testing.T) {
	stream := []byte("event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: one\ndata: two\n\n")
	one := NewSSEAssembler(4096)
	oneEvents, err := one.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: stream})
	if err != nil {
		t.Fatal(err)
	}
	two := NewSSEAssembler(4096)
	var twoEvents []SSELogicalEvent
	offset := 0
	for index, part := range [][]byte{stream[:7], stream[7:31], stream[31:62], stream[62:]} {
		events, feedErr := two.Feed(ReadChunk{Sequence: uint64(index + 1), ByteOffset: int64(offset), Data: part})
		if feedErr != nil {
			t.Fatal(feedErr)
		}
		twoEvents = append(twoEvents, events...)
		offset += len(part)
	}
	if len(oneEvents) != 2 || len(twoEvents) != 2 {
		t.Fatalf("unexpected logical event counts: %d and %d", len(oneEvents), len(twoEvents))
	}
	for index := range oneEvents {
		left, right := oneEvents[index], twoEvents[index]
		left.SourceChunkSequences = nil
		right.SourceChunkSequences = nil
		if !reflect.DeepEqual(left, right) {
			t.Fatalf("logical event changed after rechunking:\n%#v\n%#v", left, right)
		}
	}
	if reflect.DeepEqual(oneEvents[0].SourceChunkSequences, twoEvents[0].SourceChunkSequences) {
		t.Fatal("read chunk provenance should preserve different boundaries")
	}
	if oneEvents[1].Data != "one\ntwo" {
		t.Fatalf("data lines not joined: %q", oneEvents[1].Data)
	}
}

func TestSSEEverySingleSplitPreservesLogicalEvents(t *testing.T) {
	stream := []byte("event: response.created\r\ndata: one\r\n\r\nevent: response.completed\r\ndata: two\r\n\r\n")
	baselineAssembler := NewSSEAssembler(4096)
	baseline, err := baselineAssembler.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: stream})
	if err != nil {
		t.Fatal(err)
	}
	for split := 1; split < len(stream); split++ {
		assembler := NewSSEAssembler(4096)
		first, feedErr := assembler.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: stream[:split]})
		if feedErr != nil {
			t.Fatalf("split %d first chunk: %v", split, feedErr)
		}
		second, feedErr := assembler.Feed(ReadChunk{Sequence: 2, ByteOffset: int64(split), Data: stream[split:]})
		if feedErr != nil {
			t.Fatalf("split %d second chunk: %v", split, feedErr)
		}
		actual := append(first, second...)
		if len(actual) != len(baseline) {
			t.Fatalf("split %d emitted %d events, want %d", split, len(actual), len(baseline))
		}
		for index := range actual {
			left, right := baseline[index], actual[index]
			left.SourceChunkSequences = nil
			right.SourceChunkSequences = nil
			if !reflect.DeepEqual(left, right) {
				t.Fatalf("split %d changed event %d: %#v != %#v", split, index, left, right)
			}
		}
	}
}

func TestSSEFinishDoesNotInventLogicalEvent(t *testing.T) {
	assembler := NewSSEAssembler(1024)
	events, err := assembler.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: []byte("data: incomplete")})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatal("partial transport read became a logical event")
	}
	tail := assembler.Finish()
	if tail.BufferedBytes == 0 || len(tail.SourceChunkSequences) != 1 {
		t.Fatalf("incomplete tail not preserved: %#v", tail)
	}
}

func TestSSELogicalEventHasIndependentBound(t *testing.T) {
	assembler := NewSSEAssembler(16)
	first := []byte("data: 1234\n")
	if _, err := assembler.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: first}); err != nil {
		t.Fatal(err)
	}
	_, err := assembler.Feed(ReadChunk{Sequence: 2, ByteOffset: int64(len(first)), Data: []byte("data: 5678\n")})
	if err == nil || !strings.Contains(err.Error(), "logical event") {
		t.Fatalf("expected logical-event bound, got %v", err)
	}
}

func FuzzSSEAssemblerNeverPanicsOrInventsSequence(fuzz *testing.F) {
	fuzz.Add([]byte("event: response.created\ndata: {\"type\":\"response.created\"}\n\n"))
	fuzz.Add([]byte("data: [DONE]\n\n"))
	fuzz.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > 64<<10 {
			t.Skip()
		}
		assembler := NewSSEAssembler(64 << 10)
		events, err := assembler.Feed(ReadChunk{Sequence: 1, ByteOffset: 0, Data: input})
		if err != nil {
			return
		}
		for index, event := range events {
			if event.Sequence != uint64(index+1) || event.EventOffset < 0 {
				t.Fatalf("invalid event identity: %#v", event)
			}
		}
		tail := assembler.Finish()
		if tail.BufferedBytes < 0 || tail.BufferedBytes > len(input) || tail.PendingFieldCount < 0 {
			t.Fatalf("invalid bounded tail: %#v", tail)
		}
	})
}

func newTestRecorder(t *testing.T, layer schema.CaptureLayer, mode schema.InstrumentationMode) *Recorder {
	t.Helper()
	redactorInstance, err := redaction.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cas.Open(filepath.Join(t.TempDir(), "cas"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	recorderInstance, err := New(testConfig(layer, mode), redactorInstance, store)
	if err != nil {
		t.Fatal(err)
	}
	return recorderInstance
}

func testConfig(layer schema.CaptureLayer, mode schema.InstrumentationMode) Config {
	return Config{
		RunID:               testID('1'),
		InvocationID:        testID('2'),
		AttemptID:           testID('3'),
		Producer:            schema.Producer{Name: "recorder", Version: "0.1.0", ArtifactDigest: schema.NewDigest([]byte("recorder"))},
		CaptureLayer:        layer,
		InstrumentationMode: mode,
		Now:                 func() time.Time { return time.Unix(0, 0).UTC() },
	}
}

func testObservation() Observation {
	return Observation{
		Sequence:            1,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationDirect,
		Direction:           schema.DirectionTargetToCore,
		Kind:                "transport_read_chunk",
		MonotonicOffsetNS:   1,
		Payload:             []byte("synthetic fixture"),
		Format:              PayloadText,
	}
}

func testID(last byte) schema.InstanceID {
	return schema.InstanceID("00000000-0000-7000-8000-00000000000" + string(last))
}
