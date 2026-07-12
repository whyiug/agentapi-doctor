package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func TestEnvelopeThresholdAndTamperDetection(t *testing.T) {
	public1, private1 := key(t)
	public2, private2 := key(t)
	envelope, err := Sign("application/vnd.agentapi.statement+json", []byte(`{"b":2,"a":1}`), private1)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = AddSignature(envelope, private2)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := Verify(envelope, map[string]ed25519.PublicKey{KeyID(public1): public1, KeyID(public2): public2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(statement) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical payload: %s", statement)
	}
	decoded, _ := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	decoded[0] ^= 0xff
	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(decoded)
	if _, err := Verify(envelope, map[string]ed25519.PublicKey{KeyID(public1): public1, KeyID(public2): public2}, 2); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestEnvelopeRejectsDuplicateSigner(t *testing.T) {
	_, private := key(t)
	envelope, err := Sign("type", []byte(`{"ok":true}`), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddSignature(envelope, private); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestJournalRoundTripAndTamper(t *testing.T) {
	journal, err := NewJournal("018f22e2-79b0-7cc3-98c4-dc0c0c07398f")
	if err != nil {
		t.Fatal(err)
	}
	now := schema.NewUTCTime(time.Unix(100, 0))
	payload := schema.NewDigest([]byte("payload"))
	if _, err := journal.Append(EventInput{EventType: "run.planned", Status: RunPlanned, OccurredAt: now, MonotonicOffsetNS: 0, PayloadDigest: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(EventInput{EventType: "run.started", Status: RunRunning, OccurredAt: now, MonotonicOffsetNS: 1, PayloadDigest: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(EventInput{EventType: "run.completed", Status: RunCompleted, OccurredAt: now, MonotonicOffsetNS: 2, PayloadDigest: payload}); err != nil {
		t.Fatal(err)
	}
	encoded, err := journal.EncodeJSONL()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJournal(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Events()) != 3 {
		t.Fatalf("events=%d", len(decoded.Events()))
	}
	mutated := append([]byte(nil), encoded...)
	index := bytes.Index(mutated, []byte("run.started"))
	mutated[index] = 'R'
	if _, err := DecodeJournal(bytes.NewReader(mutated)); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestJournalRejectsLifecycleRewrite(t *testing.T) {
	journal, _ := NewJournal("018f22e2-79b0-7cc3-98c4-dc0c0c07398f")
	_, err := journal.Append(EventInput{EventType: "run.completed", Status: RunCompleted, OccurredAt: schema.NewUTCTime(time.Unix(1, 0)), PayloadDigest: schema.NewDigest([]byte("x"))})
	if err == nil {
		t.Fatal("expected invalid transition")
	}
}
