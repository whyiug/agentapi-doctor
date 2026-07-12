package cas

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
)

func TestStoreAcceptsOnlySanitizedPayloadAndDetectsTamper(t *testing.T) {
	redactor, err := redaction.New(nil, [][]byte{[]byte("CANARY-DO-NOT-PERSIST")})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := redactor.SanitizeJSON([]byte(`{"authorization":"Bearer abcdefghijklmnop","value":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "cas"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.Put(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(context.Background(), ref.ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abcdefghijklmnop") || !strings.Contains(string(data), redaction.Replacement) {
		t.Fatalf("unsafe persisted data: %s", data)
	}
	path, err := store.objectPath(ref.ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), ref.ContentDigest); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("expected corruption, got %v", err)
	}
}

func TestPutIsIdempotent(t *testing.T) {
	redactor, _ := redaction.New(nil, nil)
	payload, _ := redactor.SanitizeText([]byte("synthetic fixture"))
	store, err := Open(filepath.Join(t.TempDir(), "cas"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Put(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotent put changed ref: %#v %#v", first, second)
	}
}
