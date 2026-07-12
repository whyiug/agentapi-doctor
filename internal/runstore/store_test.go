package runstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const runID schema.InstanceID = "018f22e2-79b0-7cc3-98c4-dc0c0c07398f"

func TestPutGetLatestAndList(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"a":1,"z":true}`)
	if _, err := store.Put(runID, bundle); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("latest", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.RunID != runID || !bytes.Equal(record.Bundle, bundle) {
		t.Fatalf("record=%#v", record)
	}
	if _, err := store.Get("latest", false); !errors.Is(err, ErrLatestForbidden) {
		t.Fatalf("expected CI guard, got %v", err)
	}
	ids, err := store.List()
	if err != nil || len(ids) != 1 || ids[0] != runID {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestPutRequiresCanonicalStrictJSONAndIsImmutable(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "runs"), 0)
	for _, raw := range [][]byte{[]byte(`{"z":1,"a":2}`), []byte(`{"a":1,"a":2}`), []byte(`{} trailing`)} {
		if _, err := store.Put(runID, raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if _, err := store.Put(runID, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(runID, []byte(`{"a":2}`)); !errors.Is(err, ErrExists) {
		t.Fatalf("expected immutable collision, got %v", err)
	}
}

func TestTamperAndSymlinkFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	store, _ := Open(root, 0)
	if _, err := store.Put(runID, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, string(runID), "record.json")
	raw, _ := os.ReadFile(path)
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(string(runID), false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected corruption, got %v", err)
	}
	otherRoot := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(root, otherRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(otherRoot, 0); err == nil {
		t.Fatal("accepted symlink root")
	}
}

func TestConcurrentSameRunOnlyOneCommit(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "runs"), 0)
	var wait sync.WaitGroup
	success, exists := 0, 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Put(runID, []byte(`{"a":1}`))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
			} else if errors.Is(err, ErrExists) {
				exists++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wait.Wait()
	if success != 1 || exists != 7 {
		t.Fatalf("success=%d exists=%d", success, exists)
	}
}
