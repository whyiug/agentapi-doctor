package runstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const runID schema.InstanceID = "018f22e2-79b0-7cc3-98c4-dc0c0c07398f"

var canonicalPlan = []byte(`{"plan":1,"target":{"baseURL":"http://127.0.0.1:8090/v1"}}`)

func TestPutGetLatestAndList(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"a":1,"z":true}`)
	if _, err := store.Put(runID, Payload{Bundle: bundle, Plan: canonicalPlan}); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("latest", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != RecordSchema || record.RunID != runID || !bytes.Equal(record.Bundle, bundle) || !bytes.Equal(record.Plan, canonicalPlan) || record.PlanDigest != schema.NewDigest(canonicalPlan) {
		t.Fatalf("record=%#v", record)
	}
	if _, err := store.Get("latest", false); !errors.Is(err, ErrLatestForbidden) {
		t.Fatalf("expected latest guard, got %v", err)
	} else if err.Error() != "latest run reference requires explicit --allow-latest" {
		t.Fatalf("latest error is not actionable: %v", err)
	}
	ids, err := store.List()
	if err != nil || len(ids) != 1 || ids[0] != runID {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestPutRequiresCanonicalStrictJSONAndIsImmutable(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "runs"), 0)
	for _, raw := range [][]byte{[]byte(`{"z":1,"a":2}`), []byte(`{"a":1,"a":2}`), []byte(`{} trailing`)} {
		if _, err := store.Put(runID, Payload{Bundle: raw, Plan: canonicalPlan}); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, raw := range [][]byte{[]byte(`{"z":1,"a":2}`), []byte(`{"a":1,"a":2}`), []byte(`{} trailing`), nil} {
		if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: raw}); err == nil {
			t.Fatalf("accepted plan %q", raw)
		}
	}
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":2}`), Plan: canonicalPlan}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected immutable collision, got %v", err)
	}
	blockedRoot := filepath.Join(t.TempDir(), "runs")
	blocked, _ := Open(blockedRoot, 0)
	if err := os.Mkdir(filepath.Join(blockedRoot, string(runID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); !errors.Is(err, ErrExists) {
		t.Fatalf("existing empty run directory was replaced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(blockedRoot, string(runID), "record.json")); !os.IsNotExist(err) {
		t.Fatalf("record was written into an existing directory: %v", err)
	}
}

func TestTamperAndSymlinkFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	store, _ := Open(root, 0)
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); err != nil {
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

func TestStoreRejectsReplacedRootForEveryOperation(t *testing.T) {
	operations := []struct {
		name string
		run  func(*Store) error
	}{
		{name: "put", run: func(store *Store) error {
			_, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan})
			return err
		}},
		{name: "resolve", run: func(store *Store) error {
			_, err := store.Resolve(string(runID), false)
			return err
		}},
		{name: "get", run: func(store *Store) error {
			_, err := store.Get(string(runID), false)
			return err
		}},
		{name: "list", run: func(store *Store) error {
			_, err := store.List()
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "runs")
			store, err := Open(root, 0)
			if err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(parent, "original-runs")
			if err := os.Rename(root, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := operation.run(store); !errors.Is(err, ErrRootReplaced) {
				t.Fatalf("operation used a replacement root: %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("operation wrote through replacement root: %v", entries)
			}
		})
	}
}

func TestGetRejectsSymlinkRunDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "runs")
	store, err := Open(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "record.json"), []byte(`{"outside":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, string(runID))); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	if _, err := store.Get(string(runID), false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink run directory was followed: %v", err)
	}
}

func TestGetRejectsSymlinkRecordFile(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "runs")
	store, err := Open(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, string(runID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside-record.json")
	if err := os.WriteFile(outside, []byte(`{"outside":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "record.json")); err != nil {
		t.Skipf("file symlink unavailable: %v", err)
	}
	if _, err := store.Get(string(runID), false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink record file was followed: %v", err)
	}
}

func TestReadRegularRejectsReplacementAndGrowthAfterLstat(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "record.json")
		if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRegularAfterLstat(path, 1<<20, func() error {
			if err := os.Rename(path, path+".replaced"); err != nil {
				return err
			}
			return os.WriteFile(path, []byte(`{"b":2}`), 0o600)
		}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("replacement between lstat and open was accepted: %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		append string
		limit  int64
	}{
		{name: "within limit", append: "x", limit: 1 << 20},
		{name: "past limit", append: strings.Repeat("x", 32), limit: 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "record.json")
			if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRegularAfterLstat(path, test.limit, func() error {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteString(test.append); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("growth between lstat and bounded open was accepted: %v", err)
			}
		})
	}
}

func TestPlanTamperFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	store, _ := Open(root, 0)
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, string(runID), "record.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record Record
	if err := strictDecode(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Plan = []byte(`{"plan":2,"target":{"baseURL":"http://127.0.0.1:8090/v1"}}`)
	tampered, err := schema.CanonicalMarshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(string(runID), false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("plan digest tamper was accepted: %v", err)
	}
}

func TestGetReadsLegacyRecordAndLatestPointerWithoutInventingPlan(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	store, err := Open(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"legacy":true}`)
	legacy := recordV1{
		SchemaVersion: legacyRecordSchema,
		RunID:         runID,
		BundleDigest:  schema.NewDigest(bundle),
		Bundle:        bundle,
	}
	legacyBytes, err := schema.CanonicalMarshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, string(runID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "record.json"), legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pointerBytes, err := schema.CanonicalMarshal(latestPointer{
		SchemaVersion: legacyRecordSchema + ":latest",
		RunID:         runID,
		RecordDigest:  schema.NewDigest(legacyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "latest.json"), pointerBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	record, err := store.Get("latest", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != legacyRecordSchema || record.PlanDigest != "" || len(record.Plan) != 0 || !bytes.Equal(record.Bundle, bundle) {
		t.Fatalf("legacy record was not preserved: %#v", record)
	}
	direct, err := store.Get(string(runID), false)
	if err != nil || direct.SchemaVersion != legacyRecordSchema || len(direct.Plan) != 0 {
		t.Fatalf("direct legacy read failed: record=%#v err=%v", direct, err)
	}
}

func TestLegacyRecordRejectsV2PlanFields(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	store, err := Open(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"legacy":true}`)
	tampered := struct {
		recordV1
		Plan any `json:"plan"`
	}{
		recordV1: recordV1{
			SchemaVersion: legacyRecordSchema,
			RunID:         runID,
			BundleDigest:  schema.NewDigest(bundle),
			Bundle:        bundle,
		},
		Plan: map[string]bool{"invented": true},
	}
	raw, err := schema.CanonicalMarshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, string(runID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "record.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(string(runID), false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("legacy record accepted a v2 plan field: %v", err)
	}
}

func TestConcurrentStoresSameRunOnlyOneCommit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	stores := make([]*Store, 8)
	for index := range stores {
		stores[index], _ = Open(root, 0)
	}
	var wait sync.WaitGroup
	success, exists := 0, 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		store := stores[i]
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan})
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
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".run-") {
			t.Fatalf("temporary run directory remained visible after commit: %s", entry.Name())
		}
	}
}

func TestPutRejectsCombinedRecordOverLimit(t *testing.T) {
	bundle := []byte(`{"bundle":"small"}`)
	plan := []byte(`{"plan":"small"}`)
	wire, err := schema.CanonicalMarshal(recordV2{
		SchemaVersion: RecordSchema,
		RunID:         runID,
		BundleDigest:  schema.NewDigest(bundle),
		Bundle:        bundle,
		PlanDigest:    schema.NewDigest(plan),
		Plan:          plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(wire) - 1)
	if int64(len(bundle)) >= limit || int64(len(plan)) >= limit {
		t.Fatal("fixture does not isolate the combined record limit")
	}
	store, err := Open(filepath.Join(t.TempDir(), "runs"), limit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(runID, Payload{Bundle: bundle, Plan: plan}); err == nil || !strings.Contains(err.Error(), "run record size") {
		t.Fatalf("combined oversized record was accepted: %v", err)
	}
}

func TestPutSyncsRunDirectoryAndLatestRenameParentsInOrder(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	originalSync := store.syncDir
	var synced []string
	store.syncDir = func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return originalSync(path)
	}
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 3 || filepath.Dir(synced[0]) != store.root || !strings.HasPrefix(filepath.Base(synced[0]), ".run-") || synced[1] != store.root || synced[2] != store.root {
		t.Fatalf("directory fsync order = %v, want [temporary-run-directory root root]", synced)
	}
}

func TestTemporaryDirectorySyncFailurePreventsRunPublication(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("synthetic temporary directory sync failure")
	store.syncDir = func(path string) error {
		if filepath.Clean(path) != store.root {
			return syncFailure
		}
		return nil
	}
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); !errors.Is(err, syncFailure) {
		t.Fatalf("temporary directory sync failure was hidden: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, string(runID))); !os.IsNotExist(err) {
		t.Fatalf("run was published before its directory entry was synced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "latest.json")); !os.IsNotExist(err) {
		t.Fatalf("latest was published after temporary directory sync failure: %v", err)
	}
}

func TestTemporaryDirectorySyncRejectsReplacement(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := os.MkdirTemp(store.root, ".run-")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if !pinFileIdentity(identity) {
		t.Fatal("temporary directory identity is unavailable")
	}
	if err := os.Rename(temporary, temporary+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(temporary, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	store.syncDir = func(string) error {
		called = true
		return nil
	}
	if err := store.syncTemporaryDirectory(temporary, identity); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("replacement temporary directory was accepted: %v", err)
	}
	if called {
		t.Fatal("replacement temporary directory reached the platform sync helper")
	}
}

func TestRunDirectorySyncFailurePreventsLatestPublication(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("synthetic directory sync failure")
	store.syncDir = func(path string) error {
		if filepath.Clean(path) == store.root {
			return syncFailure
		}
		return syncDirectoryPlatform(path)
	}
	if _, err := store.Put(runID, Payload{Bundle: []byte(`{"a":1}`), Plan: canonicalPlan}); !errors.Is(err, syncFailure) {
		t.Fatalf("directory sync failure was hidden: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, string(runID), "record.json")); err != nil {
		t.Fatalf("atomically renamed run record is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "latest.json")); !os.IsNotExist(err) {
		t.Fatalf("latest was published before run directory fsync: %v", err)
	}
}

func TestPlatformDirectorySync(t *testing.T) {
	if err := syncDirectoryPlatform(t.TempDir()); err != nil {
		t.Fatalf("sync temporary directory: %v", err)
	}
}
