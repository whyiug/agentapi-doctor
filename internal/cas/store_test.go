package cas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
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

func TestStoreRejectsReplacedRootForEveryOperation(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *Store, schema.Evidence, redaction.SanitizedPayload) error
	}{
		{name: "put", run: func(ctx context.Context, store *Store, _ schema.Evidence, payload redaction.SanitizedPayload) error {
			_, err := store.Put(ctx, payload)
			return err
		}},
		{name: "get", run: func(ctx context.Context, store *Store, evidence schema.Evidence, _ redaction.SanitizedPayload) error {
			_, err := store.Get(ctx, evidence.PayloadRef.ContentDigest)
			return err
		}},
		{name: "put evidence", run: func(ctx context.Context, store *Store, evidence schema.Evidence, _ redaction.SanitizedPayload) error {
			_, err := store.PutEvidence(ctx, evidence)
			return err
		}},
		{name: "get evidence", run: func(ctx context.Context, store *Store, evidence schema.Evidence, _ redaction.SanitizedPayload) error {
			_, err := store.GetEvidence(ctx, evidence.ObjectRef)
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			store, evidence := testEvidenceStore(t)
			redactor, _ := redaction.New(nil, nil)
			payload, _ := redactor.SanitizeText([]byte("replacement-root-fixture"))
			original := store.root + ".original"
			if err := os.Rename(store.root, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(store.root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := operation.run(context.Background(), store, evidence, payload); !errors.Is(err, ErrRootReplaced) {
				t.Fatalf("operation used a replacement CAS root: %v", err)
			}
			entries, err := os.ReadDir(store.root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("operation wrote through replacement root: %v", entries)
			}
		})
	}
}

func TestReadBoundedRejectsDirectoryAndFileSymlinks(t *testing.T) {
	redactor, _ := redaction.New(nil, nil)
	payload, _ := redactor.SanitizeText([]byte("symlink-fixture"))
	data := payload.Bytes()
	digest := schema.NewDigest(data)
	zero(data)

	t.Run("directory", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "cas"), 1024)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := store.objectPath(digest)
		if err := os.Mkdir(filepath.Join(store.root, "sha256"), 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.Mkdir(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, filepath.Base(path)), []byte("symlink-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Dir(path)); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		if _, err := store.Get(context.Background(), digest); err == nil {
			t.Fatal("CAS followed a symlink shard directory")
		}
	})

	t.Run("file", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "cas"), 1024)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := store.objectPath(digest)
		if err := store.ensureDirectory(filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside-object")
		if err := os.WriteFile(outside, []byte("symlink-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Skipf("file symlink unavailable: %v", err)
		}
		if _, err := store.Get(context.Background(), digest); err == nil {
			t.Fatal("CAS followed a symlink object file")
		}
	})
}

func TestReadBoundedRejectsReplacementAndGrowthAfterLstat(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "cas"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(store.root, "fixtures")
	if err := store.ensureDirectory(directory); err != nil {
		t.Fatal(err)
	}

	t.Run("replacement", func(t *testing.T) {
		path := filepath.Join(directory, "replacement")
		if err := os.WriteFile(path, []byte("same-size"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.readBoundedAfterLstat(path, func() error {
			if err := os.Rename(path, path+".old"); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("same-size"), 0o600)
		}); err == nil {
			t.Fatal("CAS accepted an object replaced between lstat and open")
		}
	})

	for _, test := range []struct {
		name   string
		append string
	}{
		{name: "within limit", append: "x"},
		{name: "past limit", append: strings.Repeat("x", 2048)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.readBoundedAfterLstat(path, func() error {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteString(test.append); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			}); err == nil {
				t.Fatal("CAS accepted an object grown between lstat and bounded open")
			}
		})
	}
}

func TestDirectorySyncCoversCreationAndHardlinkCommits(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "cas"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	originalSync := store.syncDir
	var synced []string
	store.syncDir = func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return originalSync(path)
	}

	nested := filepath.Join(store.root, "new", "nested")
	if err := store.ensureDirectory(nested); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{store.root, filepath.Join(store.root, "new"), nested} {
		if !containsPath(synced, required) {
			t.Fatalf("new directory path was not synced: required=%q calls=%v", required, synced)
		}
	}

	synced = nil
	redactor, _ := redaction.New(nil, nil)
	payload, _ := redactor.SanitizeText([]byte("fsync-payload"))
	ref, err := store.Put(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	objectPath, _ := store.objectPath(ref.ContentDigest)
	if len(synced) == 0 || synced[len(synced)-1] != filepath.Dir(objectPath) {
		t.Fatalf("payload hardlink parent was not synced last: calls=%v", synced)
	}

	store, evidence := testEvidenceStore(t)
	originalSync = store.syncDir
	synced = nil
	store.syncDir = func(path string) error {
		synced = append(synced, filepath.Clean(path))
		return originalSync(path)
	}
	if _, err := store.PutEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	refPath, _ := store.evidenceRefPath(evidence.ObjectRef)
	if len(synced) == 0 || synced[len(synced)-1] != filepath.Dir(refPath) {
		t.Fatalf("Evidence hardlink parent was not synced last: calls=%v", synced)
	}
}

func TestPlatformDirectorySync(t *testing.T) {
	directory := t.TempDir()
	if err := syncDirectoryPlatform(directory); err != nil {
		t.Fatalf("sync temporary directory: %v", err)
	}
}

func TestEvidenceEnvelopeRoundTripKeepsProjectionAndStorageDigestsDistinct(t *testing.T) {
	store, evidence := testEvidenceStore(t)

	ref, err := store.PutEvidence(context.Background(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if ref != evidence.ObjectRef {
		t.Fatalf("persisted ref = %#v, want %#v", ref, evidence.ObjectRef)
	}
	if second, err := store.PutEvidence(context.Background(), evidence); err != nil || second != ref {
		t.Fatalf("idempotent Evidence put = %#v, %v", second, err)
	}

	loaded, err := store.GetEvidence(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, evidence) {
		t.Fatalf("loaded Evidence differs:\n%#v\n%#v", loaded, evidence)
	}
	payload, err := store.Get(context.Background(), loaded.PayloadRef.ContentDigest)
	if err != nil {
		t.Fatalf("resolve Evidence payload: %v", err)
	}
	if string(payload) != "synthetic sanitized payload" {
		t.Fatalf("resolved payload = %q", payload)
	}

	encoded, err := schema.CanonicalMarshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	envelopeDigest := schema.NewDigest(encoded)
	if envelopeDigest == ref.ContentDigest {
		t.Fatal("full-envelope storage digest was confused with the projection ObjectRef digest")
	}
	refPath, err := store.evidenceRefPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	envelopePath, err := store.evidenceEnvelopePath(envelopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if refPath == envelopePath || strings.Contains(refPath, filepath.Join(store.root, "sha256")) {
		t.Fatalf("Evidence and Payload namespaces overlap: %q / %q", refPath, envelopePath)
	}
	for _, path := range []string{refPath, envelopePath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("Evidence storage path is not a regular non-symlink file: %q (%v, %v)", path, info, err)
		}
	}
}

func TestEvidenceRelationsRequireResolvableTargetsAndRemainReadable(t *testing.T) {
	t.Run("dangling targets", func(t *testing.T) {
		store, evidence := testEvidenceStore(t)
		missingPayload := schema.ObjectRef{Kind: "Payload", ContentDigest: schema.NewDigest([]byte("missing-related-payload"))}
		withMissingPayload := evidence
		withMissingPayload.Sequence = 2
		withMissingPayload.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: missingPayload}}
		withMissingPayload = resealEvidence(t, withMissingPayload)
		if _, err := store.PutEvidence(context.Background(), withMissingPayload); err == nil || !strings.Contains(err.Error(), "unresolved relation") {
			t.Fatalf("dangling Payload relation was accepted: %v", err)
		}

		missingEvidence := schema.ObjectRef{Kind: "Evidence", ContentDigest: schema.NewDigest([]byte("missing-related-evidence"))}
		withMissingEvidence := evidence
		withMissingEvidence.Sequence = 3
		withMissingEvidence.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: missingEvidence}}
		withMissingEvidence = resealEvidence(t, withMissingEvidence)
		if _, err := store.PutEvidence(context.Background(), withMissingEvidence); err == nil || !strings.Contains(err.Error(), "unresolved relation") {
			t.Fatalf("dangling Evidence relation was accepted: %v", err)
		}
	})

	t.Run("payload and Evidence targets", func(t *testing.T) {
		store, target := testEvidenceStore(t)
		if _, err := store.PutEvidence(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		payloadRelated := target
		payloadRelated.Sequence = 2
		payloadRelated.EvidenceKind = "payload_relation"
		payloadRelated.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: *target.PayloadRef}}
		payloadRelated = resealEvidence(t, payloadRelated)
		if _, err := store.PutEvidence(context.Background(), payloadRelated); err != nil {
			t.Fatalf("existing Payload relation was rejected: %v", err)
		}

		evidenceRelated := target
		evidenceRelated.Sequence = 3
		evidenceRelated.EvidenceKind = "evidence_relation"
		evidenceRelated.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: target.ObjectRef}}
		evidenceRelated = resealEvidence(t, evidenceRelated)
		if _, err := store.PutEvidence(context.Background(), evidenceRelated); err != nil {
			t.Fatalf("existing Evidence relation was rejected: %v", err)
		}
		if _, err := store.GetEvidence(context.Background(), evidenceRelated.ObjectRef); err != nil {
			t.Fatalf("valid relation graph was not readable: %v", err)
		}

		targetPath, _ := store.evidenceRefPath(target.ObjectRef)
		if err := os.WriteFile(targetPath, []byte("corrupted-related-evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetEvidence(context.Background(), evidenceRelated.ObjectRef); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("Evidence with a corrupt relation target remained readable: %v", err)
		}
	})
}

func TestEvidenceRelationTraversalRejectsCycleAndExcessiveDepth(t *testing.T) {
	store, evidence := testEvidenceStore(t)
	evidence.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: evidence.ObjectRef}}

	cycle := newEvidenceTraversal()
	cycle.visiting[evidence.ObjectRef] = struct{}{}
	if err := store.resolveEvidenceRelations(context.Background(), evidence, cycle, 0); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("relation cycle guard did not fire: %v", err)
	}

	if err := store.resolveEvidenceRelations(context.Background(), evidence, newEvidenceTraversal(), maxEvidenceRelationDepth); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("relation depth guard did not fire: %v", err)
	}

	store, leaf := testEvidenceStore(t)
	installEvidenceBytes(t, store, leaf.ObjectRef, mustCanonicalEvidence(t, leaf))
	target := leaf.ObjectRef
	var root schema.Evidence
	for depth := 1; depth <= maxEvidenceRelationDepth+1; depth++ {
		root = leaf
		root.Sequence = uint64(depth + 1)
		root.Relations = []schema.EvidenceRelation{{Relation: "derived_from", Target: target}}
		root = resealEvidence(t, root)
		installEvidenceBytes(t, store, root.ObjectRef, mustCanonicalEvidence(t, root))
		target = root.ObjectRef
	}
	if _, err := store.GetEvidence(context.Background(), root.ObjectRef); !errors.Is(err, ErrCorruptObject) || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("over-depth on-disk Evidence graph remained readable: %v", err)
	}
}

func TestEvidenceEnvelopeRejectsProjectionDriftAndIdentityConflict(t *testing.T) {
	store, evidence := testEvidenceStore(t)
	if _, err := store.PutEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}

	projectionDrift := evidence
	projectionDrift.EvidenceKind = "different_kind"
	if _, err := store.PutEvidence(context.Background(), projectionDrift); err == nil || !strings.Contains(err.Error(), "projection digest") {
		t.Fatalf("expected projection digest rejection, got %v", err)
	}

	metadataConflict := evidence
	metadataConflict.CreatedAt = schema.NewUTCTime(time.Unix(2, 0).UTC())
	if _, err := store.PutEvidence(context.Background(), metadataConflict); err == nil || !strings.Contains(err.Error(), "projection digest") {
		t.Fatalf("expected metadata projection rejection, got %v", err)
	}
	loaded, err := store.GetEvidence(context.Background(), evidence.ObjectRef)
	if err != nil || !reflect.DeepEqual(loaded, evidence) {
		t.Fatalf("conflicting put changed stored Evidence: %#v, %v", loaded, err)
	}
}

func TestEvidenceObjectRefBindsSchemaProducerAndCreationTime(t *testing.T) {
	_, evidence := testEvidenceStore(t)
	otherProducer := evidence.Producer
	otherProducer.Version = "2.0.0"
	producerMeta, err := SealEvidenceMeta(otherProducer, evidence.CreatedAt, evidence)
	if err != nil {
		t.Fatal(err)
	}
	timeMeta, err := SealEvidenceMeta(evidence.Producer, schema.NewUTCTime(time.Unix(2, 0).UTC()), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if producerMeta.ObjectRef == evidence.ObjectRef || timeMeta.ObjectRef == evidence.ObjectRef || producerMeta.ObjectRef == timeMeta.ObjectRef {
		t.Fatal("Evidence ObjectRef did not bind producer and creation time")
	}
	if producerMeta.SchemaVersion != EvidenceSchemaVersion {
		t.Fatalf("sealed schema = %q", producerMeta.SchemaVersion)
	}
}

func TestEvidencePersistenceRequiresResolvablePayload(t *testing.T) {
	store, evidence := testEvidenceStore(t)
	missing := schema.NewDigest([]byte("missing payload"))
	missingRef := schema.ObjectRef{Kind: "Payload", ContentDigest: missing}
	evidence.PayloadRef, evidence.PayloadDigest = &missingRef, &missing
	meta, err := SealEvidenceMeta(evidence.Producer, evidence.CreatedAt, evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EnvelopeMeta, evidence.EvidenceID = meta, meta.ContentDigest
	if _, err := store.PutEvidence(context.Background(), evidence); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling payload was accepted: %v", err)
	}

	store, evidence = testEvidenceStore(t)
	if _, err := store.PutEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	payloadPath, err := store.objectPath(evidence.PayloadRef.ContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(payloadPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEvidence(context.Background(), evidence.ObjectRef); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Evidence with removed payload remained readable: %v", err)
	}
}

func TestGetEvidenceDetectsTamperAndSymlink(t *testing.T) {
	t.Run("full envelope metadata tamper", func(t *testing.T) {
		store, evidence := testEvidenceStore(t)
		if _, err := store.PutEvidence(context.Background(), evidence); err != nil {
			t.Fatal(err)
		}
		path, _ := store.evidenceRefPath(evidence.ObjectRef)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var tampered schema.Evidence
		if err := json.Unmarshal(raw, &tampered); err != nil {
			t.Fatal(err)
		}
		tampered.Producer.Version = "tampered"
		raw, err = schema.CanonicalMarshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetEvidence(context.Background(), evidence.ObjectRef); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("expected full-envelope tamper rejection, got %v", err)
		}
	})

	t.Run("reference symlink", func(t *testing.T) {
		store, evidence := testEvidenceStore(t)
		if _, err := store.PutEvidence(context.Background(), evidence); err != nil {
			t.Fatal(err)
		}
		path, _ := store.evidenceRefPath(evidence.ObjectRef)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		target, _ := store.evidenceEnvelopePath(schema.NewDigest(raw))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := store.GetEvidence(context.Background(), evidence.ObjectRef); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("expected symlink rejection, got %v", err)
		}
	})
}

func TestGetEvidenceRequiresCanonicalStrictJSON(t *testing.T) {
	tests := map[string]func(t *testing.T, canonical []byte) []byte{
		"noncanonical": func(t *testing.T, canonical []byte) []byte {
			t.Helper()
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, canonical, "", "  "); err != nil {
				t.Fatal(err)
			}
			return pretty.Bytes()
		},
		"unknown field": func(t *testing.T, canonical []byte) []byte {
			t.Helper()
			var value map[string]any
			decoder := json.NewDecoder(bytes.NewReader(canonical))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			value["unexpected"] = true
			mutated, err := schema.CanonicalMarshal(value)
			if err != nil {
				t.Fatal(err)
			}
			return mutated
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store, evidence := testEvidenceStore(t)
			canonical, err := schema.CanonicalMarshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			installEvidenceBytes(t, store, evidence.ObjectRef, mutate(t, canonical))
			if _, err := store.GetEvidence(context.Background(), evidence.ObjectRef); !errors.Is(err, ErrCorruptObject) {
				t.Fatalf("expected strict canonical JSON rejection, got %v", err)
			}
		})
	}
}

func testEvidenceStore(t *testing.T) (*Store, schema.Evidence) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "cas"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	redactor, err := redaction.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := redactor.SanitizeText([]byte("synthetic sanitized payload"))
	if err != nil {
		t.Fatal(err)
	}
	payloadRef, err := store.Put(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := payloadRef.ContentDigest
	evidence := schema.Evidence{
		RunID:               evidenceTestID('1'),
		InvocationID:        evidenceTestID('2'),
		AttemptID:           evidenceTestID('3'),
		Sequence:            1,
		CaptureLayer:        schema.LayerUpstreamApplication,
		InstrumentationMode: schema.InstrumentationFixture,
		Direction:           schema.DirectionTargetToCore,
		EvidenceKind:        "synthetic_fixture",
		MonotonicOffsetNS:   1,
		PayloadRef:          &payloadRef,
		PayloadDigest:       &payloadDigest,
		Redactions:          []schema.RedactionRecord{},
	}
	producer := schema.Producer{Name: "cas-test", Version: "1.0.0", ArtifactDigest: schema.NewDigest([]byte("cas-test"))}
	createdAt := schema.NewUTCTime(time.Unix(1, 0).UTC())
	meta, err := SealEvidenceMeta(producer, createdAt, evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EnvelopeMeta = meta
	evidence.EvidenceID = meta.ContentDigest
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
	return store, evidence
}

func installEvidenceBytes(t *testing.T, store *Store, ref schema.ObjectRef, raw []byte) {
	t.Helper()
	refPath, err := store.evidenceRefPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	envelopePath, err := store.evidenceEnvelopePath(schema.NewDigest(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{refPath, envelopePath} {
		if err := store.ensureDirectory(filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func evidenceTestID(last byte) schema.InstanceID {
	return schema.InstanceID("00000000-0000-7000-8000-00000000000" + string(last))
}

func resealEvidence(t *testing.T, evidence schema.Evidence) schema.Evidence {
	t.Helper()
	meta, err := SealEvidenceMeta(evidence.Producer, evidence.CreatedAt, evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.EnvelopeMeta = meta
	evidence.EvidenceID = meta.ContentDigest
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func mustCanonicalEvidence(t *testing.T, evidence schema.Evidence) []byte {
	t.Helper()
	raw, err := schema.CanonicalMarshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func containsPath(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, path := range paths {
		if filepath.Clean(path) == want {
			return true
		}
	}
	return false
}
