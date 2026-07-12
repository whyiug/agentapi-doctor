package store

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

func storeObject(t *testing.T, value any) registryapi.CanonicalObject {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	object, err := registryapi.ParseCanonicalObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func storeObservation(t *testing.T, version string) registryapi.Observation {
	t.Helper()
	observation, err := registryapi.NewObservation(registryapi.ObservationProjection{
		SchemaVersion: registryapi.ObservationSchemaV1,
		Subject:       storeObject(t, map[string]string{"project": "synthetic/runtime", "version": version}),
		Test: storeObject(t, map[string]string{
			"pack": "responses", "pack_version": "2026.07.0", "profile": "synthetic.profile",
		}),
		Environment:    storeObject(t, map[string]string{"os": "synthetic-local", "arch": "amd64"}),
		Result:         storeObject(t, map[string]string{"profile_outcome": "inconclusive"}),
		ManifestDigest: schema.NewDigest([]byte("synthetic-manifest-" + version)),
	}, schema.NewDigest([]byte("synthetic-class-"+version)), nil, registryapi.RegistryDerived{Freshness: registryapi.FreshnessFresh})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestMemoryTokenHashAndExpiry(t *testing.T) {
	memory := NewMemory()
	principal, err := domain.NewPrincipal("user", domain.ScopeObservationPrepare)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	const token = "synthetic-token-00000000"
	if err := memory.AddBearerToken(token, principal, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := memory.LookupBearerToken(t.Context(), HashBearerToken(token), now)
	if err != nil || got.ID() != principal.ID() {
		t.Fatalf("lookup principal=%s err=%v", got.ID(), err)
	}
	if _, err := memory.LookupBearerToken(t.Context(), HashBearerToken(token), now.Add(time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected expired token, got %v", err)
	}
	if _, err := memory.LookupBearerToken(t.Context(), HashBearerToken("different-token-000000"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected unknown token, got %v", err)
	}
}

func TestMemoryPublishedObservationIsConcurrentAndCursorStable(t *testing.T) {
	memory := NewMemory()
	first := storeObservation(t, "1.0.0")
	const writers = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := memory.PutPublishedObservation(t.Context(), first)
			if err == nil {
				successes.Add(1)
				return
			}
			if !errors.Is(err, ErrAlreadyExists) {
				t.Errorf("unexpected concurrent put error: %v", err)
			}
		}()
	}
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("want exactly one insert, got %d", got)
	}
	second := storeObservation(t, "1.1.0")
	if err := memory.PutPublishedObservation(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	page, err := memory.ListObservations(t.Context(), ObservationFilter{Subject: "synthetic/runtime"}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page %#v", page)
	}
	next, err := memory.ListObservations(t.Context(), ObservationFilter{Subject: "synthetic/runtime"}, page.NextCursor, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 || next.NextCursor != "" || next.Items[0].ID() == page.Items[0].ID() {
		t.Fatalf("second page %#v", next)
	}
}

func TestMemoryArtifactIsDigestCheckedAndDefensivelyCopied(t *testing.T) {
	memory := NewMemory()
	document := []byte(`{"name":"responses","version":"2026.07.0"}`)
	canonical, err := schema.CanonicalizeJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Kind: ArtifactPack, Name: "responses", Version: "2026.07.0", Digest: schema.NewDigest(canonical), Document: document}
	if err := memory.PutArtifact(artifact); err != nil {
		t.Fatal(err)
	}
	document[2] = 'X'
	loaded, err := memory.GetArtifact(t.Context(), ArtifactPack, "responses", "2026.07.0")
	if err != nil {
		t.Fatal(err)
	}
	loaded.Document[2] = 'Y'
	reloaded, err := memory.GetArtifact(t.Context(), ArtifactPack, "responses", "2026.07.0")
	if err != nil {
		t.Fatal(err)
	}
	if string(reloaded.Document) != string(canonical) {
		t.Fatalf("artifact storage was mutated through an alias: %s", reloaded.Document)
	}
}
