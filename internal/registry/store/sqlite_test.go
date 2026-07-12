package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

var sqliteTestNow = time.Date(2026, 7, 12, 12, 0, 0, 123456789, time.UTC)

func sqliteTestID(t *testing.T, suffix string) schema.InstanceID {
	t.Helper()
	id, err := schema.ParseInstanceID("00000000-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func openSQLiteForTest(t *testing.T, path string) *SQLite {
	t.Helper()
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open SQLite store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func closeSQLiteForTest(t *testing.T, store *SQLite) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("close SQLite store: %v", err)
	}
}

func assertPrivateFileMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("%s mode = %04o, want 0600", path, got)
	}
}

func TestSQLiteOpenCreatesPrivateRegularDatabaseAndRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "nested", "registry.db")
	store := openSQLiteForTest(t, databasePath)

	capabilities := store.Capabilities()
	if !capabilities.DurablePersistence || capabilities.HostedVerification || capabilities.OwnershipVerification {
		t.Fatalf("unexpected SQLite capabilities: %#v", capabilities)
	}
	version, err := store.InspectSchema(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if version != sqliteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, sqliteSchemaVersion)
	}
	info, err := os.Lstat(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("database is not a regular non-symlink file: %s", info.Mode())
	}
	assertPrivateFileMode(t, databasePath)
	closeSQLiteForTest(t, store)

	if _, err := OpenSQLite("relative-registry.db"); err == nil {
		t.Fatal("OpenSQLite accepted a relative path")
	}

	linkPath := filepath.Join(directory, "registry-link.db")
	if err := os.Symlink(databasePath, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires an unavailable Windows privilege: %v", err)
		}
		t.Fatal(err)
	}
	if linked, err := OpenSQLite(linkPath); err == nil {
		_ = linked.Close()
		t.Fatal("OpenSQLite followed a database symlink")
	}
}

func TestSQLiteBearerTokenPersistsScopesExpiryAndConfigurationRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	store := openSQLiteForTest(t, path)
	principal, err := domain.NewPrincipal("synthetic-runner", domain.ScopeObservationPrepare, domain.ScopeObservationCommit)
	if err != nil {
		t.Fatal(err)
	}
	const token = "synthetic-token-00000000"
	expiresAt := sqliteTestNow.Add(time.Hour)
	if err := store.AddBearerToken(token, principal, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := store.AddBearerToken(token, principal, expiresAt); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate token error = %v, want ErrAlreadyExists", err)
	}
	if err := store.AddBearerToken("synthetic-token-\u00a0invalid", principal, expiresAt); err == nil {
		t.Fatal("accepted a bearer token containing Unicode whitespace")
	}
	closeSQLiteForTest(t, store)

	databaseBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBytes, []byte(token)) {
		t.Fatal("SQLite database contains the plaintext bearer token")
	}

	reopened := openSQLiteForTest(t, path)
	got, err := reopened.LookupBearerToken(t.Context(), HashBearerToken(token), sqliteTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != principal.ID() || !slices.Equal(got.Scopes(), principal.Scopes()) {
		t.Fatalf("restored principal = %s %v, want %s %v", got.ID(), got.Scopes(), principal.ID(), principal.Scopes())
	}
	if _, err := reopened.LookupBearerToken(t.Context(), HashBearerToken(token), expiresAt); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("lookup at expiry error = %v, want ErrTokenExpired", err)
	}

	refreshed, err := domain.NewPrincipal("replacement-runner", domain.ScopeRunnerSubmit)
	if err != nil {
		t.Fatal(err)
	}
	refreshedExpiry := expiresAt.Add(time.Hour)
	if err := reopened.SetBearerToken(token, refreshed, refreshedExpiry); err != nil {
		t.Fatal(err)
	}
	closeSQLiteForTest(t, reopened)

	refreshedStore := openSQLiteForTest(t, path)
	got, err = refreshedStore.LookupBearerToken(t.Context(), HashBearerToken(token), expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != refreshed.ID() || !slices.Equal(got.Scopes(), refreshed.Scopes()) {
		t.Fatalf("refreshed principal = %s %v, want %s %v", got.ID(), got.Scopes(), refreshed.ID(), refreshed.Scopes())
	}
	if _, err := refreshedStore.LookupBearerToken(t.Context(), HashBearerToken(token), refreshedExpiry); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("refreshed lookup at expiry error = %v, want ErrTokenExpired", err)
	}
}

func TestSQLiteStagedIngestAndObservationSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	store := openSQLiteForTest(t, path)
	owner, err := domain.NewPrincipal("ingest-owner", domain.ScopeObservationPrepare, domain.ScopeObservationCommit)
	if err != nil {
		t.Fatal(err)
	}
	observation := storeObservation(t, "1.0.0")
	sessionID := sqliteTestID(t, "000000000101")
	session, err := domain.PrepareIngest(owner, sessionID, observation.ID(), sqliteTestNow.Add(time.Hour), sqliteTestNow)
	if err != nil {
		t.Fatal(err)
	}
	record := IngestRecord{
		Session:       session,
		DeclaredBytes: 4096,
		UploadDigest:  schema.NewDigest([]byte("synthetic-upload-body")),
		ChallengeHash: sha256.Sum256([]byte("synthetic-upload-challenge")),
	}
	if err := store.CreateIngest(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Stage(owner, observation.ID(), sqliteTestNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateIngest(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := store.PutStagedObservation(t.Context(), sessionID, observation); err != nil {
		t.Fatal(err)
	}
	if err := store.PutStagedObservation(t.Context(), sessionID, observation); err != nil {
		t.Fatalf("idempotent staged observation put: %v", err)
	}
	if err := store.PutStagedObservation(t.Context(), sessionID, storeObservation(t, "1.0.1")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("different staged observation error = %v, want ErrAlreadyExists", err)
	}
	closeSQLiteForTest(t, store)

	reopened := openSQLiteForTest(t, path)
	loaded, err := reopened.GetIngest(t.Context(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := loaded.Session.Snapshot()
	if snapshot.Status != domain.IngestStaged || snapshot.StagedDigest != observation.ID() {
		t.Fatalf("restored ingest lifecycle = %#v", snapshot)
	}
	if loaded.DeclaredBytes != record.DeclaredBytes || loaded.UploadDigest != record.UploadDigest || loaded.ChallengeHash != record.ChallengeHash {
		t.Fatalf("restored ingest record differs: %#v", loaded)
	}
	if committed, err := loaded.Session.Commit(owner, observation.ID(), sqliteTestNow.Add(2*time.Minute)); err != nil || committed.Status != domain.IngestCommitted {
		t.Fatalf("restored ingest cannot continue: status=%s err=%v", committed.Status, err)
	}
	staged, err := reopened.GetStagedObservation(t.Context(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if staged.ID() != observation.ID() {
		t.Fatalf("staged observation ID = %s, want %s", staged.ID(), observation.ID())
	}
}

func TestSQLitePublishedObservationsPersistFilterAndPaginate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	store := openSQLiteForTest(t, path)
	observations := []struct {
		version string
		value   schema.Digest
	}{
		{version: "1.0.0"},
		{version: "1.1.0"},
		{version: "2.0.0"},
	}
	for index := range observations {
		observation := storeObservation(t, observations[index].version)
		observations[index].value = observation.ID()
		if err := store.PutPublishedObservation(t.Context(), observation); err != nil {
			t.Fatal(err)
		}
	}
	closeSQLiteForTest(t, store)

	reopened := openSQLiteForTest(t, path)
	for _, expected := range observations {
		got, err := reopened.GetObservation(t.Context(), expected.value)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID() != expected.value {
			t.Fatalf("observation ID = %s, want %s", got.ID(), expected.value)
		}
	}

	first, err := reopened.ListObservations(t.Context(), ObservationFilter{
		Subject: "synthetic/runtime",
		Pack:    "responses",
		Profile: "synthetic.profile",
		Fresh:   "fresh",
	}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first page = %#v", first)
	}
	second, err := reopened.ListObservations(t.Context(), ObservationFilter{Subject: "synthetic/runtime"}, first.NextCursor, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 2 || second.NextCursor != "" {
		t.Fatalf("second page = %#v", second)
	}
	seen := map[schema.Digest]bool{first.Items[0].ID(): true}
	for _, observation := range second.Items {
		if seen[observation.ID()] {
			t.Fatalf("cursor repeated observation %s", observation.ID())
		}
		seen[observation.ID()] = true
	}
	if len(seen) != len(observations) {
		t.Fatalf("pagination returned %d unique observations, want %d", len(seen), len(observations))
	}

	filtered, err := reopened.ListObservations(t.Context(), ObservationFilter{Version: "1.1.0"}, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Items) != 1 {
		t.Fatalf("version filter returned %d observations, want 1", len(filtered.Items))
	}
	index, err := IndexObservation(filtered.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if index.Version != "1.1.0" {
		t.Fatalf("version filter returned %q", index.Version)
	}
	empty, err := reopened.ListObservations(t.Context(), ObservationFilter{Subject: "different/runtime"}, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Items) != 0 || empty.NextCursor != "" {
		t.Fatalf("nonmatching filter returned %#v", empty)
	}
	if _, err := reopened.ListObservations(t.Context(), ObservationFilter{}, "not-a-cursor", 10); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("invalid cursor error = %v, want ErrInvalidCursor", err)
	}
}

func TestSQLiteArtifactDigestAndDocumentPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	store := openSQLiteForTest(t, path)
	document := []byte(`{"version":"2026.07.0","name":"responses"}`)
	canonical, err := schema.CanonicalizeJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{
		Kind:     ArtifactPack,
		Name:     "responses",
		Version:  "2026.07.0",
		Digest:   schema.NewDigest(canonical),
		Document: document,
	}
	invalid := artifact
	invalid.Version = "2026.07.1"
	invalid.Digest = schema.NewDigest([]byte("not-the-document"))
	if err := store.PutArtifact(invalid); err == nil {
		t.Fatal("accepted artifact with a mismatched digest")
	}
	if err := store.PutArtifact(artifact); err != nil {
		t.Fatal(err)
	}
	document[2] = 'X'
	closeSQLiteForTest(t, store)

	reopened := openSQLiteForTest(t, path)
	loaded, err := reopened.GetArtifact(t.Context(), ArtifactPack, artifact.Name, artifact.Version)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Digest != artifact.Digest || !bytes.Equal(loaded.Document, canonical) {
		t.Fatalf("restored artifact = %#v document=%s", loaded, loaded.Document)
	}
	loaded.Document[0] = 'X'
	reloaded, err := reopened.GetArtifact(t.Context(), ArtifactPack, artifact.Name, artifact.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded.Document, canonical) {
		t.Fatal("caller mutated a persisted artifact through a returned slice")
	}
}

func TestSQLiteOwnershipChallengeOwnershipAndDisputeRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	store := openSQLiteForTest(t, path)
	owner, err := domain.NewPrincipal("subject-owner", domain.ScopeOwnershipManage, domain.ScopeDisputeCreate)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := domain.NewPrincipal("reporter", domain.ScopeDisputeCreate)
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := domain.NewPrincipal("independent-reviewer", domain.ScopeModerationReview)
	if err != nil {
		t.Fatal(err)
	}
	subject := domain.SubjectNamespace("example/runtime")
	challenge, err := domain.NewOwnershipChallenge(owner, sqliteTestID(t, "000000000201"), subject, domain.OwnershipDNS, "synthetic-local-nonce", sqliteTestNow.Add(time.Hour), sqliteTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challenge.Verify(schema.NewDigest([]byte("synthetic-local-ownership-evidence")), sqliteTestNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOwnershipChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	ownership, err := domain.OwnershipFromChallenge(challenge, sqliteTestNow.Add(30*24*time.Hour), sqliteTestNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOwnership(t.Context(), ownership); err != nil {
		t.Fatal(err)
	}
	dispute, err := domain.NewDispute(reporter, sqliteTestID(t, "000000000202"), schema.NewDigest([]byte("disputed-observation")), subject, owner.ID(), "synthetic result is disputed", sqliteTestNow.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dispute.AddOwnerResponse(owner, ownership, "synthetic owner response", sqliteTestNow.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := dispute.BeginReview(reviewer, sqliteTestNow.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := dispute.Resolve(reviewer, "synthetic evidence supports the observation", sqliteTestNow.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDispute(t.Context(), dispute); err != nil {
		t.Fatal(err)
	}
	wantChallenge := challenge.PersistentSnapshot()
	wantOwnership := ownership.Snapshot()
	wantDispute := dispute.Snapshot()
	closeSQLiteForTest(t, store)

	reopened := openSQLiteForTest(t, path)
	current, err := reopened.CurrentOwnership(t.Context(), subject, sqliteTestNow.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := current.Snapshot(); !reflect.DeepEqual(got, wantOwnership) {
		t.Fatalf("restored ownership = %#v, want %#v", got, wantOwnership)
	}
	if _, err := reopened.CurrentOwnership(t.Context(), subject, wantOwnership.ValidUntil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ownership at expiry error = %v, want ErrNotFound", err)
	}
	restoredDispute, err := reopened.GetDispute(t.Context(), wantDispute.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := restoredDispute.Snapshot(); !reflect.DeepEqual(got, wantDispute) {
		t.Fatalf("restored dispute = %#v, want %#v", got, wantDispute)
	}

	// Ownership challenges have no public read operation yet, but their
	// durable representation must remain reconstructable for a future worker.
	var challengeRaw []byte
	if err := reopened.db.QueryRowContext(t.Context(), `SELECT snapshot_json FROM ownership_challenges WHERE challenge_id=?`, wantChallenge.ID).Scan(&challengeRaw); err != nil {
		t.Fatal(err)
	}
	var challengeSnapshot domain.OwnershipChallengeSnapshot
	if err := json.Unmarshal(challengeRaw, &challengeSnapshot); err != nil {
		t.Fatal(err)
	}
	restoredChallenge, err := domain.RestoreOwnershipChallenge(challengeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got := restoredChallenge.PersistentSnapshot(); !reflect.DeepEqual(got, wantChallenge) {
		t.Fatalf("restored challenge = %#v, want %#v", got, wantChallenge)
	}
}

func TestSQLiteBackupIsPrivateAndReopenable(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "registry.db")
	backupPath := filepath.Join(directory, "backups", "registry-backup.db")
	store := openSQLiteForTest(t, path)
	observation := storeObservation(t, "3.0.0")
	if err := store.PutPublishedObservation(t.Context(), observation); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(t.Context(), backupPath); err != nil {
		t.Fatal(err)
	}
	assertPrivateFileMode(t, backupPath)
	if err := store.Backup(t.Context(), backupPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("backup to existing destination error = %v, want os.ErrExist", err)
	}

	backup := openSQLiteForTest(t, backupPath)
	version, err := backup.InspectSchema(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if version != sqliteSchemaVersion {
		t.Fatalf("backup schema version = %d, want %d", version, sqliteSchemaVersion)
	}
	loaded, err := backup.GetObservation(t.Context(), observation.ID())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID() != observation.ID() {
		t.Fatalf("backup observation ID = %s, want %s", loaded.ID(), observation.ID())
	}
}

func TestSQLiteConcurrentPublishedObservationHasSingleWinner(t *testing.T) {
	store := openSQLiteForTest(t, filepath.Join(t.TempDir(), "registry.db"))
	observation := storeObservation(t, "4.0.0")
	const writers = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, writers)
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := store.PutPublishedObservation(t.Context(), observation)
			if err == nil {
				successes.Add(1)
				return
			}
			if !errors.Is(err, ErrAlreadyExists) {
				errorsSeen <- err
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("unexpected concurrent insert error: %v", err)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful concurrent inserts = %d, want exactly 1", got)
	}
	page, err := store.ListObservations(t.Context(), ObservationFilter{}, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID() != observation.ID() {
		t.Fatalf("concurrent insert result = %#v", page)
	}
}
