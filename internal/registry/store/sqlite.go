package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

const sqliteSchemaVersion = 1

// SQLite is the durable single-node self-hosted Registry store. Hosted
// verification remains a separate service and is not implied by durability.
type SQLite struct {
	db   *sql.DB
	path string
}

func OpenSQLite(path string) (*SQLite, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("SQLite path must be absolute")
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("SQLite database must be a regular non-symlink file")
		}
		if err := os.Chmod(clean, 0o600); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: clean}).String() + "?_txlock=immediate"
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	store := &SQLite{db: database, path: clean}
	if err := database.Ping(); err != nil {
		database.Close()
		return nil, err
	}
	for _, statement := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
	} {
		if _, err := database.Exec(statement); err != nil {
			database.Close()
			return nil, fmt.Errorf("configure SQLite connection: %w", err)
		}
	}
	if err := store.migrate(context.Background()); err != nil {
		database.Close()
		return nil, err
	}
	if err := os.Chmod(clean, 0o600); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (store *SQLite) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	_, _ = store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return store.db.Close()
}
func (store *SQLite) Capabilities() Capabilities { return Capabilities{DurablePersistence: true} }

func (store *SQLite) migrate(ctx context.Context) error {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var version int
	if err := transaction.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > sqliteSchemaVersion {
		return fmt.Errorf("SQLite schema version %d is newer than supported %d", version, sqliteSchemaVersion)
	}
	if version == 0 {
		statements := []string{
			`CREATE TABLE tokens (token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32), principal_id TEXT NOT NULL, scopes_json BLOB NOT NULL, expires_at TEXT NOT NULL) STRICT`,
			`CREATE TABLE ingests (session_id TEXT PRIMARY KEY, snapshot_json BLOB NOT NULL, declared_bytes INTEGER NOT NULL CHECK(declared_bytes>0), upload_digest TEXT NOT NULL, challenge_hash BLOB NOT NULL CHECK(length(challenge_hash)=32)) STRICT`,
			`CREATE TABLE staged_observations (session_id TEXT PRIMARY KEY, observation_json BLOB NOT NULL) STRICT`,
			`CREATE TABLE observations (observation_id TEXT PRIMARY KEY, observation_json BLOB NOT NULL, subject TEXT NOT NULL, version TEXT NOT NULL, pack TEXT NOT NULL, profile TEXT NOT NULL) STRICT`,
			`CREATE INDEX observations_filter ON observations(subject,version,pack,profile,observation_id)`,
			`CREATE TABLE ownership_challenges (challenge_id TEXT PRIMARY KEY, snapshot_json BLOB NOT NULL) STRICT`,
			`CREATE TABLE ownerships (subject TEXT PRIMARY KEY, snapshot_json BLOB NOT NULL) STRICT`,
			`CREATE TABLE disputes (dispute_id TEXT PRIMARY KEY, snapshot_json BLOB NOT NULL) STRICT`,
			`CREATE TABLE artifacts (kind TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, digest TEXT NOT NULL, document BLOB NOT NULL, PRIMARY KEY(kind,name,version)) STRICT`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if _, err := transaction.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (store *SQLite) AddBearerToken(token string, principal domain.Principal, expiresAt time.Time) error {
	if err := validateBearerCredential(token, principal, expiresAt); err != nil {
		return err
	}
	scopes, err := schema.CanonicalMarshal(principal.Scopes())
	if err != nil {
		return err
	}
	hash := HashBearerToken(token)
	result, err := store.db.Exec(`INSERT INTO tokens(token_hash,principal_id,scopes_json,expires_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, hash[:], principal.ID(), scopes, formatTime(expiresAt))
	if err != nil {
		return err
	}
	return requireInserted(result)
}

// SetBearerToken atomically installs or refreshes a credential supplied by
// process configuration. The plaintext token is never written to SQLite.
func (store *SQLite) SetBearerToken(token string, principal domain.Principal, expiresAt time.Time) error {
	if err := validateBearerCredential(token, principal, expiresAt); err != nil {
		return err
	}
	scopes, err := schema.CanonicalMarshal(principal.Scopes())
	if err != nil {
		return err
	}
	hash := HashBearerToken(token)
	_, err = store.db.Exec(`INSERT INTO tokens(token_hash,principal_id,scopes_json,expires_at) VALUES(?,?,?,?)
		ON CONFLICT(token_hash) DO UPDATE SET principal_id=excluded.principal_id,scopes_json=excluded.scopes_json,expires_at=excluded.expires_at`, hash[:], principal.ID(), scopes, formatTime(expiresAt))
	return err
}

func (store *SQLite) LookupBearerToken(ctx context.Context, hash [32]byte, now time.Time) (domain.Principal, error) {
	var id string
	var scopesRaw []byte
	var expiryRaw string
	if err := store.db.QueryRowContext(ctx, `SELECT principal_id,scopes_json,expires_at FROM tokens WHERE token_hash=?`, hash[:]).Scan(&id, &scopesRaw, &expiryRaw); err != nil {
		return domain.Principal{}, mapNotFound(err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiryRaw)
	if err != nil {
		return domain.Principal{}, err
	}
	if now.IsZero() || !now.Before(expiry) {
		return domain.Principal{}, ErrTokenExpired
	}
	var scopes []domain.Scope
	if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
		return domain.Principal{}, err
	}
	return domain.NewPrincipal(domain.PrincipalID(id), scopes...)
}

func (store *SQLite) CreateIngest(ctx context.Context, record IngestRecord) error {
	if err := validateIngestRecord(record); err != nil {
		return err
	}
	snapshot := record.Session.Snapshot()
	raw, err := schema.CanonicalMarshal(snapshot)
	if err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO ingests(session_id,snapshot_json,declared_bytes,upload_digest,challenge_hash) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`, snapshot.SessionID, raw, record.DeclaredBytes, record.UploadDigest, record.ChallengeHash[:])
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) GetIngest(ctx context.Context, id schema.InstanceID) (IngestRecord, error) {
	var raw []byte
	var declared int64
	var upload string
	var challenge []byte
	if err := store.db.QueryRowContext(ctx, `SELECT snapshot_json,declared_bytes,upload_digest,challenge_hash FROM ingests WHERE session_id=?`, id).Scan(&raw, &declared, &upload, &challenge); err != nil {
		return IngestRecord{}, mapNotFound(err)
	}
	var snapshot domain.IngestSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return IngestRecord{}, err
	}
	session, err := domain.RestoreIngest(snapshot)
	if err != nil {
		return IngestRecord{}, err
	}
	digest, err := schema.ParseDigest(upload)
	if err != nil {
		return IngestRecord{}, err
	}
	if len(challenge) != 32 {
		return IngestRecord{}, errors.New("stored challenge hash is corrupt")
	}
	var hash [32]byte
	copy(hash[:], challenge)
	return IngestRecord{Session: session, DeclaredBytes: declared, UploadDigest: digest, ChallengeHash: hash}, nil
}
func (store *SQLite) UpdateIngest(ctx context.Context, record IngestRecord) error {
	if err := validateIngestRecord(record); err != nil {
		return err
	}
	snapshot := record.Session.Snapshot()
	raw, err := schema.CanonicalMarshal(snapshot)
	if err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `UPDATE ingests SET snapshot_json=?,declared_bytes=?,upload_digest=?,challenge_hash=? WHERE session_id=?`, raw, record.DeclaredBytes, record.UploadDigest, record.ChallengeHash[:], snapshot.SessionID)
	if err != nil {
		return err
	}
	return requireUpdated(result)
}

func validateIngestRecord(record IngestRecord) error {
	if record.Session == nil {
		return errors.New("ingest session is required")
	}
	if record.DeclaredBytes < 1 {
		return errors.New("declared bytes must be positive")
	}
	return record.UploadDigest.Validate()
}

func (store *SQLite) PutStagedObservation(ctx context.Context, id schema.InstanceID, observation registryapi.Observation) error {
	raw, err := encodeObservation(observation)
	if err != nil {
		return err
	}
	var existing []byte
	scanErr := store.db.QueryRowContext(ctx, `SELECT observation_json FROM staged_observations WHERE session_id=?`, id).Scan(&existing)
	if scanErr == nil {
		if bytes.Equal(existing, raw) {
			return nil
		}
		return ErrAlreadyExists
	}
	if !errors.Is(scanErr, sql.ErrNoRows) {
		return scanErr
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO staged_observations(session_id,observation_json) VALUES(?,?) ON CONFLICT DO NOTHING`, id, raw)
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) GetStagedObservation(ctx context.Context, id schema.InstanceID) (registryapi.Observation, error) {
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT observation_json FROM staged_observations WHERE session_id=?`, id).Scan(&raw); err != nil {
		return registryapi.Observation{}, mapNotFound(err)
	}
	return decodeObservation(raw)
}
func (store *SQLite) EnqueueVerification(context.Context, schema.InstanceID) error {
	return ErrNotImplemented
}

func (store *SQLite) PutPublishedObservation(ctx context.Context, observation registryapi.Observation) error {
	raw, err := encodeObservation(observation)
	if err != nil {
		return err
	}
	index, err := IndexObservation(observation)
	if err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO observations(observation_id,observation_json,subject,version,pack,profile) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`, observation.ID(), raw, index.Subject, index.Version, index.Pack, index.Profile)
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) GetObservation(ctx context.Context, id schema.Digest) (registryapi.Observation, error) {
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT observation_json FROM observations WHERE observation_id=?`, id).Scan(&raw); err != nil {
		return registryapi.Observation{}, mapNotFound(err)
	}
	return decodeObservation(raw)
}
func (store *SQLite) ListObservations(ctx context.Context, filter ObservationFilter, cursor string, limit int) (ObservationPage, error) {
	if limit < 1 || limit > 100 {
		return ObservationPage{}, errors.New("limit must be between 1 and 100")
	}
	after := ""
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return ObservationPage{}, ErrInvalidCursor
		}
		digest, err := schema.ParseDigest(string(decoded))
		if err != nil {
			return ObservationPage{}, ErrInvalidCursor
		}
		after = string(digest)
	}
	rows, err := store.db.QueryContext(ctx, `SELECT observation_json FROM observations WHERE observation_id>? ORDER BY observation_id`, after)
	if err != nil {
		return ObservationPage{}, err
	}
	defer rows.Close()
	items := make([]registryapi.Observation, 0, limit+1)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return ObservationPage{}, err
		}
		observation, err := decodeObservation(raw)
		if err != nil {
			return ObservationPage{}, err
		}
		index, err := IndexObservation(observation)
		if err != nil {
			return ObservationPage{}, err
		}
		if !matches(filter, index) {
			continue
		}
		items = append(items, observation)
		if len(items) == limit+1 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return ObservationPage{}, err
	}
	page := ObservationPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(page.Items[limit-1].ID()))
	}
	return page, nil
}

func (store *SQLite) PutOwnershipChallenge(ctx context.Context, challenge *domain.OwnershipChallenge) error {
	if challenge == nil {
		return errors.New("challenge is required")
	}
	snapshot := challenge.PersistentSnapshot()
	raw, err := schema.CanonicalMarshal(snapshot)
	if err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO ownership_challenges(challenge_id,snapshot_json) VALUES(?,?) ON CONFLICT DO NOTHING`, snapshot.ID, raw)
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) PutOwnership(ctx context.Context, ownership *domain.Ownership) error {
	if ownership == nil {
		return errors.New("ownership is required")
	}
	snapshot := ownership.Snapshot()
	raw, err := schema.CanonicalMarshal(snapshot)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO ownerships(subject,snapshot_json) VALUES(?,?) ON CONFLICT(subject) DO UPDATE SET snapshot_json=excluded.snapshot_json`, snapshot.Subject, raw)
	return err
}
func (store *SQLite) CurrentOwnership(ctx context.Context, subject domain.SubjectNamespace, now time.Time) (*domain.Ownership, error) {
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT snapshot_json FROM ownerships WHERE subject=?`, subject).Scan(&raw); err != nil {
		return nil, mapNotFound(err)
	}
	var snapshot domain.OwnershipSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	ownership, err := domain.RestoreOwnership(snapshot)
	if err != nil {
		return nil, err
	}
	if !ownership.Current(now) {
		return nil, ErrNotFound
	}
	return ownership, nil
}

func (store *SQLite) PutDispute(ctx context.Context, dispute *domain.Dispute) error {
	if dispute == nil {
		return errors.New("dispute is required")
	}
	snapshot := dispute.Snapshot()
	raw, err := schema.CanonicalMarshal(snapshot)
	if err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO disputes(dispute_id,snapshot_json) VALUES(?,?) ON CONFLICT DO NOTHING`, snapshot.ID, raw)
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) GetDispute(ctx context.Context, id schema.InstanceID) (*domain.Dispute, error) {
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT snapshot_json FROM disputes WHERE dispute_id=?`, id).Scan(&raw); err != nil {
		return nil, mapNotFound(err)
	}
	var snapshot domain.DisputeSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return domain.RestoreDispute(snapshot)
}

func (store *SQLite) PutArtifact(artifact Artifact) error {
	if artifact.Kind != ArtifactPack && artifact.Kind != ArtifactProfile {
		return errors.New("invalid artifact kind")
	}
	if artifact.Name == "" || artifact.Version == "" {
		return errors.New("artifact identity is required")
	}
	canonical, err := schema.CanonicalizeJSON(artifact.Document)
	if err != nil {
		return err
	}
	if schema.NewDigest(canonical) != artifact.Digest {
		return errors.New("artifact digest mismatch")
	}
	result, err := store.db.Exec(`INSERT INTO artifacts(kind,name,version,digest,document) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`, artifact.Kind, artifact.Name, artifact.Version, artifact.Digest, canonical)
	if err != nil {
		return err
	}
	return requireInserted(result)
}
func (store *SQLite) GetArtifact(ctx context.Context, kind ArtifactKind, name, version string) (Artifact, error) {
	var digestText string
	var document []byte
	if err := store.db.QueryRowContext(ctx, `SELECT digest,document FROM artifacts WHERE kind=? AND name=? AND version=?`, kind, name, version).Scan(&digestText, &document); err != nil {
		return Artifact{}, mapNotFound(err)
	}
	digest, err := schema.ParseDigest(digestText)
	if err != nil {
		return Artifact{}, err
	}
	if schema.NewDigest(document) != digest {
		return Artifact{}, errors.New("stored artifact digest mismatch")
	}
	return Artifact{Kind: kind, Name: name, Version: version, Digest: digest, Document: bytes.Clone(document)}, nil
}

func encodeObservation(observation registryapi.Observation) ([]byte, error) {
	if err := observation.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return schema.CanonicalizeJSON(raw)
}
func decodeObservation(raw []byte) (registryapi.Observation, error) {
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return registryapi.Observation{}, errors.New("stored observation is not canonical")
	}
	var observation registryapi.Observation
	if err := json.Unmarshal(raw, &observation); err != nil {
		return registryapi.Observation{}, err
	}
	return observation, nil
}
func requireInserted(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrAlreadyExists
	}
	return nil
}
func requireUpdated(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}
func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

// Backup creates a transactionally consistent standalone SQLite copy using
// VACUUM INTO. The destination must not already exist.
func (store *SQLite) Backup(ctx context.Context, destination string) error {
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("backup destination must be absolute")
	}
	clean := filepath.Clean(destination)
	if _, err := os.Lstat(clean); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return err
	}
	quoted := strings.ReplaceAll(clean, "'", "''")
	if _, err := store.db.ExecContext(ctx, "VACUUM INTO '"+quoted+"'"); err != nil {
		return err
	}
	return os.Chmod(clean, 0o600)
}

// InspectSchema is used by backup/restore smoke tests without exposing SQL.
func (store *SQLite) InspectSchema(ctx context.Context) (int, error) {
	var version int
	err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	return version, err
}

var _ Store = (*SQLite)(nil)
