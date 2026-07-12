package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

type tokenRecord struct {
	principal domain.Principal
	expiresAt time.Time
}

// Memory is concurrency-safe but deliberately non-durable.  Its use in a
// running binary must be explicitly acknowledged by the operator.
type Memory struct {
	mu         sync.RWMutex
	tokens     map[[32]byte]tokenRecord
	ingests    map[schema.InstanceID]IngestRecord
	staged     map[schema.InstanceID]registryapi.Observation
	observed   map[schema.Digest]registryapi.Observation
	ownerships map[domain.SubjectNamespace]*domain.Ownership
	challenges map[schema.InstanceID]*domain.OwnershipChallenge
	disputes   map[schema.InstanceID]*domain.Dispute
	artifacts  map[string]Artifact
}

func NewMemory() *Memory {
	return &Memory{
		tokens:     make(map[[32]byte]tokenRecord),
		ingests:    make(map[schema.InstanceID]IngestRecord),
		staged:     make(map[schema.InstanceID]registryapi.Observation),
		observed:   make(map[schema.Digest]registryapi.Observation),
		ownerships: make(map[domain.SubjectNamespace]*domain.Ownership),
		challenges: make(map[schema.InstanceID]*domain.OwnershipChallenge),
		disputes:   make(map[schema.InstanceID]*domain.Dispute),
		artifacts:  make(map[string]Artifact),
	}
}

func HashBearerToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (memory *Memory) Capabilities() Capabilities { return Capabilities{} }

// AddBearerToken hashes the token before retaining it.  The plaintext is not
// stored and is never exposed by the Store interface.
func (memory *Memory) AddBearerToken(token string, principal domain.Principal, expiresAt time.Time) error {
	if err := validateBearerCredential(token, principal, expiresAt); err != nil {
		return err
	}
	hash := HashBearerToken(token)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.tokens[hash]; exists {
		return ErrAlreadyExists
	}
	memory.tokens[hash] = tokenRecord{principal: principal, expiresAt: expiresAt.UTC()}
	return nil
}

// SetBearerToken installs or refreshes an operator-configured credential. It
// is intentionally outside the Store request interface: callers must already
// control process configuration, and only the SHA-256 token hash is retained.
func (memory *Memory) SetBearerToken(token string, principal domain.Principal, expiresAt time.Time) error {
	if err := validateBearerCredential(token, principal, expiresAt); err != nil {
		return err
	}
	hash := HashBearerToken(token)
	memory.mu.Lock()
	memory.tokens[hash] = tokenRecord{principal: principal, expiresAt: expiresAt.UTC()}
	memory.mu.Unlock()
	return nil
}

func validateBearerCredential(token string, principal domain.Principal, expiresAt time.Time) error {
	if len(token) < 16 || len(token) > 4096 || strings.TrimSpace(token) != token {
		return fmt.Errorf("bearer token must be 16..4096 non-whitespace bytes")
	}
	for _, character := range token {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return fmt.Errorf("bearer token contains whitespace or control characters")
		}
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("bearer token expiry is required")
	}
	return principal.ID().Validate()
}

func (memory *Memory) LookupBearerToken(_ context.Context, hash [32]byte, now time.Time) (domain.Principal, error) {
	memory.mu.RLock()
	record, exists := memory.tokens[hash]
	memory.mu.RUnlock()
	if !exists {
		return domain.Principal{}, ErrNotFound
	}
	if now.IsZero() || !now.Before(record.expiresAt) {
		return domain.Principal{}, ErrTokenExpired
	}
	return record.principal, nil
}

func (memory *Memory) CreateIngest(_ context.Context, record IngestRecord) error {
	if record.Session == nil {
		return fmt.Errorf("ingest session is required")
	}
	if record.DeclaredBytes < 1 {
		return fmt.Errorf("declared upload size must be positive")
	}
	if err := record.UploadDigest.Validate(); err != nil {
		return fmt.Errorf("upload digest: %w", err)
	}
	id := record.Session.Snapshot().SessionID
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.ingests[id]; exists {
		return ErrAlreadyExists
	}
	memory.ingests[id] = record
	return nil
}

func (memory *Memory) GetIngest(_ context.Context, id schema.InstanceID) (IngestRecord, error) {
	memory.mu.RLock()
	record, exists := memory.ingests[id]
	memory.mu.RUnlock()
	if !exists {
		return IngestRecord{}, ErrNotFound
	}
	return record, nil
}

func (memory *Memory) UpdateIngest(_ context.Context, record IngestRecord) error {
	if record.Session == nil {
		return fmt.Errorf("ingest session is required")
	}
	id := record.Session.Snapshot().SessionID
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.ingests[id]; !exists {
		return ErrNotFound
	}
	memory.ingests[id] = record
	return nil
}

func (memory *Memory) PutStagedObservation(_ context.Context, id schema.InstanceID, observation registryapi.Observation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if existing, exists := memory.staged[id]; exists {
		if existing.ID() == observation.ID() {
			return nil
		}
		return ErrAlreadyExists
	}
	memory.staged[id] = observation
	return nil
}

func (memory *Memory) GetStagedObservation(_ context.Context, id schema.InstanceID) (registryapi.Observation, error) {
	memory.mu.RLock()
	observation, exists := memory.staged[id]
	memory.mu.RUnlock()
	if !exists {
		return registryapi.Observation{}, ErrNotFound
	}
	return observation, nil
}

func (memory *Memory) EnqueueVerification(_ context.Context, _ schema.InstanceID) error {
	return ErrNotImplemented
}

func (memory *Memory) PutPublishedObservation(_ context.Context, observation registryapi.Observation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	if _, err := IndexObservation(observation); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.observed[observation.ID()]; exists {
		return ErrAlreadyExists
	}
	memory.observed[observation.ID()] = observation
	return nil
}

func (memory *Memory) GetObservation(_ context.Context, id schema.Digest) (registryapi.Observation, error) {
	memory.mu.RLock()
	observation, exists := memory.observed[id]
	memory.mu.RUnlock()
	if !exists {
		return registryapi.Observation{}, ErrNotFound
	}
	return observation, nil
}

func (memory *Memory) ListObservations(_ context.Context, filter ObservationFilter, cursor string, limit int) (ObservationPage, error) {
	if limit < 1 || limit > 100 {
		return ObservationPage{}, fmt.Errorf("limit must be between 1 and 100")
	}
	var after schema.Digest
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return ObservationPage{}, ErrInvalidCursor
		}
		after, err = schema.ParseDigest(string(decoded))
		if err != nil {
			return ObservationPage{}, ErrInvalidCursor
		}
	}
	memory.mu.RLock()
	items := make([]registryapi.Observation, 0, len(memory.observed))
	for _, observation := range memory.observed {
		items = append(items, observation)
	}
	memory.mu.RUnlock()
	sort.Slice(items, func(left, right int) bool { return items[left].ID() < items[right].ID() })

	filtered := make([]registryapi.Observation, 0, min(limit+1, len(items)))
	for _, observation := range items {
		if after != "" && observation.ID() <= after {
			continue
		}
		index, err := IndexObservation(observation)
		if err != nil {
			return ObservationPage{}, err
		}
		if !matches(filter, index) {
			continue
		}
		filtered = append(filtered, observation)
		if len(filtered) == limit+1 {
			break
		}
	}
	page := ObservationPage{Items: filtered}
	if len(filtered) > limit {
		page.Items = filtered[:limit]
		last := page.Items[len(page.Items)-1].ID()
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(last))
	}
	return page, nil
}

func matches(filter ObservationFilter, index ObservationIndex) bool {
	if filter.Subject != "" && filter.Subject != index.Subject {
		return false
	}
	if filter.Version != "" && filter.Version != index.Version {
		return false
	}
	if filter.Pack != "" && filter.Pack != index.Pack {
		return false
	}
	if filter.Profile != "" && filter.Profile != index.Profile {
		return false
	}
	if filter.Trust != "" && !slices.Contains(index.TrustLabels, filter.Trust) {
		return false
	}
	if filter.Fresh != "" && filter.Fresh != index.Freshness {
		return false
	}
	return true
}

func IndexObservation(observation registryapi.Observation) (ObservationIndex, error) {
	projection := observation.Projection()
	var subject struct {
		Project string `json:"project"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(projection.Subject.Bytes(), &subject); err != nil {
		return ObservationIndex{}, fmt.Errorf("index observation subject: %w", err)
	}
	var test struct {
		Pack        string `json:"pack"`
		PackVersion string `json:"pack_version"`
		Profile     string `json:"profile"`
	}
	if err := json.Unmarshal(projection.Test.Bytes(), &test); err != nil {
		return ObservationIndex{}, fmt.Errorf("index observation test: %w", err)
	}
	if subject.Project == "" || subject.Version == "" || test.Pack == "" || test.PackVersion == "" || test.Profile == "" {
		return ObservationIndex{}, fmt.Errorf("observation lacks subject/test fields required by Registry indexes")
	}
	derived := observation.RegistryDerived()
	return ObservationIndex{
		Subject:     subject.Project,
		Version:     subject.Version,
		Pack:        test.Pack,
		PackVersion: test.PackVersion,
		Profile:     test.Profile,
		TrustLabels: slices.Clone(derived.TrustLabels),
		Freshness:   string(derived.Freshness),
	}, nil
}

func (memory *Memory) PutOwnershipChallenge(_ context.Context, challenge *domain.OwnershipChallenge) error {
	if challenge == nil {
		return fmt.Errorf("ownership challenge is required")
	}
	id := challenge.Snapshot(time.Time{}).ID
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.challenges[id]; exists {
		return ErrAlreadyExists
	}
	memory.challenges[id] = challenge
	return nil
}

func (memory *Memory) PutOwnership(_ context.Context, ownership *domain.Ownership) error {
	if ownership == nil {
		return fmt.Errorf("ownership is required")
	}
	snapshot := ownership.Snapshot()
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.ownerships[snapshot.Subject] = ownership
	return nil
}

func (memory *Memory) CurrentOwnership(_ context.Context, subject domain.SubjectNamespace, now time.Time) (*domain.Ownership, error) {
	memory.mu.RLock()
	ownership, exists := memory.ownerships[subject]
	memory.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	if !ownership.Current(now) {
		return nil, ErrNotFound
	}
	return ownership, nil
}

func (memory *Memory) PutDispute(_ context.Context, dispute *domain.Dispute) error {
	if dispute == nil {
		return fmt.Errorf("dispute is required")
	}
	id := dispute.Snapshot().ID
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.disputes[id]; exists {
		return ErrAlreadyExists
	}
	memory.disputes[id] = dispute
	return nil
}

func (memory *Memory) GetDispute(_ context.Context, id schema.InstanceID) (*domain.Dispute, error) {
	memory.mu.RLock()
	dispute, exists := memory.disputes[id]
	memory.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	return dispute, nil
}

func artifactKey(kind ArtifactKind, name, version string) string {
	return string(kind) + "\x00" + name + "\x00" + version
}

// PutArtifact installs a signed/digest-checked fixture or a result from a
// higher-level artifact verifier.  The HTTP layer has no endpoint that can
// call it with user-controlled content.
func (memory *Memory) PutArtifact(artifact Artifact) error {
	if artifact.Kind != ArtifactPack && artifact.Kind != ArtifactProfile {
		return fmt.Errorf("invalid artifact kind %q", artifact.Kind)
	}
	if artifact.Name == "" || artifact.Version == "" {
		return fmt.Errorf("artifact name and version are required")
	}
	if err := artifact.Digest.Validate(); err != nil {
		return err
	}
	canonical, err := schema.CanonicalizeJSON(artifact.Document)
	if err != nil {
		return err
	}
	if schema.NewDigest(canonical) != artifact.Digest {
		return fmt.Errorf("artifact document digest mismatch")
	}
	artifact.Document = bytes.Clone(canonical)
	key := artifactKey(artifact.Kind, artifact.Name, artifact.Version)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.artifacts[key]; exists {
		return ErrAlreadyExists
	}
	memory.artifacts[key] = artifact
	return nil
}

func (memory *Memory) GetArtifact(_ context.Context, kind ArtifactKind, name, version string) (Artifact, error) {
	memory.mu.RLock()
	artifact, exists := memory.artifacts[artifactKey(kind, name, version)]
	memory.mu.RUnlock()
	if !exists {
		return Artifact{}, ErrNotFound
	}
	artifact.Document = bytes.Clone(artifact.Document)
	return artifact, nil
}
