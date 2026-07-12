// Package cas implements immutable local content-addressed storage for
// sanitized payloads and their strongly typed Evidence envelopes. It
// deliberately cannot accept arbitrary raw payload bytes.
package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	DefaultMaxObjectBytes    int64 = 256 << 20
	EvidenceSchemaVersion          = "urn:agentapi-doctor:evidence:v1alpha2"
	maxEvidenceRelationDepth       = 32
)

var (
	ErrCorruptObject  = errors.New("CAS object digest mismatch")
	ErrObjectConflict = errors.New("CAS object identity already has different content")
	ErrRootReplaced   = errors.New("CAS root identity changed")
)

type Store struct {
	root           string
	rootIdentity   os.FileInfo
	maxObjectBytes int64
	syncDir        func(string) error
}

func Open(root string, maxObjectBytes int64) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("CAS root must be an absolute path")
	}
	if maxObjectBytes <= 0 {
		maxObjectBytes = DefaultMaxObjectBytes
	}
	clean := filepath.Clean(root)
	_, beforeErr := os.Lstat(clean)
	created := errors.Is(beforeErr, os.ErrNotExist)
	if beforeErr != nil && !created {
		return nil, fmt.Errorf("stat CAS root: %w", beforeErr)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create CAS root: %w", err)
	}
	if err := requireDirectory(clean); err != nil {
		return nil, fmt.Errorf("CAS root: %w", err)
	}
	if created {
		if err := syncDirectoryPlatform(filepath.Dir(clean)); err != nil {
			return nil, fmt.Errorf("sync CAS root parent: %w", err)
		}
		if err := syncDirectoryPlatform(clean); err != nil {
			return nil, fmt.Errorf("sync CAS root: %w", err)
		}
	}
	identity, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("stat CAS root identity: %w", err)
	}
	return &Store{root: clean, rootIdentity: identity, maxObjectBytes: maxObjectBytes, syncDir: syncDirectoryPlatform}, nil
}

func (store *Store) validateRoot() error {
	if store == nil || store.rootIdentity == nil {
		return errors.New("CAS store is nil")
	}
	current, err := os.Lstat(store.root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRootReplaced, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(store.rootIdentity, current) {
		return ErrRootReplaced
	}
	return nil
}

func (store *Store) rootAwareError(err error) error {
	if rootErr := store.validateRoot(); rootErr != nil {
		return rootErr
	}
	return err
}

func (store *Store) syncDirectory(path string) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	relative, err := filepath.Rel(store.root, clean)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("CAS directory sync path escapes its root")
	}
	if store.syncDir == nil {
		return errors.New("CAS directory sync capability is unavailable")
	}
	if err := store.syncDir(clean); err != nil {
		return err
	}
	return store.validateRoot()
}

// Put accepts only a SanitizedPayload, preserving the write-before-redaction
// type boundary for payload objects.
func (store *Store) Put(ctx context.Context, payload redaction.SanitizedPayload) (schema.ObjectRef, error) {
	if store == nil {
		return schema.ObjectRef{}, errors.New("CAS store is nil")
	}
	if ctx == nil {
		return schema.ObjectRef{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return schema.ObjectRef{}, err
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	if payload.Size() <= 0 || int64(payload.Size()) > store.maxObjectBytes {
		return schema.ObjectRef{}, fmt.Errorf("sanitized payload size must be between 1 and %d bytes", store.maxObjectBytes)
	}
	data := payload.Bytes()
	defer zero(data)
	digest := schema.NewDigest(data)
	path, err := store.objectPath(digest)
	if err != nil {
		return schema.ObjectRef{}, err
	}
	if err := store.putDigestBytes(path, data, digest); err != nil {
		return schema.ObjectRef{}, err
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	return schema.ObjectRef{Kind: "Payload", ContentDigest: digest}, nil
}

func (store *Store) Get(ctx context.Context, digest schema.Digest) ([]byte, error) {
	if store == nil {
		return nil, errors.New("CAS store is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	path, err := store.objectPath(digest)
	if err != nil {
		return nil, err
	}
	return store.readVerified(path, digest)
}

func (store *Store) Verify(ctx context.Context, digest schema.Digest) error {
	data, err := store.Get(ctx, digest)
	if err != nil {
		return err
	}
	zero(data)
	return nil
}

// SealEvidenceMeta is the single definition of the recorder's immutable
// Evidence projection. Both recorder creation and CAS reads use it, so a
// projection change cannot silently make newly written references dangling.
func SealEvidenceMeta(producer schema.Producer, createdAt schema.UTCTime, evidence schema.Evidence) (schema.EnvelopeMeta, error) {
	projection, err := evidenceProjectionOf(evidence, producer, createdAt)
	if err != nil {
		return schema.EnvelopeMeta{}, err
	}
	return schema.SealMeta(EvidenceSchemaVersion, "Evidence", "", producer, createdAt, projection)
}

// PutEvidence persists one validated Evidence envelope. Its ObjectRef digest
// remains the digest of the immutable Evidence projection. A separate
// full-envelope content object protects all canonical envelope bytes at rest.
func (store *Store) PutEvidence(ctx context.Context, evidence schema.Evidence) (schema.ObjectRef, error) {
	if store == nil {
		return schema.ObjectRef{}, errors.New("CAS store is nil")
	}
	if ctx == nil {
		return schema.ObjectRef{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return schema.ObjectRef{}, err
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	if err := validateEvidence(evidence, evidence.ObjectRef); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("persist Evidence envelope: %w", err)
	}
	if err := store.Verify(ctx, evidence.PayloadRef.ContentDigest); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("persist Evidence envelope with unavailable payload: %w", err)
	}
	relations := newEvidenceTraversal()
	relations.visiting[evidence.ObjectRef] = struct{}{}
	if err := store.resolveEvidenceRelations(ctx, evidence, relations, 0); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("persist Evidence envelope with unresolved relation: %w", err)
	}
	encoded, err := schema.CanonicalMarshal(evidence)
	if err != nil {
		return schema.ObjectRef{}, fmt.Errorf("encode Evidence envelope: %w", err)
	}
	if len(encoded) == 0 || int64(len(encoded)) > store.maxObjectBytes {
		return schema.ObjectRef{}, errors.New("evidence envelope size is outside the configured limit")
	}

	ref := evidence.ObjectRef
	refPath, err := store.evidenceRefPath(ref)
	if err != nil {
		return schema.ObjectRef{}, err
	}
	if _, statErr := os.Lstat(refPath); statErr == nil {
		if err := store.syncDirectory(filepath.Dir(refPath)); err != nil {
			return schema.ObjectRef{}, fmt.Errorf("sync existing Evidence reference directory: %w", err)
		}
		return store.compareExistingEvidence(ctx, ref, encoded)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return schema.ObjectRef{}, statErr
	}

	envelopeDigest := schema.NewDigest(encoded)
	envelopePath, err := store.evidenceEnvelopePath(envelopeDigest)
	if err != nil {
		return schema.ObjectRef{}, err
	}
	if err := store.putDigestBytes(envelopePath, encoded, envelopeDigest); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("persist canonical Evidence envelope bytes: %w", err)
	}
	if err := store.ensureDirectory(filepath.Dir(refPath)); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("create Evidence reference shard: %w", err)
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	if err := os.Link(envelopePath, refPath); err != nil {
		if !os.IsExist(err) {
			return schema.ObjectRef{}, fmt.Errorf("commit immutable Evidence reference: %w", store.rootAwareError(err))
		}
		if err := store.syncDirectory(filepath.Dir(refPath)); err != nil {
			return schema.ObjectRef{}, fmt.Errorf("sync existing Evidence reference directory: %w", err)
		}
		return store.compareExistingEvidence(ctx, ref, encoded)
	}
	if err := store.syncDirectory(filepath.Dir(refPath)); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("sync committed Evidence reference directory: %w", err)
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	loaded, err := store.GetEvidence(ctx, ref)
	if err != nil {
		return schema.ObjectRef{}, err
	}
	loadedBytes, err := schema.CanonicalMarshal(loaded)
	if err != nil || !bytes.Equal(loadedBytes, encoded) {
		return schema.ObjectRef{}, ErrObjectConflict
	}
	if err := store.validateRoot(); err != nil {
		return schema.ObjectRef{}, err
	}
	return ref, nil
}

type evidenceTraversal struct {
	visiting map[schema.ObjectRef]struct{}
	loaded   map[schema.ObjectRef]schema.Evidence
}

func newEvidenceTraversal() *evidenceTraversal {
	return &evidenceTraversal{
		visiting: make(map[schema.ObjectRef]struct{}),
		loaded:   make(map[schema.ObjectRef]schema.Evidence),
	}
}

// GetEvidence resolves a report Evidence ref to a strict canonical envelope.
// It verifies the full-envelope storage object, typed schema, envelope ref,
// independently recomputed immutable projection digest, payload, and complete
// relation graph.
func (store *Store) GetEvidence(ctx context.Context, ref schema.ObjectRef) (schema.Evidence, error) {
	if store == nil {
		return schema.Evidence{}, errors.New("CAS store is nil")
	}
	if ctx == nil {
		return schema.Evidence{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return schema.Evidence{}, err
	}
	if err := store.validateRoot(); err != nil {
		return schema.Evidence{}, err
	}
	return store.getEvidence(ctx, ref, newEvidenceTraversal(), 0)
}

func (store *Store) getEvidence(ctx context.Context, ref schema.ObjectRef, traversal *evidenceTraversal, depth int) (schema.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return schema.Evidence{}, err
	}
	if depth > maxEvidenceRelationDepth {
		return schema.Evidence{}, corruptEvidence(errors.New("evidence relation depth exceeds the configured limit"))
	}
	if evidence, ok := traversal.loaded[ref]; ok {
		return evidence, nil
	}
	if _, cycle := traversal.visiting[ref]; cycle {
		return schema.Evidence{}, corruptEvidence(errors.New("evidence relation cycle detected"))
	}
	traversal.visiting[ref] = struct{}{}
	defer delete(traversal.visiting, ref)

	path, err := store.evidenceRefPath(ref)
	if err != nil {
		return schema.Evidence{}, err
	}
	raw, err := store.readBounded(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return schema.Evidence{}, err
		}
		return schema.Evidence{}, corruptEvidence(err)
	}
	defer zero(raw)

	envelopeDigest := schema.NewDigest(raw)
	envelopePath, err := store.evidenceEnvelopePath(envelopeDigest)
	if err != nil {
		return schema.Evidence{}, corruptEvidence(err)
	}
	content, err := store.readVerified(envelopePath, envelopeDigest)
	if err != nil {
		return schema.Evidence{}, corruptEvidence(err)
	}
	defer zero(content)
	if !bytes.Equal(raw, content) {
		return schema.Evidence{}, corruptEvidence(errors.New("evidence reference and envelope content differ"))
	}

	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return schema.Evidence{}, corruptEvidence(errors.New("evidence envelope is not strict RFC 8785 canonical JSON"))
	}
	var evidence schema.Evidence
	if err := decodeStrictJSON(raw, &evidence); err != nil {
		return schema.Evidence{}, corruptEvidence(fmt.Errorf("decode Evidence envelope: %w", err))
	}
	if err := validateEvidence(evidence, ref); err != nil {
		return schema.Evidence{}, corruptEvidence(err)
	}
	if err := store.Verify(ctx, evidence.PayloadRef.ContentDigest); err != nil {
		return schema.Evidence{}, corruptEvidence(fmt.Errorf("resolve Evidence payload: %w", err))
	}
	if err := store.resolveEvidenceRelations(ctx, evidence, traversal, depth); err != nil {
		return schema.Evidence{}, corruptEvidence(fmt.Errorf("resolve Evidence relations: %w", err))
	}
	if err := store.validateRoot(); err != nil {
		return schema.Evidence{}, err
	}
	traversal.loaded[ref] = evidence
	return evidence, nil
}

func (store *Store) resolveEvidenceRelations(ctx context.Context, evidence schema.Evidence, traversal *evidenceTraversal, depth int) error {
	for index, relation := range evidence.Relations {
		target := relation.Target
		if err := target.Validate(); err != nil {
			return fmt.Errorf("relation %d target: %w", index, err)
		}
		if target.InstanceID != "" {
			return fmt.Errorf("relation %d target must be content-addressed", index)
		}
		switch target.Kind {
		case "Payload":
			if err := store.Verify(ctx, target.ContentDigest); err != nil {
				return fmt.Errorf("relation %d Payload target: %w", index, err)
			}
		case "Evidence":
			if _, err := store.getEvidence(ctx, target, traversal, depth+1); err != nil {
				return fmt.Errorf("relation %d Evidence target: %w", index, err)
			}
		default:
			return fmt.Errorf("relation %d target kind %q is unsupported", index, target.Kind)
		}
	}
	return nil
}

func (store *Store) compareExistingEvidence(ctx context.Context, ref schema.ObjectRef, expected []byte) (schema.ObjectRef, error) {
	loaded, err := store.GetEvidence(ctx, ref)
	if err != nil {
		return schema.ObjectRef{}, err
	}
	encoded, err := schema.CanonicalMarshal(loaded)
	if err != nil {
		return schema.ObjectRef{}, corruptEvidence(err)
	}
	if !bytes.Equal(encoded, expected) {
		return schema.ObjectRef{}, ErrObjectConflict
	}
	return ref, nil
}

func validateEvidence(evidence schema.Evidence, expected schema.ObjectRef) error {
	if err := expected.Validate(); err != nil {
		return fmt.Errorf("evidence ref: %w", err)
	}
	if expected.Kind != "Evidence" || expected.InstanceID != "" {
		return errors.New("evidence store requires a content-addressed Evidence ref")
	}
	if err := evidence.Validate(); err != nil {
		return fmt.Errorf("evidence validation: %w", err)
	}
	if evidence.SchemaVersion != EvidenceSchemaVersion || evidence.Kind != "Evidence" || evidence.InstanceID != "" {
		return errors.New("evidence envelope has an unsupported schema or identity form")
	}
	if evidence.ObjectRef != expected {
		return errors.New("evidence ObjectRef does not match the requested reference")
	}
	if evidence.PayloadRef == nil || evidence.PayloadDigest == nil {
		return errors.New("persisted evidence requires a payload reference")
	}
	if evidence.PayloadRef.Kind != "Payload" || evidence.PayloadRef.InstanceID != "" {
		return errors.New("evidence payload_ref must be a content-addressed Payload ref")
	}
	resealed, err := SealEvidenceMeta(evidence.Producer, evidence.CreatedAt, evidence)
	if err != nil {
		return fmt.Errorf("recompute evidence projection: %w", err)
	}
	if resealed.ContentDigest != evidence.ContentDigest || resealed.ObjectRef != evidence.ObjectRef || evidence.EvidenceID != resealed.ContentDigest {
		return errors.New("evidence immutable projection digest does not match its envelope")
	}
	return nil
}

type evidenceProjection struct {
	SchemaVersion       string                     `json:"schema_version"`
	Kind                string                     `json:"kind"`
	Producer            schema.Producer            `json:"producer"`
	CreatedAt           schema.UTCTime             `json:"created_at"`
	Extensions          map[string]json.RawMessage `json:"extensions,omitempty"`
	RunID               schema.InstanceID          `json:"run_id"`
	InvocationID        schema.InstanceID          `json:"invocation_id"`
	AttemptID           schema.InstanceID          `json:"attempt_id"`
	Sequence            uint64                     `json:"sequence"`
	CaptureLayer        schema.CaptureLayer        `json:"capture_layer"`
	InstrumentationMode schema.InstrumentationMode `json:"instrumentation_mode"`
	Direction           schema.Direction           `json:"direction"`
	EvidenceKind        string                     `json:"evidence_kind"`
	MonotonicOffsetNS   int64                      `json:"monotonic_offset_ns"`
	ByteOffset          *int64                     `json:"byte_offset,omitempty"`
	EventOffset         *int64                     `json:"event_offset,omitempty"`
	PayloadRef          schema.ObjectRef           `json:"payload_ref"`
	PayloadDigest       schema.Digest              `json:"payload_digest"`
	Redactions          []schema.RedactionRecord   `json:"redactions"`
	Relations           []schema.EvidenceRelation  `json:"relations,omitempty"`
}

func evidenceProjectionOf(evidence schema.Evidence, producer schema.Producer, createdAt schema.UTCTime) (evidenceProjection, error) {
	if evidence.PayloadRef == nil || evidence.PayloadDigest == nil {
		return evidenceProjection{}, errors.New("evidence projection requires payload_ref and payload_digest")
	}
	return evidenceProjection{
		SchemaVersion:       EvidenceSchemaVersion,
		Kind:                "Evidence",
		Producer:            producer,
		CreatedAt:           createdAt,
		Extensions:          evidence.Extensions,
		RunID:               evidence.RunID,
		InvocationID:        evidence.InvocationID,
		AttemptID:           evidence.AttemptID,
		Sequence:            evidence.Sequence,
		CaptureLayer:        evidence.CaptureLayer,
		InstrumentationMode: evidence.InstrumentationMode,
		Direction:           evidence.Direction,
		EvidenceKind:        evidence.EvidenceKind,
		MonotonicOffsetNS:   evidence.MonotonicOffsetNS,
		ByteOffset:          evidence.ByteOffset,
		EventOffset:         evidence.EventOffset,
		PayloadRef:          *evidence.PayloadRef,
		PayloadDigest:       *evidence.PayloadDigest,
		Redactions:          evidence.Redactions,
		Relations:           evidence.Relations,
	}, nil
}

func (store *Store) objectPath(digest schema.Digest) (string, error) {
	return store.digestPath(filepath.Join(store.root, "sha256"), digest)
}

func (store *Store) evidenceRefPath(ref schema.ObjectRef) (string, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	if ref.Kind != "Evidence" || ref.InstanceID != "" {
		return "", errors.New("evidence ref must be content-addressed and have kind Evidence")
	}
	return store.digestPath(filepath.Join(store.root, "objects", "evidence", "refs", "sha256"), ref.ContentDigest)
}

func (store *Store) evidenceEnvelopePath(digest schema.Digest) (string, error) {
	return store.digestPath(filepath.Join(store.root, "objects", "evidence", "envelopes", "sha256"), digest)
}

func (store *Store) digestPath(base string, digest schema.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}
	hexDigest := strings.TrimPrefix(string(digest), "sha256:")
	return filepath.Join(base, hexDigest[:2], hexDigest[2:]), nil
}

func (store *Store) putDigestBytes(path string, data []byte, digest schema.Digest) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := store.ensureDirectory(directory); err != nil {
		return fmt.Errorf("create CAS shard: %w", err)
	}
	if existing, err := store.readVerified(path, digest); err == nil {
		zero(existing)
		if err := store.syncDirectory(directory); err != nil {
			return fmt.Errorf("sync existing CAS object directory: %w", err)
		}
		return store.validateRoot()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".put-*")
	if err != nil {
		return fmt.Errorf("create CAS temporary object: %w", store.rootAwareError(err))
	}
	temporaryName := temporary.Name()
	temporaryIdentity, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return store.rootAwareError(err)
	}
	defer func() {
		_ = temporary.Close()
		if store.validateRoot() != nil {
			return
		}
		current, err := os.Lstat(temporaryName)
		if err == nil && current.Mode()&os.ModeSymlink == 0 && current.Mode().IsRegular() && os.SameFile(temporaryIdentity, current) {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := store.validateRoot(); err != nil {
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set CAS object permissions: %w", store.rootAwareError(err))
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write CAS object: %w", store.rootAwareError(err))
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync CAS object: %w", store.rootAwareError(err))
	}
	written, err := temporary.Stat()
	if err != nil {
		return store.rootAwareError(err)
	}
	if !written.Mode().IsRegular() || !os.SameFile(temporaryIdentity, written) || written.Size() != int64(len(data)) {
		return errors.New("CAS temporary object identity changed")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close CAS object: %w", store.rootAwareError(err))
	}
	if err := store.validateRoot(); err != nil {
		return err
	}
	current, err := os.Lstat(temporaryName)
	if err != nil {
		return store.rootAwareError(err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(temporaryIdentity, current) || current.Size() != int64(len(data)) {
		return errors.New("CAS temporary object path changed before commit")
	}
	if err := os.Link(temporaryName, path); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("commit immutable CAS object: %w", store.rootAwareError(err))
		}
	}
	committed, err := store.readVerified(path, digest)
	if err != nil {
		return err
	}
	zero(committed)
	current, err = os.Lstat(temporaryName)
	if err != nil {
		return store.rootAwareError(err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(temporaryIdentity, current) {
		return errors.New("CAS temporary object path changed after commit")
	}
	if err := os.Remove(temporaryName); err != nil {
		return fmt.Errorf("remove CAS temporary object: %w", store.rootAwareError(err))
	}
	if err := store.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync committed CAS object directory: %w", err)
	}
	if err := store.validateRoot(); err != nil {
		return err
	}
	return nil
}

func (store *Store) readVerified(path string, expected schema.Digest) ([]byte, error) {
	data, err := store.readBounded(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	actual := schema.Digest("sha256:" + hex.EncodeToString(sum[:]))
	if actual != expected {
		zero(data)
		return nil, ErrCorruptObject
	}
	return data, nil
}

func (store *Store) readBounded(path string) ([]byte, error) {
	return store.readBoundedAfterLstat(path, nil)
}

func (store *Store) readBoundedAfterLstat(path string, hook func() error) ([]byte, error) {
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	if err := store.checkDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, store.rootAwareError(err)
	}
	if !store.regularObject(before) {
		return nil, errors.New("CAS object must be a bounded regular non-symlink file")
	}
	if hook != nil {
		if err := hook(); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, store.rootAwareError(err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !store.regularObject(opened) || !os.SameFile(before, opened) || before.Size() != opened.Size() {
		return nil, errors.New("CAS object changed between lstat and open")
	}
	readLimit := store.maxObjectBytes + 1
	if readLimit <= 0 {
		readLimit = store.maxObjectBytes
	}
	limited := io.LimitReader(file, readLimit)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		zero(data)
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		zero(data)
		return nil, store.rootAwareError(err)
	}
	if !store.regularObject(after) || !store.regularObject(pathAfter) ||
		!os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		opened.Size() != after.Size() || opened.Size() != pathAfter.Size() || int64(len(data)) != opened.Size() {
		zero(data)
		return nil, errors.New("CAS object changed or exceeded the configured limit during read")
	}
	if err := store.checkDirectory(filepath.Dir(path), false); err != nil {
		zero(data)
		return nil, err
	}
	if err := store.validateRoot(); err != nil {
		zero(data)
		return nil, err
	}
	return data, nil
}

func (store *Store) regularObject(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= store.maxObjectBytes
}

func (store *Store) ensureDirectory(path string) error {
	return store.checkDirectory(path, true)
}

func (store *Store) checkDirectory(path string, create bool) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	relative, err := filepath.Rel(store.root, clean)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("CAS path escapes its root")
	}
	if relative == "." {
		return nil
	}
	current := store.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		if create {
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
		}
		if err := requireDirectory(current); err != nil {
			return err
		}
		if create {
			if err := store.validateRoot(); err != nil {
				return err
			}
			if err := store.syncDirectory(current); err != nil {
				return fmt.Errorf("sync CAS directory %q: %w", current, err)
			}
			if err := store.syncDirectory(filepath.Dir(current)); err != nil {
				return fmt.Errorf("sync CAS directory parent %q: %w", filepath.Dir(current), err)
			}
		}
	}
	return store.validateRoot()
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a non-symlink directory")
	}
	return nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func corruptEvidence(err error) error {
	if err == nil {
		return ErrCorruptObject
	}
	return fmt.Errorf("%w: %v", ErrCorruptObject, err)
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
