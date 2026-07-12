// Package runstore persists immutable, canonical local run artifacts. It does
// not upload data or interpret compatibility results.
package runstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	RecordSchema                = "urn:agentapi-doctor:local-run-record:v1alpha2"
	legacyRecordSchema          = "urn:agentapi-doctor:local-run-record:v1alpha1"
	DefaultMaxRecordBytes int64 = 64 << 20
)

var (
	ErrExists          = errors.New("run already exists")
	ErrCorrupt         = errors.New("local run record is corrupt")
	ErrLatestForbidden = errors.New("latest run reference is forbidden in CI mode")
	ErrRootReplaced    = errors.New("run store root identity changed")
)

type Record struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         schema.InstanceID `json:"run_id"`
	BundleDigest  schema.Digest     `json:"bundle_digest"`
	Bundle        json.RawMessage   `json:"bundle"`
	PlanDigest    schema.Digest     `json:"plan_digest,omitempty"`
	Plan          json.RawMessage   `json:"plan,omitempty"`
}

// Payload keeps the two canonical documents named at the call site so bundle
// and plan bytes cannot be silently swapped.
type Payload struct {
	Bundle []byte
	Plan   []byte
}

type recordV2 struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         schema.InstanceID `json:"run_id"`
	BundleDigest  schema.Digest     `json:"bundle_digest"`
	Bundle        json.RawMessage   `json:"bundle"`
	PlanDigest    schema.Digest     `json:"plan_digest"`
	Plan          json.RawMessage   `json:"plan"`
}

type recordV1 struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         schema.InstanceID `json:"run_id"`
	BundleDigest  schema.Digest     `json:"bundle_digest"`
	Bundle        json.RawMessage   `json:"bundle"`
}

type latestPointer struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         schema.InstanceID `json:"run_id"`
	RecordDigest  schema.Digest     `json:"record_digest"`
}

type Store struct {
	root         string
	rootIdentity os.FileInfo
	maxBytes     int64
	syncDir      func(string) error
	mu           sync.Mutex
}

func Open(root string, maxBytes int64) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("run store root must be absolute")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRecordBytes
	}
	clean := filepath.Clean(root)
	if err := ensureDirectory(clean); err != nil {
		return nil, err
	}
	identity, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	return &Store{root: clean, rootIdentity: identity, maxBytes: maxBytes, syncDir: syncDirectoryPlatform}, nil
}

func (store *Store) validateRoot() error {
	if store == nil || store.rootIdentity == nil {
		return errors.New("run store is nil")
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
	if filepath.Clean(path) != store.root {
		return errors.New("run store directory sync path must be its root")
	}
	if store.syncDir == nil {
		return errors.New("run store directory sync capability is unavailable")
	}
	if err := store.syncDir(store.root); err != nil {
		return err
	}
	return store.validateRoot()
}

func (store *Store) syncTemporaryDirectory(path string, identity os.FileInfo) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	if identity == nil || filepath.Dir(clean) != store.root || !strings.HasPrefix(filepath.Base(clean), ".run-") {
		return ErrCorrupt
	}
	current, err := os.Lstat(clean)
	if err != nil {
		return store.rootAwareError(err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(identity, current) {
		return ErrCorrupt
	}
	if store.syncDir == nil {
		return errors.New("run store directory sync capability is unavailable")
	}
	if err := store.syncDir(clean); err != nil {
		return err
	}
	after, err := os.Lstat(clean)
	if err != nil {
		return store.rootAwareError(err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(identity, after) {
		return ErrCorrupt
	}
	return store.validateRoot()
}

// Put publishes one canonical JSON bundle and canonical plan snapshot together
// under the immutable UUIDv7 run ID. PlanDigest is the digest of the complete
// embedded snapshot bytes, distinct from any nested ResolvedRunPlan digest.
func (store *Store) Put(runID schema.InstanceID, payload Payload) (schema.Digest, error) {
	if store == nil {
		return "", errors.New("run store is nil")
	}
	if err := runID.Validate(); err != nil {
		return "", err
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if err := requireCanonicalJSON("bundle", payload.Bundle, store.maxBytes); err != nil {
		return "", err
	}
	if err := requireCanonicalJSON("plan", payload.Plan, store.maxBytes); err != nil {
		return "", err
	}
	record := recordV2{
		SchemaVersion: RecordSchema,
		RunID:         runID,
		BundleDigest:  schema.NewDigest(payload.Bundle),
		Bundle:        append(json.RawMessage(nil), payload.Bundle...),
		PlanDigest:    schema.NewDigest(payload.Plan),
		Plan:          append(json.RawMessage(nil), payload.Plan...),
	}
	encoded, err := schema.CanonicalMarshal(record)
	if err != nil {
		return "", err
	}
	if int64(len(encoded)) > store.maxBytes {
		return "", errors.New("run record size is outside the configured limit")
	}
	recordDigest := schema.NewDigest(encoded)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	temporaryDirectory, err := os.MkdirTemp(store.root, ".run-*")
	if err != nil {
		return "", store.rootAwareError(err)
	}
	temporaryIdentity, err := os.Lstat(temporaryDirectory)
	if err != nil {
		return "", store.rootAwareError(err)
	}
	defer func() {
		if temporaryDirectory == "" || store.validateRoot() != nil {
			return
		}
		current, err := os.Lstat(temporaryDirectory)
		if err == nil && current.Mode()&os.ModeSymlink == 0 && current.IsDir() && os.SameFile(temporaryIdentity, current) {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if err := writeExclusive(filepath.Join(temporaryDirectory, "record.json"), encoded); err != nil {
		return "", store.rootAwareError(err)
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	writtenRecord, err := readRegular(filepath.Join(temporaryDirectory, "record.json"), store.maxBytes)
	if err != nil {
		return "", store.rootAwareError(err)
	}
	if !bytes.Equal(writtenRecord, encoded) {
		return "", ErrCorrupt
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	currentTemporary, err := os.Lstat(temporaryDirectory)
	if err != nil || currentTemporary.Mode()&os.ModeSymlink != 0 || !currentTemporary.IsDir() || !os.SameFile(temporaryIdentity, currentTemporary) {
		return "", ErrCorrupt
	}
	if err := store.syncTemporaryDirectory(temporaryDirectory, temporaryIdentity); err != nil {
		return "", fmt.Errorf("sync temporary run directory: %w", err)
	}
	directory := filepath.Join(store.root, string(runID))
	if _, err := os.Lstat(directory); err == nil {
		return "", ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", store.rootAwareError(err)
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryDirectory, directory); err != nil {
		if rootErr := store.validateRoot(); rootErr != nil {
			return "", rootErr
		}
		if _, existsErr := os.Lstat(directory); existsErr == nil {
			return "", ErrExists
		}
		return "", err
	}
	temporaryDirectory = ""
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if err := store.syncDirectory(store.root); err != nil {
		return "", fmt.Errorf("sync published run directory parent: %w", err)
	}
	publishedDirectory, err := os.Lstat(directory)
	if err != nil || publishedDirectory.Mode()&os.ModeSymlink != 0 || !publishedDirectory.IsDir() || !os.SameFile(temporaryIdentity, publishedDirectory) {
		return "", ErrCorrupt
	}
	publishedRecord, err := store.readRunRecord(runID)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(publishedRecord, encoded) {
		return "", ErrCorrupt
	}
	pointer := latestPointer{SchemaVersion: RecordSchema + ":latest", RunID: runID, RecordDigest: recordDigest}
	pointerBytes, err := schema.CanonicalMarshal(pointer)
	if err != nil {
		return "", err
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if err := store.replaceLatest(pointerBytes); err != nil {
		return "", err
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	return recordDigest, nil
}

func (store *Store) Resolve(reference string, allowLatest bool) (schema.InstanceID, error) {
	if store == nil {
		return "", errors.New("run store is nil")
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	if strings.EqualFold(reference, "latest") {
		if !allowLatest {
			return "", ErrLatestForbidden
		}
		pointer, err := store.readLatest()
		if err != nil {
			return "", err
		}
		recordRaw, err := store.readRunRecord(pointer.RunID)
		if err != nil {
			if errors.Is(err, ErrRootReplaced) {
				return "", err
			}
			return "", ErrCorrupt
		}
		if schema.NewDigest(recordRaw) != pointer.RecordDigest {
			return "", ErrCorrupt
		}
		if err := requireCanonicalJSON("record", recordRaw, store.maxBytes); err != nil {
			return "", ErrCorrupt
		}
		record, err := decodeRecord(recordRaw, pointer.RunID, store.maxBytes)
		if err != nil || pointer.SchemaVersion != record.SchemaVersion+":latest" {
			return "", ErrCorrupt
		}
		if err := store.validateRoot(); err != nil {
			return "", err
		}
		return pointer.RunID, nil
	}
	runID, err := schema.ParseInstanceID(reference)
	if err != nil {
		return "", err
	}
	if err := store.validateRoot(); err != nil {
		return "", err
	}
	return runID, nil
}

func (store *Store) Get(reference string, allowLatest bool) (Record, error) {
	if store == nil {
		return Record{}, errors.New("run store is nil")
	}
	if err := store.validateRoot(); err != nil {
		return Record{}, err
	}
	var (
		runID          schema.InstanceID
		expectedDigest schema.Digest
		pointerSchema  string
	)
	if strings.EqualFold(reference, "latest") {
		if !allowLatest {
			return Record{}, ErrLatestForbidden
		}
		pointer, err := store.readLatest()
		if err != nil {
			return Record{}, err
		}
		runID, expectedDigest, pointerSchema = pointer.RunID, pointer.RecordDigest, pointer.SchemaVersion
	} else {
		var err error
		runID, err = schema.ParseInstanceID(reference)
		if err != nil {
			return Record{}, err
		}
	}
	raw, err := store.readRunRecord(runID)
	if err != nil {
		if errors.Is(err, ErrRootReplaced) {
			return Record{}, err
		}
		if expectedDigest != "" {
			return Record{}, ErrCorrupt
		}
		return Record{}, err
	}
	if expectedDigest != "" && schema.NewDigest(raw) != expectedDigest {
		return Record{}, ErrCorrupt
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Record{}, ErrCorrupt
	}
	record, err := decodeRecord(raw, runID, store.maxBytes)
	if err != nil {
		return Record{}, ErrCorrupt
	}
	if pointerSchema != "" && pointerSchema != record.SchemaVersion+":latest" {
		return Record{}, ErrCorrupt
	}
	return record, nil
}

func (store *Store) List() ([]schema.InstanceID, error) {
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, store.rootAwareError(err)
	}
	result := []schema.InstanceID{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id, err := schema.ParseInstanceID(entry.Name())
		if err == nil {
			result = append(result, id)
		}
	}
	sortIDs(result)
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	return result, nil
}

func (store *Store) readLatest() (latestPointer, error) {
	if err := store.validateRoot(); err != nil {
		return latestPointer{}, err
	}
	raw, err := readRegular(filepath.Join(store.root, "latest.json"), 1<<20)
	if err != nil {
		return latestPointer{}, store.rootAwareError(err)
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return latestPointer{}, ErrCorrupt
	}
	var pointer latestPointer
	if err := strictDecode(raw, &pointer); err != nil || !supportedPointerSchema(pointer.SchemaVersion) || pointer.RunID.Validate() != nil || pointer.RecordDigest.Validate() != nil {
		return latestPointer{}, ErrCorrupt
	}
	if err := store.validateRoot(); err != nil {
		return latestPointer{}, err
	}
	return pointer, nil
}

func (store *Store) readRunRecord(runID schema.InstanceID) ([]byte, error) {
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	directory := filepath.Join(store.root, string(runID))
	before, err := os.Lstat(directory)
	if err != nil {
		return nil, store.rootAwareError(err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, ErrCorrupt
	}
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	raw, err := readRegular(filepath.Join(directory, "record.json"), store.maxBytes)
	if err != nil {
		return nil, store.rootAwareError(err)
	}
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	after, err := os.Lstat(directory)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(before, after) {
		return nil, ErrCorrupt
	}
	if err := store.validateRoot(); err != nil {
		return nil, err
	}
	return raw, nil
}

func decodeRecord(raw []byte, runID schema.InstanceID, maxBytes int64) (Record, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Record{}, ErrCorrupt
	}
	var record Record
	switch header.SchemaVersion {
	case RecordSchema:
		var wire recordV2
		if err := strictDecode(raw, &wire); err != nil {
			return Record{}, ErrCorrupt
		}
		record = Record(wire)
		if schema.NewDigest(record.Plan) != record.PlanDigest || requireCanonicalJSON("plan", record.Plan, maxBytes) != nil {
			return Record{}, ErrCorrupt
		}
	case legacyRecordSchema:
		var wire recordV1
		if err := strictDecode(raw, &wire); err != nil {
			return Record{}, ErrCorrupt
		}
		record = Record{
			SchemaVersion: wire.SchemaVersion,
			RunID:         wire.RunID,
			BundleDigest:  wire.BundleDigest,
			Bundle:        wire.Bundle,
		}
	default:
		return Record{}, ErrCorrupt
	}
	if record.RunID != runID || schema.NewDigest(record.Bundle) != record.BundleDigest || requireCanonicalJSON("bundle", record.Bundle, maxBytes) != nil {
		return Record{}, ErrCorrupt
	}
	return record, nil
}

func requireCanonicalJSON(label string, raw []byte, maxBytes int64) error {
	if len(raw) == 0 || int64(len(raw)) > maxBytes {
		return fmt.Errorf("%s size is outside the configured limit", label)
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		return fmt.Errorf("%s must be strict JSON: %w", label, err)
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("%s must already be RFC8785 canonical JSON", label)
	}
	return nil
}

func supportedPointerSchema(value string) bool {
	return value == RecordSchema+":latest" || value == legacyRecordSchema+":latest"
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("run store root must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}
func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}
func (store *Store) replaceLatest(data []byte) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.root, ".latest-*")
	if err != nil {
		return store.rootAwareError(err)
	}
	name := temporary.Name()
	temporaryIdentity, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return store.rootAwareError(err)
	}
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if !removeTemporary || store.validateRoot() != nil {
			return
		}
		current, err := os.Lstat(name)
		if err == nil && current.Mode()&os.ModeSymlink == 0 && current.Mode().IsRegular() && os.SameFile(temporaryIdentity, current) {
			_ = os.Remove(name)
		}
	}()
	if err := store.validateRoot(); err != nil {
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		return store.rootAwareError(err)
	}
	if _, err := temporary.Write(data); err != nil {
		return store.rootAwareError(err)
	}
	if err := temporary.Sync(); err != nil {
		return store.rootAwareError(err)
	}
	if err := temporary.Close(); err != nil {
		return store.rootAwareError(err)
	}
	if err := store.validateRoot(); err != nil {
		return err
	}
	current, err := os.Lstat(name)
	if err != nil {
		return store.rootAwareError(err)
	}
	if !regularWithinLimit(current, int64(len(data))) || current.Size() != int64(len(data)) || !os.SameFile(temporaryIdentity, current) {
		return ErrCorrupt
	}
	if err := os.Rename(name, filepath.Join(store.root, "latest.json")); err != nil {
		return store.rootAwareError(err)
	}
	removeTemporary = false
	if err := store.syncDirectory(store.root); err != nil {
		return fmt.Errorf("sync latest pointer parent: %w", err)
	}
	return store.validateRoot()
}
func readRegular(path string, limit int64) ([]byte, error) {
	return readRegularAfterLstat(path, limit, nil)
}

func readRegularAfterLstat(path string, limit int64, hook func() error) ([]byte, error) {
	if limit <= 0 {
		return nil, ErrCorrupt
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !regularWithinLimit(before, limit) {
		return nil, ErrCorrupt
	}
	if hook != nil {
		if err := hook(); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !regularWithinLimit(opened, limit) || !os.SameFile(before, opened) || before.Size() != opened.Size() {
		return nil, ErrCorrupt
	}
	readLimit := limit + 1
	if readLimit <= 0 {
		readLimit = limit
	}
	raw, err := io.ReadAll(io.LimitReader(file, readLimit))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return nil, ErrCorrupt
	}
	if !regularWithinLimit(after, limit) || !regularWithinLimit(pathAfter, limit) ||
		!os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		opened.Size() != after.Size() || opened.Size() != pathAfter.Size() || int64(len(raw)) != opened.Size() {
		return nil, ErrCorrupt
	}
	return raw, nil
}

func regularWithinLimit(info os.FileInfo, limit int64) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= limit
}
func sortIDs(values []schema.InstanceID) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
