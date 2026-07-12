// Package runstore persists immutable, canonical local run artifacts. It does
// not upload data or interpret compatibility results.
package runstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	RecordSchema                = "urn:agentapi-doctor:local-run-record:v1alpha1"
	DefaultMaxRecordBytes int64 = 64 << 20
)

var (
	ErrExists          = errors.New("run already exists")
	ErrCorrupt         = errors.New("local run record is corrupt")
	ErrLatestForbidden = errors.New("latest run reference is forbidden in CI mode")
)

type Record struct {
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
	root     string
	maxBytes int64
	mu       sync.Mutex
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
	return &Store{root: clean, maxBytes: maxBytes}, nil
}

// Put stores one canonical JSON bundle under its immutable UUIDv7 run ID.
func (store *Store) Put(runID schema.InstanceID, bundle []byte) (schema.Digest, error) {
	if store == nil {
		return "", errors.New("run store is nil")
	}
	if err := runID.Validate(); err != nil {
		return "", err
	}
	if len(bundle) == 0 || int64(len(bundle)) > store.maxBytes {
		return "", errors.New("bundle size is outside the configured limit")
	}
	canonical, err := schema.CanonicalizeJSON(bundle)
	if err != nil {
		return "", fmt.Errorf("bundle must be strict JSON: %w", err)
	}
	if !bytes.Equal(bundle, canonical) {
		return "", errors.New("bundle must already be RFC8785 canonical JSON")
	}
	record := Record{SchemaVersion: RecordSchema, RunID: runID, BundleDigest: schema.NewDigest(bundle), Bundle: append(json.RawMessage(nil), bundle...)}
	encoded, err := schema.CanonicalMarshal(record)
	if err != nil {
		return "", err
	}
	recordDigest := schema.NewDigest(encoded)
	store.mu.Lock()
	defer store.mu.Unlock()
	directory := filepath.Join(store.root, string(runID))
	if err := createExclusiveDirectory(directory); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", ErrExists
		}
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := writeExclusive(filepath.Join(directory, "record.json"), encoded); err != nil {
		return "", err
	}
	pointer := latestPointer{SchemaVersion: RecordSchema + ":latest", RunID: runID, RecordDigest: recordDigest}
	pointerBytes, err := schema.CanonicalMarshal(pointer)
	if err != nil {
		return "", err
	}
	if err := replaceFile(filepath.Join(store.root, "latest.json"), pointerBytes); err != nil {
		return "", err
	}
	committed = true
	return recordDigest, nil
}

func (store *Store) Resolve(reference string, allowLatest bool) (schema.InstanceID, error) {
	if strings.EqualFold(reference, "latest") {
		if !allowLatest {
			return "", ErrLatestForbidden
		}
		pointer, err := store.readLatest()
		if err != nil {
			return "", err
		}
		return pointer.RunID, nil
	}
	return schema.ParseInstanceID(reference)
}

func (store *Store) Get(reference string, allowLatest bool) (Record, error) {
	if store == nil {
		return Record{}, errors.New("run store is nil")
	}
	runID, err := store.Resolve(reference, allowLatest)
	if err != nil {
		return Record{}, err
	}
	path := filepath.Join(store.root, string(runID), "record.json")
	raw, err := readRegular(path, store.maxBytes)
	if err != nil {
		return Record{}, err
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Record{}, ErrCorrupt
	}
	var record Record
	if err := strictDecode(raw, &record); err != nil {
		return Record{}, ErrCorrupt
	}
	if record.SchemaVersion != RecordSchema || record.RunID != runID || schema.NewDigest(record.Bundle) != record.BundleDigest {
		return Record{}, ErrCorrupt
	}
	bundleCanonical, err := schema.CanonicalizeJSON(record.Bundle)
	if err != nil || !bytes.Equal(record.Bundle, bundleCanonical) {
		return Record{}, ErrCorrupt
	}
	return record, nil
}

func (store *Store) List() ([]schema.InstanceID, error) {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, err
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
	return result, nil
}

func (store *Store) readLatest() (latestPointer, error) {
	raw, err := readRegular(filepath.Join(store.root, "latest.json"), 1<<20)
	if err != nil {
		return latestPointer{}, err
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return latestPointer{}, ErrCorrupt
	}
	var pointer latestPointer
	if err := strictDecode(raw, &pointer); err != nil || pointer.SchemaVersion != RecordSchema+":latest" || pointer.RunID.Validate() != nil || pointer.RecordDigest.Validate() != nil {
		return latestPointer{}, ErrCorrupt
	}
	recordRaw, err := readRegular(filepath.Join(store.root, string(pointer.RunID), "record.json"), store.maxBytes)
	if err != nil || schema.NewDigest(recordRaw) != pointer.RecordDigest {
		return latestPointer{}, ErrCorrupt
	}
	return pointer, nil
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
func createExclusiveDirectory(path string) error { return os.Mkdir(path, 0o700) }
func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func replaceFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".latest-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, ErrCorrupt
	}
	return os.ReadFile(path)
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
