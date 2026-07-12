// Package cas implements an immutable local content-addressed store for
// sanitized evidence.  It deliberately cannot accept arbitrary raw bytes.
package cas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const DefaultMaxObjectBytes int64 = 256 << 20

var ErrCorruptObject = errors.New("CAS object digest mismatch")

type Store struct {
	root           string
	maxObjectBytes int64
}

func Open(root string, maxObjectBytes int64) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("CAS root must be an absolute path")
	}
	if maxObjectBytes <= 0 {
		maxObjectBytes = DefaultMaxObjectBytes
	}
	clean := filepath.Clean(root)
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create CAS root: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("stat CAS root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("CAS root must be a non-symlink directory")
	}
	return &Store{root: clean, maxObjectBytes: maxObjectBytes}, nil
}

func (store *Store) Put(ctx context.Context, payload redaction.SanitizedPayload) (schema.ObjectRef, error) {
	if err := ctx.Err(); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("create CAS shard: %w", err)
	}
	if existing, err := store.readVerified(path, digest); err == nil {
		zero(existing)
		return schema.ObjectRef{Kind: "Payload", ContentDigest: digest}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return schema.ObjectRef{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".put-*")
	if err != nil {
		return schema.ObjectRef{}, fmt.Errorf("create CAS temporary object: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return schema.ObjectRef{}, fmt.Errorf("set CAS object permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return schema.ObjectRef{}, fmt.Errorf("write CAS object: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return schema.ObjectRef{}, fmt.Errorf("sync CAS object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("close CAS object: %w", err)
	}
	if err := os.Link(temporaryName, path); err != nil {
		if !os.IsExist(err) {
			return schema.ObjectRef{}, fmt.Errorf("commit immutable CAS object: %w", err)
		}
		if existing, verifyErr := store.readVerified(path, digest); verifyErr != nil {
			return schema.ObjectRef{}, verifyErr
		} else {
			zero(existing)
		}
	}
	committed = true
	if err := os.Remove(temporaryName); err != nil {
		return schema.ObjectRef{}, fmt.Errorf("remove CAS temporary object: %w", err)
	}
	return schema.ObjectRef{Kind: "Payload", ContentDigest: digest}, nil
}

func (store *Store) Get(ctx context.Context, digest schema.Digest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
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

func (store *Store) objectPath(digest schema.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}
	hexDigest := strings.TrimPrefix(string(digest), "sha256:")
	return filepath.Join(store.root, "sha256", hexDigest[:2], hexDigest[2:]), nil
}

func (store *Store) readVerified(path string, expected schema.Digest) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("CAS object must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > store.maxObjectBytes {
		return nil, errors.New("CAS object size is outside the configured limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	limited := io.LimitReader(file, store.maxObjectBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > store.maxObjectBytes {
		zero(data)
		return nil, errors.New("CAS object exceeded the configured limit")
	}
	sum := sha256.Sum256(data)
	actual := schema.Digest("sha256:" + hex.EncodeToString(sum[:]))
	if actual != expected {
		zero(data)
		return nil, ErrCorruptObject
	}
	return data, nil
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
