package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// Digest is a lowercase, algorithm-qualified content digest.
type Digest string

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// NewDigest computes a SHA-256 digest over bytes that are already in their
// immutable projection.  Callers that start from JSON should use
// CanonicalDigest instead.
func NewDigest(data []byte) Digest {
	sum := sha256.Sum256(data)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// ParseDigest validates and returns a supported digest.
func ParseDigest(value string) (Digest, error) {
	if !digestPattern.MatchString(value) {
		return "", fmt.Errorf("invalid digest %q: expected sha256 and 64 lowercase hex characters", value)
	}
	return Digest(value), nil
}

// Validate checks the digest syntax and supported algorithm.
func (d Digest) Validate() error {
	if d == "" {
		return errors.New("digest is required")
	}
	_, err := ParseDigest(string(d))
	return err
}
