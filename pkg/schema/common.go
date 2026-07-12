package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	SchemaNamespace = "urn:agentapi-doctor:"
	ExtensionPrefix = "x-"
)

var (
	kindPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{1,63}$`)
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
)

// Producer identifies the exact software artifact that emitted an object.
type Producer struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	ArtifactDigest Digest `json:"artifact_digest"`
}

func (producer Producer) Validate() error {
	if !namePattern.MatchString(producer.Name) {
		return fmt.Errorf("invalid producer name %q", producer.Name)
	}
	if producer.Version == "" {
		return errors.New("producer version is required")
	}
	if err := producer.ArtifactDigest.Validate(); err != nil {
		return fmt.Errorf("producer artifact digest: %w", err)
	}
	return nil
}

// ObjectRef prevents an instance identifier from being rebound to different
// content.  Content-addressed objects omit InstanceID.
type ObjectRef struct {
	Kind          string     `json:"kind"`
	InstanceID    InstanceID `json:"instance_id,omitempty"`
	ContentDigest Digest     `json:"content_digest"`
}

func (ref ObjectRef) Validate() error {
	if !kindPattern.MatchString(ref.Kind) {
		return fmt.Errorf("invalid object kind %q", ref.Kind)
	}
	if ref.InstanceID != "" {
		if err := ref.InstanceID.Validate(); err != nil {
			return fmt.Errorf("object instance ID: %w", err)
		}
	}
	if err := ref.ContentDigest.Validate(); err != nil {
		return fmt.Errorf("object content digest: %w", err)
	}
	return nil
}

// EnvelopeMeta is embedded by immutable public objects. JSON public contracts
// use snake_case; authored YAML resources use apiVersion/kind.
type EnvelopeMeta struct {
	SchemaVersion string                     `json:"schema_version"`
	Kind          string                     `json:"kind"`
	InstanceID    InstanceID                 `json:"instance_id,omitempty"`
	ContentDigest Digest                     `json:"content_digest"`
	ObjectRef     ObjectRef                  `json:"object_ref"`
	Producer      Producer                   `json:"producer"`
	CreatedAt     UTCTime                    `json:"created_at"`
	Extensions    map[string]json.RawMessage `json:"extensions,omitempty"`
}

func (meta EnvelopeMeta) Validate() error {
	if !strings.HasPrefix(meta.SchemaVersion, SchemaNamespace) {
		return fmt.Errorf("schema version %q is outside %s", meta.SchemaVersion, SchemaNamespace)
	}
	if !kindPattern.MatchString(meta.Kind) {
		return fmt.Errorf("invalid kind %q", meta.Kind)
	}
	if meta.InstanceID != "" {
		if err := meta.InstanceID.Validate(); err != nil {
			return fmt.Errorf("instance ID: %w", err)
		}
	}
	if err := meta.ContentDigest.Validate(); err != nil {
		return fmt.Errorf("content digest: %w", err)
	}
	if err := meta.ObjectRef.Validate(); err != nil {
		return err
	}
	if meta.ObjectRef.Kind != meta.Kind || meta.ObjectRef.InstanceID != meta.InstanceID || meta.ObjectRef.ContentDigest != meta.ContentDigest {
		return errors.New("object_ref does not match envelope identity")
	}
	if err := meta.Producer.Validate(); err != nil {
		return err
	}
	if meta.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	for namespace, raw := range meta.Extensions {
		if !strings.HasPrefix(namespace, ExtensionPrefix) || len(namespace) <= len(ExtensionPrefix) {
			return fmt.Errorf("extension namespace %q must start with x-", namespace)
		}
		if len(raw) == 0 || !json.Valid(raw) {
			return fmt.Errorf("extension %q is not valid JSON", namespace)
		}
	}
	return nil
}

// SealMeta computes an object's content digest over a caller-supplied,
// explicitly versioned immutable projection and returns matching envelope
// identity.  The projection must not contain content_digest, object_ref,
// signatures, or Registry-derived fields.
func SealMeta(schemaVersion, kind string, id InstanceID, producer Producer, createdAt UTCTime, projection any) (EnvelopeMeta, error) {
	if !strings.HasPrefix(schemaVersion, SchemaNamespace) {
		return EnvelopeMeta{}, fmt.Errorf("schema version %q is outside %s", schemaVersion, SchemaNamespace)
	}
	if !kindPattern.MatchString(kind) {
		return EnvelopeMeta{}, fmt.Errorf("invalid kind %q", kind)
	}
	if id != "" {
		if err := id.Validate(); err != nil {
			return EnvelopeMeta{}, err
		}
	}
	if err := producer.Validate(); err != nil {
		return EnvelopeMeta{}, err
	}
	if createdAt.IsZero() {
		return EnvelopeMeta{}, errors.New("created_at is required")
	}
	digest, err := CanonicalDigest(projection)
	if err != nil {
		return EnvelopeMeta{}, fmt.Errorf("digest immutable projection: %w", err)
	}
	return EnvelopeMeta{
		SchemaVersion: schemaVersion,
		Kind:          kind,
		InstanceID:    id,
		ContentDigest: digest,
		ObjectRef:     ObjectRef{Kind: kind, InstanceID: id, ContentDigest: digest},
		Producer:      producer,
		CreatedAt:     createdAt,
	}, nil
}
