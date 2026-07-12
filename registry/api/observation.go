package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const ObservationSchemaV1 = "urn:agentapi-doctor:observation:v1"

// CanonicalObject is an RFC 8785 JSON object.  Its byte slice is private so a
// caller cannot mutate an Observation's signed projection through an alias.
type CanonicalObject struct {
	canonical []byte
}

// ParseCanonicalObject rejects ambiguous JSON before retaining canonical
// bytes.  Observation sections are objects, not arbitrary JSON values.
func ParseCanonicalObject(raw []byte) (CanonicalObject, error) {
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		return CanonicalObject{}, err
	}
	if len(canonical) == 0 || canonical[0] != '{' {
		return CanonicalObject{}, errors.New("observation section must be a JSON object")
	}
	return CanonicalObject{canonical: bytes.Clone(canonical)}, nil
}

func (object CanonicalObject) IsZero() bool { return len(object.canonical) == 0 }

// Bytes returns a defensive copy of the canonical representation.
func (object CanonicalObject) Bytes() []byte { return bytes.Clone(object.canonical) }

func (object CanonicalObject) Equal(other CanonicalObject) bool {
	return bytes.Equal(object.canonical, other.canonical)
}

func (object CanonicalObject) MarshalJSON() ([]byte, error) {
	if object.IsZero() {
		return nil, errors.New("canonical JSON object is required")
	}
	return object.Bytes(), nil
}

func (object *CanonicalObject) UnmarshalJSON(raw []byte) error {
	if object == nil {
		return errors.New("cannot unmarshal canonical object into nil receiver")
	}
	parsed, err := ParseCanonicalObject(raw)
	if err != nil {
		return err
	}
	*object = parsed
	return nil
}

// ObservationProjection is the complete v1 observation_id input.  IDs,
// signatures, attestations, trust/freshness, publication time, disputes and
// correction relations deliberately live outside this structure.
type ObservationProjection struct {
	SchemaVersion  string          `json:"schema_version"`
	Subject        CanonicalObject `json:"subject"`
	Test           CanonicalObject `json:"test"`
	Environment    CanonicalObject `json:"environment"`
	Result         CanonicalObject `json:"result"`
	ManifestDigest schema.Digest   `json:"manifest_digest"`
}

func (projection ObservationProjection) Validate() error {
	if projection.SchemaVersion != ObservationSchemaV1 {
		return fmt.Errorf("unsupported observation schema %q", projection.SchemaVersion)
	}
	for name, object := range map[string]CanonicalObject{
		"subject":     projection.Subject,
		"test":        projection.Test,
		"environment": projection.Environment,
		"result":      projection.Result,
	} {
		if object.IsZero() {
			return fmt.Errorf("%s is required", name)
		}
	}
	if err := projection.ManifestDigest.Validate(); err != nil {
		return fmt.Errorf("manifest digest: %w", err)
	}
	return nil
}

// Digest computes observation_id over the immutable projection only.
func (projection ObservationProjection) Digest() (schema.Digest, error) {
	if err := projection.Validate(); err != nil {
		return "", err
	}
	return schema.CanonicalDigest(projection)
}

type AttestationReference struct {
	Digest schema.Digest `json:"digest"`
	URI    string        `json:"uri,omitempty"`
}

func (reference AttestationReference) validate() error {
	if err := reference.Digest.Validate(); err != nil {
		return fmt.Errorf("attestation digest: %w", err)
	}
	if strings.ContainsAny(reference.URI, "\r\n\x00") {
		return errors.New("attestation URI contains a control character")
	}
	return nil
}

type Freshness string

const (
	FreshnessUnknown Freshness = "unknown"
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
)

// RegistryDerived contains mutable interpretations and publication metadata.
// None of these fields participate in observation_id.
type RegistryDerived struct {
	TrustLabels  []string        `json:"trust_labels,omitempty"`
	Freshness    Freshness       `json:"freshness,omitempty"`
	PublishedAt  *schema.UTCTime `json:"published_at,omitempty"`
	DisputeIDs   []string        `json:"dispute_ids,omitempty"`
	SupersededBy schema.Digest   `json:"superseded_by,omitempty"`
	Tombstoned   bool            `json:"tombstoned,omitempty"`
}

func (derived RegistryDerived) clone() RegistryDerived {
	clone := derived
	clone.TrustLabels = slices.Clone(derived.TrustLabels)
	clone.DisputeIDs = slices.Clone(derived.DisputeIDs)
	if derived.PublishedAt != nil {
		published := *derived.PublishedAt
		clone.PublishedAt = &published
	}
	return clone
}

func (derived RegistryDerived) validate() error {
	switch derived.Freshness {
	case "", FreshnessUnknown, FreshnessFresh, FreshnessStale:
	default:
		return fmt.Errorf("invalid freshness %q", derived.Freshness)
	}
	if derived.PublishedAt != nil && derived.PublishedAt.IsZero() {
		return errors.New("published_at cannot be zero")
	}
	if derived.SupersededBy != "" {
		if err := derived.SupersededBy.Validate(); err != nil {
			return fmt.Errorf("superseded_by: %w", err)
		}
	}
	if err := validateUniqueNonempty("trust label", derived.TrustLabels); err != nil {
		return err
	}
	if err := validateUniqueNonempty("dispute ID", derived.DisputeIDs); err != nil {
		return err
	}
	return nil
}

func validateUniqueNonempty(kind string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s cannot be empty", kind)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate %s %q", kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// Observation binds an immutable projection to its content-derived ID while
// permitting append-only provenance and recomputable Registry metadata to
// evolve independently.
type Observation struct {
	id              schema.Digest
	classID         schema.Digest
	projection      ObservationProjection
	attestations    []AttestationReference
	registryDerived RegistryDerived
}

func NewObservation(
	projection ObservationProjection,
	classID schema.Digest,
	attestations []AttestationReference,
	derived RegistryDerived,
) (Observation, error) {
	id, err := projection.Digest()
	if err != nil {
		return Observation{}, err
	}
	observation := Observation{
		id:              id,
		classID:         classID,
		projection:      projection,
		attestations:    slices.Clone(attestations),
		registryDerived: derived.clone(),
	}
	if err := observation.Validate(); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func (observation Observation) ID() schema.Digest      { return observation.id }
func (observation Observation) ClassID() schema.Digest { return observation.classID }
func (observation Observation) Projection() ObservationProjection {
	return observation.projection
}
func (observation Observation) Attestations() []AttestationReference {
	return slices.Clone(observation.attestations)
}
func (observation Observation) RegistryDerived() RegistryDerived {
	return observation.registryDerived.clone()
}

// WithAttestation appends provenance without replacing previously recorded
// attestations.  Exact duplicates are rejected by Validate.
func (observation Observation) WithAttestation(reference AttestationReference) (Observation, error) {
	attestations := append(observation.Attestations(), reference)
	return NewObservation(observation.projection, observation.classID, attestations, observation.registryDerived)
}

// WithRegistryDerived returns a new derived view while preserving immutable
// content and all append-only provenance.
func (observation Observation) WithRegistryDerived(derived RegistryDerived) (Observation, error) {
	return NewObservation(observation.projection, observation.classID, observation.attestations, derived)
}

func (observation Observation) Validate() error {
	if err := observation.classID.Validate(); err != nil {
		return fmt.Errorf("observation class ID: %w", err)
	}
	want, err := observation.projection.Digest()
	if err != nil {
		return err
	}
	if observation.id != want {
		return fmt.Errorf("observation ID mismatch: got %s, want %s", observation.id, want)
	}
	seen := make(map[schema.Digest]struct{}, len(observation.attestations))
	for _, reference := range observation.attestations {
		if err := reference.validate(); err != nil {
			return err
		}
		if _, exists := seen[reference.Digest]; exists {
			return fmt.Errorf("duplicate attestation %s", reference.Digest)
		}
		seen[reference.Digest] = struct{}{}
	}
	return observation.registryDerived.validate()
}

type observationWire struct {
	SchemaVersion      string                 `json:"schema_version"`
	ObservationID      schema.Digest          `json:"observation_id"`
	ObservationClassID schema.Digest          `json:"observation_class_id"`
	Subject            CanonicalObject        `json:"subject"`
	Test               CanonicalObject        `json:"test"`
	Environment        CanonicalObject        `json:"environment"`
	Result             CanonicalObject        `json:"result"`
	ManifestDigest     schema.Digest          `json:"manifest_digest"`
	Provenance         []AttestationReference `json:"provenance,omitempty"`
	RegistryDerived    RegistryDerived        `json:"registry_derived,omitempty"`
}

func (observation Observation) MarshalJSON() ([]byte, error) {
	if err := observation.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(observationWire{
		SchemaVersion:      observation.projection.SchemaVersion,
		ObservationID:      observation.id,
		ObservationClassID: observation.classID,
		Subject:            observation.projection.Subject,
		Test:               observation.projection.Test,
		Environment:        observation.projection.Environment,
		Result:             observation.projection.Result,
		ManifestDigest:     observation.projection.ManifestDigest,
		Provenance:         observation.attestations,
		RegistryDerived:    observation.registryDerived,
	})
}

func (observation *Observation) UnmarshalJSON(raw []byte) error {
	if observation == nil {
		return errors.New("cannot unmarshal observation into nil receiver")
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		return fmt.Errorf("validate observation JSON: %w", err)
	}
	var wire observationWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return err
	}
	parsed, err := NewObservation(ObservationProjection{
		SchemaVersion:  wire.SchemaVersion,
		Subject:        wire.Subject,
		Test:           wire.Test,
		Environment:    wire.Environment,
		Result:         wire.Result,
		ManifestDigest: wire.ManifestDigest,
	}, wire.ObservationClassID, wire.Provenance, wire.RegistryDerived)
	if err != nil {
		return err
	}
	if wire.ObservationID != parsed.ID() {
		return fmt.Errorf("observation ID mismatch: got %s, want %s", wire.ObservationID, parsed.ID())
	}
	*observation = parsed
	return nil
}
