// Package store defines persistence boundaries for the Registry HTTP layer.
// The in-memory implementation is intentionally ephemeral and is intended
// for offline tests and explicitly enabled local development only.
package store

import (
	"context"
	"errors"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

var (
	ErrNotFound       = errors.New("registry store object not found")
	ErrAlreadyExists  = errors.New("registry store object already exists")
	ErrTokenExpired   = errors.New("registry bearer token expired")
	ErrInvalidCursor  = errors.New("registry list cursor is invalid")
	ErrNotImplemented = errors.New("registry persistent hosted capability is not implemented")
)

type Capabilities struct {
	DurablePersistence    bool `json:"durable_persistence"`
	HostedVerification    bool `json:"hosted_verification"`
	OwnershipVerification bool `json:"ownership_verification"`
}

type IngestRecord struct {
	Session       *domain.IngestSession
	DeclaredBytes int64
	UploadDigest  schema.Digest
	ChallengeHash [32]byte
}

type ObservationFilter struct {
	Subject string
	Version string
	Pack    string
	Profile string
	Trust   string
	Fresh   string
}

type ObservationPage struct {
	Items      []registryapi.Observation
	NextCursor string
}

type ObservationIndex struct {
	Subject     string
	Version     string
	Pack        string
	PackVersion string
	Profile     string
	TrustLabels []string
	Freshness   string
}

type ArtifactKind string

const (
	ArtifactPack    ArtifactKind = "pack"
	ArtifactProfile ArtifactKind = "profile"
)

type Artifact struct {
	Kind     ArtifactKind  `json:"kind"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Digest   schema.Digest `json:"digest"`
	Document []byte        `json:"-"`
}

type Store interface {
	Capabilities() Capabilities
	LookupBearerToken(context.Context, [32]byte, time.Time) (domain.Principal, error)

	CreateIngest(context.Context, IngestRecord) error
	GetIngest(context.Context, schema.InstanceID) (IngestRecord, error)
	UpdateIngest(context.Context, IngestRecord) error
	PutStagedObservation(context.Context, schema.InstanceID, registryapi.Observation) error
	GetStagedObservation(context.Context, schema.InstanceID) (registryapi.Observation, error)
	EnqueueVerification(context.Context, schema.InstanceID) error

	PutPublishedObservation(context.Context, registryapi.Observation) error
	GetObservation(context.Context, schema.Digest) (registryapi.Observation, error)
	ListObservations(context.Context, ObservationFilter, string, int) (ObservationPage, error)

	PutOwnershipChallenge(context.Context, *domain.OwnershipChallenge) error
	PutOwnership(context.Context, *domain.Ownership) error
	CurrentOwnership(context.Context, domain.SubjectNamespace, time.Time) (*domain.Ownership, error)

	PutDispute(context.Context, *domain.Dispute) error
	GetDispute(context.Context, schema.InstanceID) (*domain.Dispute, error)

	GetArtifact(context.Context, ArtifactKind, string, string) (Artifact, error)
}
