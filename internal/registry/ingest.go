package registry

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type IngestStatus string

const (
	IngestPrepared    IngestStatus = "prepared"
	IngestStaged      IngestStatus = "staged"
	IngestCommitted   IngestStatus = "committed"
	IngestValidating  IngestStatus = "validating"
	IngestQuarantined IngestStatus = "quarantined"
	IngestPublished   IngestStatus = "published"
)

type IngestSnapshot struct {
	SessionID       schema.InstanceID
	Owner           PrincipalID
	ExpectedDigest  schema.Digest
	StagedDigest    schema.Digest
	ExpiresAt       time.Time
	Status          IngestStatus
	QuarantineClass string
}

// IngestSession is the concurrency-safe domain state for two-phase upload.
// Owner, expiry and expected digest are fixed at prepare time.
type IngestSession struct {
	mu              sync.Mutex
	sessionID       schema.InstanceID
	owner           PrincipalID
	expectedDigest  schema.Digest
	stagedDigest    schema.Digest
	expiresAt       time.Time
	status          IngestStatus
	quarantineClass string
}

// RestoreIngest reconstructs previously validated durable state. It is used
// only by Registry stores and applies stricter lifecycle consistency checks
// than ordinary JSON decoding.
func RestoreIngest(snapshot IngestSnapshot) (*IngestSession, error) {
	if err := snapshot.SessionID.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Owner.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.ExpectedDigest.Validate(); err != nil {
		return nil, err
	}
	if snapshot.ExpiresAt.IsZero() {
		return nil, errors.New("ingest expiry is required")
	}
	valid := snapshot.Status == IngestPrepared || snapshot.Status == IngestStaged || snapshot.Status == IngestCommitted || snapshot.Status == IngestValidating || snapshot.Status == IngestQuarantined || snapshot.Status == IngestPublished
	if !valid {
		return nil, fmt.Errorf("invalid ingest status %q", snapshot.Status)
	}
	if snapshot.Status == IngestPrepared {
		if snapshot.StagedDigest != "" || snapshot.QuarantineClass != "" {
			return nil, errors.New("prepared ingest contains later lifecycle fields")
		}
	} else if err := snapshot.StagedDigest.Validate(); err != nil {
		return nil, errors.New("non-prepared ingest requires staged digest")
	}
	if snapshot.Status == IngestQuarantined {
		if err := validateReason(snapshot.QuarantineClass); err != nil {
			return nil, err
		}
	} else if snapshot.QuarantineClass != "" {
		return nil, errors.New("only quarantined ingest may have a quarantine class")
	}
	return &IngestSession{sessionID: snapshot.SessionID, owner: snapshot.Owner, expectedDigest: snapshot.ExpectedDigest, stagedDigest: snapshot.StagedDigest, expiresAt: snapshot.ExpiresAt.UTC(), status: snapshot.Status, quarantineClass: snapshot.QuarantineClass}, nil
}

func PrepareIngest(
	principal Principal,
	sessionID schema.InstanceID,
	expectedDigest schema.Digest,
	expiresAt time.Time,
	now time.Time,
) (*IngestSession, error) {
	if err := principal.RequireScope(ScopeObservationPrepare); err != nil {
		return nil, err
	}
	if err := sessionID.Validate(); err != nil {
		return nil, fmt.Errorf("session ID: %w", err)
	}
	if err := expectedDigest.Validate(); err != nil {
		return nil, fmt.Errorf("expected digest: %w", err)
	}
	if now.IsZero() {
		return nil, errors.New("prepare time is required")
	}
	if !expiresAt.After(now) {
		return nil, errors.New("ingest expiry must be after prepare time")
	}
	return &IngestSession{
		sessionID:      sessionID,
		owner:          principal.ID(),
		expectedDigest: expectedDigest,
		expiresAt:      expiresAt.UTC(),
		status:         IngestPrepared,
	}, nil
}

func (session *IngestSession) Snapshot() IngestSnapshot {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.snapshotLocked()
}

func (session *IngestSession) snapshotLocked() IngestSnapshot {
	return IngestSnapshot{
		SessionID:       session.sessionID,
		Owner:           session.owner,
		ExpectedDigest:  session.expectedDigest,
		StagedDigest:    session.stagedDigest,
		ExpiresAt:       session.expiresAt,
		Status:          session.status,
		QuarantineClass: session.quarantineClass,
	}
}

func (session *IngestSession) Stage(principal Principal, digest schema.Digest, now time.Time) (IngestSnapshot, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := authorizeOwned(principal, session.owner, ScopeObservationPrepare); err != nil {
		return session.snapshotLocked(), err
	}
	if digest != session.expectedDigest {
		return session.snapshotLocked(), ErrDigestMismatch
	}
	if session.status == IngestStaged && session.stagedDigest == digest {
		return session.snapshotLocked(), nil
	}
	if session.status != IngestPrepared {
		return session.snapshotLocked(), transitionError(session.status, IngestStaged)
	}
	if expired(now, session.expiresAt) {
		return session.snapshotLocked(), ErrExpired
	}
	session.stagedDigest = digest
	session.status = IngestStaged
	return session.snapshotLocked(), nil
}

// Commit is idempotent for the owner and exact prepared digest.  Once a
// commit has succeeded, replaying it remains successful even if the upload
// session subsequently expires or validation advances.
func (session *IngestSession) Commit(principal Principal, digest schema.Digest, now time.Time) (IngestSnapshot, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := authorizeOwned(principal, session.owner, ScopeObservationCommit); err != nil {
		return session.snapshotLocked(), err
	}
	if digest != session.expectedDigest || (session.stagedDigest != "" && digest != session.stagedDigest) {
		return session.snapshotLocked(), ErrDigestMismatch
	}
	switch session.status {
	case IngestCommitted, IngestValidating, IngestQuarantined, IngestPublished:
		return session.snapshotLocked(), nil
	case IngestStaged:
		if expired(now, session.expiresAt) {
			return session.snapshotLocked(), ErrExpired
		}
		session.status = IngestCommitted
		return session.snapshotLocked(), nil
	default:
		return session.snapshotLocked(), transitionError(session.status, IngestCommitted)
	}
}

// BeginValidation is called only by the isolated verifier service, not by a
// submitter-controlled request.  It is idempotent under at-least-once queue
// delivery.
func (session *IngestSession) BeginValidation() (IngestSnapshot, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	switch session.status {
	case IngestCommitted:
		session.status = IngestValidating
		return session.snapshotLocked(), nil
	case IngestValidating:
		return session.snapshotLocked(), nil
	default:
		return session.snapshotLocked(), transitionError(session.status, IngestValidating)
	}
}

func (session *IngestSession) Publish() (IngestSnapshot, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	switch session.status {
	case IngestValidating:
		session.status = IngestPublished
		return session.snapshotLocked(), nil
	case IngestPublished:
		return session.snapshotLocked(), nil
	default:
		return session.snapshotLocked(), transitionError(session.status, IngestPublished)
	}
}

func (session *IngestSession) Quarantine(reasonClass string) (IngestSnapshot, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := validateReason(reasonClass); err != nil {
		return session.snapshotLocked(), err
	}
	switch session.status {
	case IngestValidating:
		session.status = IngestQuarantined
		session.quarantineClass = reasonClass
		return session.snapshotLocked(), nil
	case IngestQuarantined:
		if session.quarantineClass == reasonClass {
			return session.snapshotLocked(), nil
		}
		return session.snapshotLocked(), ErrConflict
	default:
		return session.snapshotLocked(), transitionError(session.status, IngestQuarantined)
	}
}

func expired(now, expiresAt time.Time) bool {
	return now.IsZero() || !now.Before(expiresAt)
}

func transitionError(from, to IngestStatus) error {
	return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
}
