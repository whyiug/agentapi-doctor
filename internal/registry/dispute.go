package registry

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func validateReason(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 4096 {
		return errors.New("reason must be 1..4096 non-whitespace bytes")
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			return errors.New("reason contains a forbidden control character")
		}
	}
	return nil
}

type DisputeStatus string

const (
	DisputeOpened      DisputeStatus = "opened"
	DisputeUnderReview DisputeStatus = "under_review"
	DisputeResolved    DisputeStatus = "resolved"
	DisputeSuperseded  DisputeStatus = "superseded"
)

type DisputeEventKind string

const (
	DisputeEventOpened        DisputeEventKind = "opened"
	DisputeEventOwnerResponse DisputeEventKind = "owner_response"
	DisputeEventReviewStarted DisputeEventKind = "review_started"
	DisputeEventResolved      DisputeEventKind = "resolved"
	DisputeEventSuperseded    DisputeEventKind = "superseded"
)

type DisputeEvent struct {
	Sequence      uint64
	Kind          DisputeEventKind
	Actor         PrincipalID
	At            time.Time
	Statement     string
	ReplacementID schema.Digest
}

type DisputeSnapshot struct {
	ID            schema.InstanceID
	ObservationID schema.Digest
	Subject       SubjectNamespace
	Creator       PrincipalID
	SubjectOwner  PrincipalID
	Reviewer      PrincipalID
	Status        DisputeStatus
	Events        []DisputeEvent
}

type Dispute struct {
	mu            sync.Mutex
	id            schema.InstanceID
	observationID schema.Digest
	subject       SubjectNamespace
	creator       PrincipalID
	subjectOwner  PrincipalID
	reviewer      PrincipalID
	status        DisputeStatus
	events        []DisputeEvent
}

func RestoreDispute(snapshot DisputeSnapshot) (*Dispute, error) {
	if err := snapshot.ID.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.ObservationID.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Subject.Validate(); err != nil {
		return nil, err
	}
	for _, id := range []PrincipalID{snapshot.Creator, snapshot.SubjectOwner} {
		if err := id.Validate(); err != nil {
			return nil, err
		}
	}
	if snapshot.Status != DisputeOpened && snapshot.Status != DisputeUnderReview && snapshot.Status != DisputeResolved && snapshot.Status != DisputeSuperseded {
		return nil, errors.New("invalid dispute status")
	}
	if snapshot.Status != DisputeOpened {
		if err := snapshot.Reviewer.Validate(); err != nil {
			return nil, errors.New("reviewed dispute requires reviewer")
		}
	}
	if len(snapshot.Events) == 0 {
		return nil, errors.New("dispute event journal is empty")
	}
	previous := time.Time{}
	for index, event := range snapshot.Events {
		if event.Sequence != uint64(index+1) || event.At.IsZero() || event.At.Before(previous) {
			return nil, errors.New("dispute event sequence or time is invalid")
		}
		if err := event.Actor.Validate(); err != nil {
			return nil, err
		}
		if err := validateReason(event.Statement); err != nil {
			return nil, err
		}
		switch event.Kind {
		case DisputeEventOpened, DisputeEventOwnerResponse, DisputeEventReviewStarted, DisputeEventResolved:
			if event.ReplacementID != "" {
				return nil, errors.New("unexpected replacement ID")
			}
		case DisputeEventSuperseded:
			if err := event.ReplacementID.Validate(); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("invalid dispute event kind")
		}
		previous = event.At
	}
	if snapshot.Events[0].Kind != DisputeEventOpened || snapshot.Events[0].Actor != snapshot.Creator {
		return nil, errors.New("dispute journal must start with creator open event")
	}
	events := append([]DisputeEvent(nil), snapshot.Events...)
	return &Dispute{id: snapshot.ID, observationID: snapshot.ObservationID, subject: snapshot.Subject, creator: snapshot.Creator, subjectOwner: snapshot.SubjectOwner, reviewer: snapshot.Reviewer, status: snapshot.Status, events: events}, nil
}

func NewDispute(
	principal Principal,
	id schema.InstanceID,
	observationID schema.Digest,
	subject SubjectNamespace,
	subjectOwner PrincipalID,
	statement string,
	now time.Time,
) (*Dispute, error) {
	if err := principal.RequireScope(ScopeDisputeCreate); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("dispute ID: %w", err)
	}
	if err := observationID.Validate(); err != nil {
		return nil, fmt.Errorf("observation ID: %w", err)
	}
	if err := subject.Validate(); err != nil {
		return nil, err
	}
	if err := subjectOwner.Validate(); err != nil {
		return nil, fmt.Errorf("subject owner: %w", err)
	}
	if err := validateReason(statement); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("dispute creation time is required")
	}
	dispute := &Dispute{
		id:            id,
		observationID: observationID,
		subject:       subject,
		creator:       principal.ID(),
		subjectOwner:  subjectOwner,
		status:        DisputeOpened,
	}
	dispute.appendEventLocked(DisputeEventOpened, principal.ID(), statement, "", now)
	return dispute, nil
}

func (dispute *Dispute) Snapshot() DisputeSnapshot {
	dispute.mu.Lock()
	defer dispute.mu.Unlock()
	events := make([]DisputeEvent, len(dispute.events))
	copy(events, dispute.events)
	return DisputeSnapshot{
		ID:            dispute.id,
		ObservationID: dispute.observationID,
		Subject:       dispute.subject,
		Creator:       dispute.creator,
		SubjectOwner:  dispute.subjectOwner,
		Reviewer:      dispute.reviewer,
		Status:        dispute.status,
		Events:        events,
	}
}

func (dispute *Dispute) AddOwnerResponse(
	principal Principal,
	ownership *Ownership,
	statement string,
	now time.Time,
) (DisputeSnapshot, error) {
	if now.IsZero() {
		return dispute.Snapshot(), errors.New("owner response time is required")
	}
	if err := principal.RequireScope(ScopeDisputeCreate); err != nil {
		return dispute.Snapshot(), err
	}
	if err := ownership.AuthorizeManage(principal, now); err != nil {
		return dispute.Snapshot(), err
	}
	ownershipSnapshot := ownership.Snapshot()
	if ownershipSnapshot.Subject != dispute.subject || ownershipSnapshot.Owner != dispute.subjectOwner {
		return dispute.Snapshot(), ErrNotOwner
	}
	if err := validateReason(statement); err != nil {
		return dispute.Snapshot(), err
	}
	dispute.mu.Lock()
	defer dispute.mu.Unlock()
	if dispute.status != DisputeOpened && dispute.status != DisputeUnderReview {
		return dispute.snapshotLocked(), ErrInvalidTransition
	}
	dispute.appendEventLocked(DisputeEventOwnerResponse, principal.ID(), statement, "", now)
	return dispute.snapshotLocked(), nil
}

func (dispute *Dispute) BeginReview(principal Principal, now time.Time) (DisputeSnapshot, error) {
	dispute.mu.Lock()
	defer dispute.mu.Unlock()
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return dispute.snapshotLocked(), err
	}
	if principal.ID() == dispute.creator || principal.ID() == dispute.subjectOwner {
		return dispute.snapshotLocked(), fmt.Errorf("%w: dispute reviewer has a direct conflict of interest", ErrForbidden)
	}
	if dispute.status == DisputeUnderReview && dispute.reviewer == principal.ID() {
		return dispute.snapshotLocked(), nil
	}
	if dispute.status != DisputeOpened {
		return dispute.snapshotLocked(), ErrInvalidTransition
	}
	if now.IsZero() {
		return dispute.snapshotLocked(), errors.New("review time is required")
	}
	dispute.reviewer = principal.ID()
	dispute.status = DisputeUnderReview
	dispute.appendEventLocked(DisputeEventReviewStarted, principal.ID(), "review_started", "", now)
	return dispute.snapshotLocked(), nil
}

func (dispute *Dispute) Resolve(principal Principal, resolution string, now time.Time) (DisputeSnapshot, error) {
	dispute.mu.Lock()
	defer dispute.mu.Unlock()
	if err := dispute.authorizeReviewerLocked(principal); err != nil {
		return dispute.snapshotLocked(), err
	}
	if err := validateReason(resolution); err != nil {
		return dispute.snapshotLocked(), err
	}
	if now.IsZero() {
		return dispute.snapshotLocked(), errors.New("resolution time is required")
	}
	if dispute.status != DisputeUnderReview {
		return dispute.snapshotLocked(), ErrInvalidTransition
	}
	dispute.status = DisputeResolved
	dispute.appendEventLocked(DisputeEventResolved, principal.ID(), resolution, "", now)
	return dispute.snapshotLocked(), nil
}

func (dispute *Dispute) Supersede(
	principal Principal,
	replacementID schema.Digest,
	reason string,
	now time.Time,
) (DisputeSnapshot, error) {
	dispute.mu.Lock()
	defer dispute.mu.Unlock()
	if err := dispute.authorizeReviewerLocked(principal); err != nil {
		return dispute.snapshotLocked(), err
	}
	if err := replacementID.Validate(); err != nil {
		return dispute.snapshotLocked(), fmt.Errorf("replacement observation: %w", err)
	}
	if replacementID == dispute.observationID {
		return dispute.snapshotLocked(), errors.New("replacement observation must differ from original")
	}
	if err := validateReason(reason); err != nil {
		return dispute.snapshotLocked(), err
	}
	if now.IsZero() {
		return dispute.snapshotLocked(), errors.New("supersession time is required")
	}
	if dispute.status != DisputeUnderReview {
		return dispute.snapshotLocked(), ErrInvalidTransition
	}
	dispute.status = DisputeSuperseded
	dispute.appendEventLocked(DisputeEventSuperseded, principal.ID(), reason, replacementID, now)
	return dispute.snapshotLocked(), nil
}

func (dispute *Dispute) authorizeReviewerLocked(principal Principal) error {
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return err
	}
	if principal.ID() != dispute.reviewer {
		return fmt.Errorf("%w: only the assigned independent reviewer may resolve the dispute", ErrForbidden)
	}
	return nil
}

func (dispute *Dispute) appendEventLocked(
	kind DisputeEventKind,
	actor PrincipalID,
	statement string,
	replacementID schema.Digest,
	now time.Time,
) {
	dispute.events = append(dispute.events, DisputeEvent{
		Sequence:      uint64(len(dispute.events) + 1),
		Kind:          kind,
		Actor:         actor,
		At:            now.UTC(),
		Statement:     statement,
		ReplacementID: replacementID,
	})
}

func (dispute *Dispute) snapshotLocked() DisputeSnapshot {
	events := make([]DisputeEvent, len(dispute.events))
	copy(events, dispute.events)
	return DisputeSnapshot{
		ID:            dispute.id,
		ObservationID: dispute.observationID,
		Subject:       dispute.subject,
		Creator:       dispute.creator,
		SubjectOwner:  dispute.subjectOwner,
		Reviewer:      dispute.reviewer,
		Status:        dispute.status,
		Events:        events,
	}
}

type Supersession struct {
	OriginalID    schema.Digest
	ReplacementID schema.Digest
	Reason        string
	Actor         PrincipalID
	CreatedAt     time.Time
}

func NewSupersession(
	principal Principal,
	originalID, replacementID schema.Digest,
	reason string,
	now time.Time,
) (Supersession, error) {
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return Supersession{}, err
	}
	if err := originalID.Validate(); err != nil {
		return Supersession{}, fmt.Errorf("original observation: %w", err)
	}
	if err := replacementID.Validate(); err != nil {
		return Supersession{}, fmt.Errorf("replacement observation: %w", err)
	}
	if originalID == replacementID {
		return Supersession{}, errors.New("supersession requires different observations")
	}
	if err := validateReason(reason); err != nil {
		return Supersession{}, err
	}
	if now.IsZero() {
		return Supersession{}, errors.New("supersession time is required")
	}
	return Supersession{
		OriginalID:    originalID,
		ReplacementID: replacementID,
		Reason:        reason,
		Actor:         principal.ID(),
		CreatedAt:     now.UTC(),
	}, nil
}

type Tombstone struct {
	ObservationID schema.Digest
	Reason        string
	Actor         PrincipalID
	CreatedAt     time.Time
}

func NewTombstone(principal Principal, observationID schema.Digest, reason string, now time.Time) (Tombstone, error) {
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return Tombstone{}, err
	}
	if err := observationID.Validate(); err != nil {
		return Tombstone{}, fmt.Errorf("observation ID: %w", err)
	}
	if err := validateReason(reason); err != nil {
		return Tombstone{}, err
	}
	if now.IsZero() {
		return Tombstone{}, errors.New("tombstone time is required")
	}
	return Tombstone{
		ObservationID: observationID,
		Reason:        reason,
		Actor:         principal.ID(),
		CreatedAt:     now.UTC(),
	}, nil
}
