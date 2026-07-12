package registry

import (
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const ActiveStorePurgeTarget = 24 * time.Hour

type PurgeReason string

const (
	PurgeSecret       PurgeReason = "secret"
	PurgePII          PurgeReason = "pii"
	PurgeUnlawful     PurgeReason = "unlawful_content"
	PurgeUnauthorized PurgeReason = "unauthorized_submission"
)

func (reason PurgeReason) validate() error {
	switch reason {
	case PurgeSecret, PurgePII, PurgeUnlawful, PurgeUnauthorized:
		return nil
	default:
		return fmt.Errorf("invalid sensitive purge reason %q", reason)
	}
}

type PurgeTarget string

const (
	PurgeObjectStore PurgeTarget = "object_store"
	PurgeCDN         PurgeTarget = "cdn"
	PurgeSearch      PurgeTarget = "search"
	PurgeCache       PurgeTarget = "cache"
	PurgePublicPage  PurgeTarget = "public_page"
)

var allPurgeTargets = []PurgeTarget{
	PurgeObjectStore,
	PurgeCDN,
	PurgeSearch,
	PurgeCache,
	PurgePublicPage,
}

type PurgeTargetStatus string

const (
	PurgeTargetPending       PurgeTargetStatus = "pending"
	PurgeTargetPurged        PurgeTargetStatus = "purged"
	PurgeTargetNotApplicable PurgeTargetStatus = "not_applicable"
)

type PurgeStatus string

const (
	PurgeRequested  PurgeStatus = "requested"
	PurgeInProgress PurgeStatus = "in_progress"
	PurgeCompleted  PurgeStatus = "completed"
)

type PurgeEvent struct {
	Sequence uint64
	Actor    PrincipalID
	Action   string
	Target   PurgeTarget
	At       time.Time
}

// PurgeSnapshot is safe for a restricted audit log: it intentionally has no
// content digest, blob key, URL, or hash of material being removed.
type PurgeSnapshot struct {
	EventID     schema.InstanceID
	Reason      PurgeReason
	Status      PurgeStatus
	RequestedAt time.Time
	Deadline    time.Time
	CompletedAt time.Time
	Targets     map[PurgeTarget]PurgeTargetStatus
	Events      []PurgeEvent
}

type PurgeRequest struct {
	mu          sync.Mutex
	eventID     schema.InstanceID
	reason      PurgeReason
	status      PurgeStatus
	requestedAt time.Time
	deadline    time.Time
	completedAt time.Time
	targets     map[PurgeTarget]PurgeTargetStatus
	events      []PurgeEvent
}

func NewPurgeRequest(principal Principal, eventID schema.InstanceID, reason PurgeReason, now time.Time) (*PurgeRequest, error) {
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return nil, err
	}
	if err := eventID.Validate(); err != nil {
		return nil, fmt.Errorf("purge event ID: %w", err)
	}
	if err := reason.validate(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("purge request time is required")
	}
	targets := make(map[PurgeTarget]PurgeTargetStatus, len(allPurgeTargets))
	for _, target := range allPurgeTargets {
		targets[target] = PurgeTargetPending
	}
	request := &PurgeRequest{
		eventID:     eventID,
		reason:      reason,
		status:      PurgeRequested,
		requestedAt: now.UTC(),
		deadline:    now.UTC().Add(ActiveStorePurgeTarget),
		targets:     targets,
	}
	request.appendEventLocked(principal.ID(), "requested", "", now)
	return request, nil
}

func (request *PurgeRequest) Snapshot() PurgeSnapshot {
	request.mu.Lock()
	defer request.mu.Unlock()
	return request.snapshotLocked()
}

func (request *PurgeRequest) Start(principal Principal, now time.Time) (PurgeSnapshot, error) {
	request.mu.Lock()
	defer request.mu.Unlock()
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return request.snapshotLocked(), err
	}
	if request.status == PurgeInProgress {
		return request.snapshotLocked(), nil
	}
	if request.status != PurgeRequested {
		return request.snapshotLocked(), ErrInvalidTransition
	}
	if now.IsZero() {
		return request.snapshotLocked(), errors.New("purge start time is required")
	}
	request.status = PurgeInProgress
	request.appendEventLocked(principal.ID(), "started", "", now)
	return request.snapshotLocked(), nil
}

func (request *PurgeRequest) CompleteTarget(
	principal Principal,
	target PurgeTarget,
	status PurgeTargetStatus,
	now time.Time,
) (PurgeSnapshot, error) {
	request.mu.Lock()
	defer request.mu.Unlock()
	if err := principal.RequireScope(ScopeModerationReview); err != nil {
		return request.snapshotLocked(), err
	}
	current, exists := request.targets[target]
	if !exists {
		return request.snapshotLocked(), fmt.Errorf("unknown purge target %q", target)
	}
	if status != PurgeTargetPurged && status != PurgeTargetNotApplicable {
		return request.snapshotLocked(), fmt.Errorf("invalid terminal purge target status %q", status)
	}
	if request.status == PurgeCompleted && current == status {
		return request.snapshotLocked(), nil
	}
	if request.status != PurgeInProgress {
		return request.snapshotLocked(), ErrInvalidTransition
	}
	if current == status {
		return request.snapshotLocked(), nil
	}
	if current != PurgeTargetPending {
		return request.snapshotLocked(), ErrConflict
	}
	if now.IsZero() {
		return request.snapshotLocked(), errors.New("purge target completion time is required")
	}
	request.targets[target] = status
	request.appendEventLocked(principal.ID(), string(status), target, now)
	if request.allTargetsTerminalLocked() {
		request.status = PurgeCompleted
		request.completedAt = now.UTC()
		request.appendEventLocked(principal.ID(), "completed", "", now)
	}
	return request.snapshotLocked(), nil
}

func (request *PurgeRequest) MissedDeadline(now time.Time) bool {
	request.mu.Lock()
	defer request.mu.Unlock()
	return request.status != PurgeCompleted && !now.IsZero() && !now.Before(request.deadline)
}

func (request *PurgeRequest) allTargetsTerminalLocked() bool {
	for _, status := range request.targets {
		if status == PurgeTargetPending {
			return false
		}
	}
	return true
}

func (request *PurgeRequest) appendEventLocked(actor PrincipalID, action string, target PurgeTarget, now time.Time) {
	request.events = append(request.events, PurgeEvent{
		Sequence: uint64(len(request.events) + 1),
		Actor:    actor,
		Action:   action,
		Target:   target,
		At:       now.UTC(),
	})
}

func (request *PurgeRequest) snapshotLocked() PurgeSnapshot {
	events := make([]PurgeEvent, len(request.events))
	copy(events, request.events)
	return PurgeSnapshot{
		EventID:     request.eventID,
		Reason:      request.reason,
		Status:      request.status,
		RequestedAt: request.requestedAt,
		Deadline:    request.deadline,
		CompletedAt: request.completedAt,
		Targets:     maps.Clone(request.targets),
		Events:      events,
	}
}
