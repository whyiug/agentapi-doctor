package registry

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type SubjectNamespace string

var namespacePartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (namespace SubjectNamespace) Validate() error {
	parts := strings.Split(string(namespace), "/")
	if len(parts) != 2 || !namespacePartPattern.MatchString(parts[0]) || !namespacePartPattern.MatchString(parts[1]) {
		return fmt.Errorf("subject namespace %q must be owner/project", namespace)
	}
	if parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return fmt.Errorf("subject namespace %q contains a path segment", namespace)
	}
	return nil
}

type OwnershipMethod string

const (
	OwnershipDNS       OwnershipMethod = "dns_txt"
	OwnershipGitHubOrg OwnershipMethod = "github_org"
	OwnershipDomain    OwnershipMethod = "controlled_domain"
)

func (method OwnershipMethod) validate() error {
	switch method {
	case OwnershipDNS, OwnershipGitHubOrg, OwnershipDomain:
		return nil
	default:
		return fmt.Errorf("invalid ownership method %q", method)
	}
}

type ChallengeStatus string

const (
	ChallengePending  ChallengeStatus = "pending"
	ChallengeVerified ChallengeStatus = "verified"
	ChallengeExpired  ChallengeStatus = "expired"
)

type OwnershipChallengeSnapshot struct {
	ID             schema.InstanceID
	Subject        SubjectNamespace
	Requester      PrincipalID
	Method         OwnershipMethod
	Nonce          string
	ExpiresAt      time.Time
	Status         ChallengeStatus
	VerifiedAt     time.Time
	EvidenceDigest schema.Digest
}

type OwnershipChallenge struct {
	mu             sync.Mutex
	id             schema.InstanceID
	subject        SubjectNamespace
	requester      PrincipalID
	method         OwnershipMethod
	nonce          string
	expiresAt      time.Time
	status         ChallengeStatus
	verifiedAt     time.Time
	evidenceDigest schema.Digest
}

func RestoreOwnershipChallenge(snapshot OwnershipChallengeSnapshot) (*OwnershipChallenge, error) {
	if err := snapshot.ID.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Subject.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Requester.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Method.validate(); err != nil {
		return nil, err
	}
	if err := validateNonce(snapshot.Nonce); err != nil {
		return nil, err
	}
	if snapshot.ExpiresAt.IsZero() {
		return nil, errors.New("challenge expiry is required")
	}
	if snapshot.Status != ChallengePending && snapshot.Status != ChallengeVerified && snapshot.Status != ChallengeExpired {
		return nil, errors.New("invalid challenge status")
	}
	if snapshot.Status == ChallengeVerified {
		if snapshot.VerifiedAt.IsZero() {
			return nil, errors.New("verified challenge requires time")
		}
		if err := snapshot.EvidenceDigest.Validate(); err != nil {
			return nil, err
		}
	} else if !snapshot.VerifiedAt.IsZero() || snapshot.EvidenceDigest != "" {
		return nil, errors.New("unverified challenge contains verification fields")
	}
	return &OwnershipChallenge{id: snapshot.ID, subject: snapshot.Subject, requester: snapshot.Requester, method: snapshot.Method, nonce: snapshot.Nonce, expiresAt: snapshot.ExpiresAt.UTC(), status: snapshot.Status, verifiedAt: snapshot.VerifiedAt.UTC(), evidenceDigest: snapshot.EvidenceDigest}, nil
}

func NewOwnershipChallenge(
	principal Principal,
	id schema.InstanceID,
	subject SubjectNamespace,
	method OwnershipMethod,
	nonce string,
	expiresAt time.Time,
	now time.Time,
) (*OwnershipChallenge, error) {
	if err := principal.RequireScope(ScopeOwnershipManage); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("challenge ID: %w", err)
	}
	if err := subject.Validate(); err != nil {
		return nil, err
	}
	if err := method.validate(); err != nil {
		return nil, err
	}
	if err := validateNonce(nonce); err != nil {
		return nil, err
	}
	if now.IsZero() || !expiresAt.After(now) {
		return nil, errors.New("challenge expiry must be after creation time")
	}
	return &OwnershipChallenge{
		id:        id,
		subject:   subject,
		requester: principal.ID(),
		method:    method,
		nonce:     nonce,
		expiresAt: expiresAt.UTC(),
		status:    ChallengePending,
	}, nil
}

func validateNonce(nonce string) error {
	if nonce == "" || nonce != strings.TrimSpace(nonce) || len(nonce) > 512 || strings.ContainsAny(nonce, "\r\n\x00") {
		return errors.New("ownership nonce must be 1..512 non-control bytes")
	}
	return nil
}

func (challenge *OwnershipChallenge) Snapshot(now time.Time) OwnershipChallengeSnapshot {
	challenge.mu.Lock()
	defer challenge.mu.Unlock()
	return challenge.snapshotLocked(now)
}

func (challenge *OwnershipChallenge) PersistentSnapshot() OwnershipChallengeSnapshot {
	challenge.mu.Lock()
	defer challenge.mu.Unlock()
	return OwnershipChallengeSnapshot{ID: challenge.id, Subject: challenge.subject, Requester: challenge.requester, Method: challenge.method, Nonce: challenge.nonce, ExpiresAt: challenge.expiresAt, Status: challenge.status, VerifiedAt: challenge.verifiedAt, EvidenceDigest: challenge.evidenceDigest}
}

func (challenge *OwnershipChallenge) snapshotLocked(now time.Time) OwnershipChallengeSnapshot {
	status := challenge.status
	if status == ChallengePending && expired(now, challenge.expiresAt) {
		status = ChallengeExpired
	}
	return OwnershipChallengeSnapshot{
		ID:             challenge.id,
		Subject:        challenge.subject,
		Requester:      challenge.requester,
		Method:         challenge.method,
		Nonce:          challenge.nonce,
		ExpiresAt:      challenge.expiresAt,
		Status:         status,
		VerifiedAt:     challenge.verifiedAt,
		EvidenceDigest: challenge.evidenceDigest,
	}
}

// Verify records the result of an already policy-constrained verifier.  It
// does not perform DNS, GitHub or HTTP access itself.
func (challenge *OwnershipChallenge) Verify(evidenceDigest schema.Digest, now time.Time) (OwnershipChallengeSnapshot, error) {
	challenge.mu.Lock()
	defer challenge.mu.Unlock()
	if err := evidenceDigest.Validate(); err != nil {
		return challenge.snapshotLocked(now), fmt.Errorf("ownership evidence digest: %w", err)
	}
	if expired(now, challenge.expiresAt) {
		return challenge.snapshotLocked(now), ErrExpired
	}
	if challenge.status == ChallengeVerified {
		if challenge.evidenceDigest == evidenceDigest {
			return challenge.snapshotLocked(now), nil
		}
		return challenge.snapshotLocked(now), ErrConflict
	}
	if challenge.status != ChallengePending {
		return challenge.snapshotLocked(now), ErrInvalidTransition
	}
	challenge.status = ChallengeVerified
	challenge.verifiedAt = now.UTC()
	challenge.evidenceDigest = evidenceDigest
	return challenge.snapshotLocked(now), nil
}

type OwnershipSnapshot struct {
	Subject    SubjectNamespace
	Owner      PrincipalID
	Method     OwnershipMethod
	Evidence   schema.Digest
	VerifiedAt time.Time
	ValidUntil time.Time
	RevokedAt  time.Time
	Reason     string
}

type Ownership struct {
	mu         sync.Mutex
	subject    SubjectNamespace
	owner      PrincipalID
	method     OwnershipMethod
	evidence   schema.Digest
	verifiedAt time.Time
	validUntil time.Time
	revokedAt  time.Time
	reason     string
}

func RestoreOwnership(snapshot OwnershipSnapshot) (*Ownership, error) {
	if err := snapshot.Subject.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Owner.Validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Method.validate(); err != nil {
		return nil, err
	}
	if err := snapshot.Evidence.Validate(); err != nil {
		return nil, err
	}
	if snapshot.VerifiedAt.IsZero() || !snapshot.ValidUntil.After(snapshot.VerifiedAt) {
		return nil, errors.New("ownership validity interval is invalid")
	}
	if snapshot.RevokedAt.IsZero() != (snapshot.Reason == "") {
		return nil, errors.New("ownership revocation time and reason must appear together")
	}
	if !snapshot.RevokedAt.IsZero() {
		if err := validateReason(snapshot.Reason); err != nil {
			return nil, err
		}
	}
	return &Ownership{subject: snapshot.Subject, owner: snapshot.Owner, method: snapshot.Method, evidence: snapshot.Evidence, verifiedAt: snapshot.VerifiedAt.UTC(), validUntil: snapshot.ValidUntil.UTC(), revokedAt: snapshot.RevokedAt.UTC(), reason: snapshot.Reason}, nil
}

func OwnershipFromChallenge(challenge *OwnershipChallenge, validUntil, now time.Time) (*Ownership, error) {
	if challenge == nil {
		return nil, errors.New("ownership challenge is required")
	}
	if now.IsZero() {
		return nil, errors.New("ownership verification time is required")
	}
	snapshot := challenge.Snapshot(now)
	if snapshot.Status != ChallengeVerified {
		return nil, errors.New("ownership challenge is not verified")
	}
	if !now.Before(snapshot.ExpiresAt) {
		return nil, ErrExpired
	}
	if !validUntil.After(now) {
		return nil, errors.New("ownership validity must extend beyond verification")
	}
	return &Ownership{
		subject:    snapshot.Subject,
		owner:      snapshot.Requester,
		method:     snapshot.Method,
		evidence:   snapshot.EvidenceDigest,
		verifiedAt: snapshot.VerifiedAt,
		validUntil: validUntil.UTC(),
	}, nil
}

func (ownership *Ownership) Snapshot() OwnershipSnapshot {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	return ownership.snapshotLocked()
}

func (ownership *Ownership) snapshotLocked() OwnershipSnapshot {
	return OwnershipSnapshot{
		Subject:    ownership.subject,
		Owner:      ownership.owner,
		Method:     ownership.method,
		Evidence:   ownership.evidence,
		VerifiedAt: ownership.verifiedAt,
		ValidUntil: ownership.validUntil,
		RevokedAt:  ownership.revokedAt,
		Reason:     ownership.reason,
	}
}

func (ownership *Ownership) Current(now time.Time) bool {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	return ownership.currentLocked(now)
}

func (ownership *Ownership) currentLocked(now time.Time) bool {
	return !now.IsZero() && ownership.revokedAt.IsZero() && now.Before(ownership.validUntil)
}

func (ownership *Ownership) AuthorizeManage(principal Principal, now time.Time) error {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if err := authorizeOwned(principal, ownership.owner, ScopeOwnershipManage); err != nil {
		return err
	}
	if !ownership.currentLocked(now) {
		return ErrExpired
	}
	return nil
}

func (ownership *Ownership) Revoke(principal Principal, reason string, now time.Time) (OwnershipSnapshot, error) {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if err := validateReason(reason); err != nil {
		return ownership.snapshotLocked(), err
	}
	if principal.HasScope(ScopeModerationReview) {
		if err := principal.RequireScope(ScopeModerationReview); err != nil {
			return ownership.snapshotLocked(), err
		}
	} else if err := authorizeOwned(principal, ownership.owner, ScopeOwnershipManage); err != nil {
		return ownership.snapshotLocked(), err
	}
	if !ownership.revokedAt.IsZero() {
		if ownership.reason == reason {
			return ownership.snapshotLocked(), nil
		}
		return ownership.snapshotLocked(), ErrConflict
	}
	if now.IsZero() {
		return ownership.snapshotLocked(), errors.New("revocation time is required")
	}
	ownership.revokedAt = now.UTC()
	ownership.reason = reason
	return ownership.snapshotLocked(), nil
}

// Transfer requires a still-current old owner and a separately verified
// challenge for the same exact subject namespace.
func (ownership *Ownership) Transfer(
	principal Principal,
	newChallenge *OwnershipChallenge,
	newValidUntil time.Time,
	now time.Time,
) (*Ownership, error) {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if err := authorizeOwned(principal, ownership.owner, ScopeOwnershipManage); err != nil {
		return nil, err
	}
	if !ownership.currentLocked(now) {
		return nil, ErrExpired
	}
	newOwnership, err := OwnershipFromChallenge(newChallenge, newValidUntil, now)
	if err != nil {
		return nil, err
	}
	if newOwnership.subject != ownership.subject {
		return nil, errors.New("ownership transfer challenge names a different subject")
	}
	if newOwnership.owner == ownership.owner {
		return nil, errors.New("ownership transfer requires a different owner")
	}
	ownership.revokedAt = now.UTC()
	ownership.reason = "ownership_transferred"
	return newOwnership, nil
}
