package registry

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

var testNow = time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

func testPrincipal(t *testing.T, id string, scopes ...Scope) Principal {
	t.Helper()
	principal, err := NewPrincipal(PrincipalID(id), scopes...)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func testID(t *testing.T, suffix string) schema.InstanceID {
	t.Helper()
	id, err := schema.ParseInstanceID("00000000-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPrincipalScopesAreExactAndAdminDoesNotBypass(t *testing.T) {
	if _, err := NewPrincipal("user", ScopeObservationPrepare, ScopeObservationPrepare); err == nil {
		t.Fatal("accepted duplicate scope")
	}
	if _, err := NewPrincipal("user", Scope("all:*")); err == nil {
		t.Fatal("accepted unknown scope")
	}
	admin := testPrincipal(t, "admin", ScopeRegistryAdmin)
	if err := admin.RequireScope(ScopeModerationReview); !errors.Is(err, ErrForbidden) {
		t.Fatalf("registry:admin implicitly bypassed moderation scope: %v", err)
	}
	owner := testPrincipal(t, "owner", ScopeObservationPrepare)
	if err := authorizeOwned(owner, "someone-else", ScopeObservationPrepare); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("expected object owner rejection, got %v", err)
	}
}

func TestIngestHappyPathAndIdempotentCommit(t *testing.T) {
	owner := testPrincipal(t, "owner", ScopeObservationPrepare, ScopeObservationCommit)
	digest := schema.NewDigest([]byte("observation"))
	session, err := PrepareIngest(owner, testID(t, "000000000001"), digest, testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := session.Snapshot().Status; got != IngestPrepared {
		t.Fatalf("want prepared, got %s", got)
	}
	if snapshot, err := session.Stage(owner, digest, testNow.Add(time.Minute)); err != nil || snapshot.Status != IngestStaged {
		t.Fatalf("stage: status=%s err=%v", snapshot.Status, err)
	}
	if snapshot, err := session.Commit(owner, digest, testNow.Add(2*time.Minute)); err != nil || snapshot.Status != IngestCommitted {
		t.Fatalf("commit: status=%s err=%v", snapshot.Status, err)
	}

	const callers = 16
	var wait sync.WaitGroup
	errorsSeen := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := session.Commit(owner, digest, testNow.Add(2*time.Hour))
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("idempotent commit failed after expiry: %v", err)
		}
	}
	if snapshot, err := session.BeginValidation(); err != nil || snapshot.Status != IngestValidating {
		t.Fatalf("begin validation: status=%s err=%v", snapshot.Status, err)
	}
	if snapshot, err := session.Publish(); err != nil || snapshot.Status != IngestPublished {
		t.Fatalf("publish: status=%s err=%v", snapshot.Status, err)
	}
	if snapshot, err := session.Commit(owner, digest, testNow.Add(24*time.Hour)); err != nil || snapshot.Status != IngestPublished {
		t.Fatalf("terminal idempotent commit: status=%s err=%v", snapshot.Status, err)
	}
}

func TestIngestRejectsWrongOwnerDigestExpiryAndTransitions(t *testing.T) {
	owner := testPrincipal(t, "owner", ScopeObservationPrepare, ScopeObservationCommit)
	attacker := testPrincipal(t, "attacker", ScopeObservationPrepare, ScopeObservationCommit)
	digest := schema.NewDigest([]byte("observation"))
	other := schema.NewDigest([]byte("other"))
	session, err := PrepareIngest(owner, testID(t, "000000000002"), digest, testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Stage(attacker, digest, testNow); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("expected owner rejection, got %v", err)
	}
	if _, err := session.Stage(owner, other, testNow); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	if _, err := session.Commit(owner, digest, testNow); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("commit before stage should fail, got %v", err)
	}
	if _, err := session.Stage(owner, digest, testNow.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("stage at expiry should fail, got %v", err)
	}

	fresh, err := PrepareIngest(owner, testID(t, "000000000003"), digest, testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Stage(owner, digest, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Commit(owner, other, testNow); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("commit changed digest, got %v", err)
	}
	if _, err := fresh.Commit(attacker, digest, testNow); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("attacker committed another session, got %v", err)
	}
}

func TestIngestQuarantineIsTerminalAndReasonBound(t *testing.T) {
	owner := testPrincipal(t, "owner", ScopeObservationPrepare, ScopeObservationCommit)
	digest := schema.NewDigest([]byte("observation"))
	session, err := PrepareIngest(owner, testID(t, "000000000004"), digest, testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Stage(owner, digest, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Commit(owner, digest, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := session.BeginValidation(); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := session.Quarantine("secret_canary"); err != nil || snapshot.Status != IngestQuarantined {
		t.Fatalf("quarantine: status=%s err=%v", snapshot.Status, err)
	}
	if _, err := session.Quarantine("different_reason"); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed terminal quarantine reason: %v", err)
	}
	if _, err := session.Publish(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("published quarantined ingest: %v", err)
	}
}

func TestOwnershipVerificationAuthorizationRevocationAndTransfer(t *testing.T) {
	oldOwner := testPrincipal(t, "old-owner", ScopeOwnershipManage)
	newOwner := testPrincipal(t, "new-owner", ScopeOwnershipManage)
	moderator := testPrincipal(t, "moderator", ScopeModerationReview)
	outsider := testPrincipal(t, "outsider", ScopeOwnershipManage)
	subject := SubjectNamespace("example/runtime")
	challenge, err := NewOwnershipChallenge(oldOwner, testID(t, "000000000010"), subject, OwnershipDNS, "nonce-1", testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	// This is a deterministic local unit-test token, not a claim that an
	// external DNS or organization check occurred.
	evidence := schema.NewDigest([]byte("synthetic-local-ownership-evidence"))
	if snapshot, err := challenge.Verify(evidence, testNow.Add(time.Minute)); err != nil || snapshot.Status != ChallengeVerified {
		t.Fatalf("verify: status=%s err=%v", snapshot.Status, err)
	}
	ownership, err := OwnershipFromChallenge(challenge, testNow.Add(90*24*time.Hour), testNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !ownership.Current(testNow.Add(24 * time.Hour)) {
		t.Fatal("verified ownership should be current")
	}
	if err := ownership.AuthorizeManage(outsider, testNow); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("outsider managed ownership: %v", err)
	}

	newChallenge, err := NewOwnershipChallenge(newOwner, testID(t, "000000000011"), subject, OwnershipGitHubOrg, "nonce-2", testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newChallenge.Verify(schema.NewDigest([]byte("synthetic-local-transfer-evidence")), testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	transferred, err := ownership.Transfer(oldOwner, newChallenge, testNow.Add(90*24*time.Hour), testNow.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ownership.Current(testNow.Add(3 * time.Minute)) {
		t.Fatal("old ownership remained current after transfer")
	}
	if got := transferred.Snapshot().Owner; got != newOwner.ID() {
		t.Fatalf("want new owner, got %s", got)
	}
	if _, err := transferred.Revoke(moderator, "account_compromise", testNow.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if transferred.Current(testNow.Add(4 * time.Minute)) {
		t.Fatal("moderator revocation did not take effect")
	}
}

func TestOwnershipRejectsExpiredChallenge(t *testing.T) {
	owner := testPrincipal(t, "owner", ScopeOwnershipManage)
	challenge, err := NewOwnershipChallenge(owner, testID(t, "000000000012"), "example/runtime", OwnershipDomain, "nonce", testNow.Add(time.Minute), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challenge.Verify(schema.NewDigest([]byte("synthetic-local-expired-evidence")), testNow.Add(time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired challenge, got %v", err)
	}
}

func TestDisputeRequiresOwnerAndIndependentModerator(t *testing.T) {
	reporter := testPrincipal(t, "reporter", ScopeDisputeCreate)
	owner := testPrincipal(t, "owner", ScopeDisputeCreate, ScopeOwnershipManage, ScopeModerationReview)
	moderator := testPrincipal(t, "moderator", ScopeModerationReview)
	otherModerator := testPrincipal(t, "other-moderator", ScopeModerationReview)
	subject := SubjectNamespace("example/runtime")
	dispute, err := NewDispute(reporter, testID(t, "000000000020"), schema.NewDigest([]byte("observation")), subject, owner.ID(), "result is disputed", testNow)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := NewOwnershipChallenge(owner, testID(t, "000000000021"), subject, OwnershipDNS, "nonce", testNow.Add(time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challenge.Verify(schema.NewDigest([]byte("synthetic-local-owner-response-evidence")), testNow); err != nil {
		t.Fatal(err)
	}
	ownership, err := OwnershipFromChallenge(challenge, testNow.Add(90*24*time.Hour), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := dispute.AddOwnerResponse(owner, ownership, "fixed in the next release", testNow.Add(time.Minute)); err != nil || len(snapshot.Events) != 2 {
		t.Fatalf("owner response: events=%d err=%v", len(snapshot.Events), err)
	}
	if _, err := dispute.BeginReview(owner, testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("subject owner reviewed own dispute: %v", err)
	}
	if _, err := dispute.BeginReview(reporter, testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("creator reviewed own dispute: %v", err)
	}
	if snapshot, err := dispute.BeginReview(moderator, testNow.Add(2*time.Minute)); err != nil || snapshot.Status != DisputeUnderReview {
		t.Fatalf("begin review: status=%s err=%v", snapshot.Status, err)
	}
	if _, err := dispute.Resolve(otherModerator, "not assigned", testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unassigned moderator resolved dispute: %v", err)
	}
	if snapshot, err := dispute.Resolve(moderator, "evidence supports the original observation", testNow.Add(3*time.Minute)); err != nil || snapshot.Status != DisputeResolved {
		t.Fatalf("resolve: status=%s err=%v", snapshot.Status, err)
	}
	snapshot := dispute.Snapshot()
	snapshot.Events[0].Statement = "mutated"
	if dispute.Snapshot().Events[0].Statement == "mutated" {
		t.Fatal("caller mutated append-only dispute event through snapshot")
	}
}

func TestSupersessionAndTombstoneRequireModeration(t *testing.T) {
	user := testPrincipal(t, "user", ScopeDisputeCreate)
	moderator := testPrincipal(t, "moderator", ScopeModerationReview)
	original := schema.NewDigest([]byte("original"))
	replacement := schema.NewDigest([]byte("replacement"))
	if _, err := NewSupersession(user, original, replacement, "corrected", testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unprivileged supersession: %v", err)
	}
	if record, err := NewSupersession(moderator, original, replacement, "corrected", testNow); err != nil || record.OriginalID != original {
		t.Fatalf("supersession: %#v err=%v", record, err)
	}
	if _, err := NewTombstone(user, original, "invalid submission", testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unprivileged tombstone: %v", err)
	}
	if record, err := NewTombstone(moderator, original, "invalid submission", testNow); err != nil || record.ObservationID != original {
		t.Fatalf("tombstone: %#v err=%v", record, err)
	}
}

func TestPurgeAuthorizationChecklistAndDeadline(t *testing.T) {
	user := testPrincipal(t, "user", ScopeDisputeCreate)
	moderator := testPrincipal(t, "moderator", ScopeModerationReview)
	admin := testPrincipal(t, "admin", ScopeRegistryAdmin)
	if _, err := NewPurgeRequest(user, testID(t, "000000000030"), PurgeSecret, testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user created purge: %v", err)
	}
	if _, err := NewPurgeRequest(admin, testID(t, "000000000031"), PurgeSecret, testNow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin bypassed moderation separation: %v", err)
	}
	request, err := NewPurgeRequest(moderator, testID(t, "000000000032"), PurgePII, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := request.Snapshot().Deadline.Sub(testNow); got != 24*time.Hour {
		t.Fatalf("want 24h deadline, got %s", got)
	}
	if _, err := request.CompleteTarget(moderator, PurgeCDN, PurgeTargetPurged, testNow); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("completed target before start: %v", err)
	}
	if _, err := request.Start(moderator, testNow); err != nil {
		t.Fatal(err)
	}
	for index, target := range allPurgeTargets {
		status := PurgeTargetPurged
		if target == PurgeCDN {
			status = PurgeTargetNotApplicable
		}
		snapshot, err := request.CompleteTarget(moderator, target, status, testNow.Add(time.Duration(index+1)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if index < len(allPurgeTargets)-1 && snapshot.Status == PurgeCompleted {
			t.Fatal("purge completed before every active-store target was terminal")
		}
	}
	snapshot := request.Snapshot()
	if snapshot.Status != PurgeCompleted || snapshot.CompletedAt.IsZero() {
		t.Fatalf("purge did not complete: %#v", snapshot)
	}
	snapshot.Targets[PurgeObjectStore] = PurgeTargetPending
	if request.Snapshot().Targets[PurgeObjectStore] == PurgeTargetPending {
		t.Fatal("caller mutated purge checklist through snapshot")
	}
	if request.MissedDeadline(testNow.Add(25 * time.Hour)) {
		t.Fatal("completed purge reported missed deadline")
	}
}

func TestPurgeMissedDeadline(t *testing.T) {
	moderator := testPrincipal(t, "moderator", ScopeModerationReview)
	request, err := NewPurgeRequest(moderator, testID(t, "000000000033"), PurgeUnauthorized, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !request.MissedDeadline(testNow.Add(24 * time.Hour)) {
		t.Fatal("pending purge did not report 24h deadline miss")
	}
}
