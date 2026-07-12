package budget

import (
	"errors"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func policy() schema.BudgetPolicy {
	return schema.BudgetPolicy{
		Hard:        schema.HardBudget{MaxRequests: 2, MaxRequestBytes: 100, MaxResponseBytes: 200, MaxArtifactBytes: 300, MaxProcesses: 2, MaxDuration: schema.NewDuration(time.Minute)},
		Reservation: schema.TokenBudget{MaxInputTokens: 1000, MaxOutputTokens: 500},
		Cleanup:     schema.HardBudget{MaxRequests: 1, MaxRequestBytes: 10, MaxResponseBytes: 10, MaxArtifactBytes: 10, MaxProcesses: 1, MaxDuration: schema.NewDuration(time.Minute)},
	}
}

func TestReservationPreventsConcurrentOversubscription(t *testing.T) {
	now := time.Unix(0, 0)
	ledger, err := New(policy(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := ledger.Reserve(Usage{Requests: 1, RequestBytes: 60, ResponseBytes: 100, Processes: 1, InputTokens: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(Usage{Requests: 1, RequestBytes: 60, ResponseBytes: 100, Processes: 1, InputTokens: 600}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected reservation exhaustion, got %v", err)
	}
	if err := first.Commit(Usage{Requests: 1, RequestBytes: 50, ResponseBytes: 90, Processes: 1, InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(Usage{Requests: 1, RequestBytes: 50, ResponseBytes: 100, Processes: 1, InputTokens: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupBudgetSurvivesNormalExhaustion(t *testing.T) {
	now := time.Unix(0, 0)
	ledger, _ := New(policy(), func() time.Time { return now })
	reservation, _ := ledger.Reserve(Usage{Requests: 2, RequestBytes: 100, ResponseBytes: 200, Processes: 2})
	if err := reservation.Commit(Usage{Requests: 3, RequestBytes: 101, ResponseBytes: 201, Processes: 2}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected hard exhaustion, got %v", err)
	}
	if err := ledger.ConsumeCleanup(Usage{Requests: 1, RequestBytes: 1, ResponseBytes: 1, Processes: 1}); err != nil {
		t.Fatalf("cleanup should remain available: %v", err)
	}
	if !ledger.Snapshot().Exhausted {
		t.Fatal("ledger should remain exhausted")
	}
}

func TestDeadlineAndClosedReservation(t *testing.T) {
	now := time.Unix(0, 0)
	ledger, _ := New(policy(), func() time.Time { return now })
	reservation, _ := ledger.Reserve(Usage{Requests: 1})
	if err := reservation.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Cancel(); !errors.Is(err, ErrReservationClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := ledger.Reserve(Usage{Requests: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected deadline exhaustion, got %v", err)
	}
}
