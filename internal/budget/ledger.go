// Package budget enforces independent hard, reservation, and cleanup ledgers.
package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

var (
	ErrExhausted          = errors.New("budget exhausted")
	ErrReservationClosed  = errors.New("reservation is already closed")
	ErrInvalidConsumption = errors.New("budget consumption cannot be negative")
)

type Usage struct {
	Requests      int64 `json:"requests"`
	RequestBytes  int64 `json:"request_bytes"`
	ResponseBytes int64 `json:"response_bytes"`
	ArtifactBytes int64 `json:"artifact_bytes"`
	Processes     int64 `json:"processes"`
	InputTokens   int64 `json:"input_tokens"`
	OutputTokens  int64 `json:"output_tokens"`
}

func (usage Usage) Validate() error {
	if usage.Requests < 0 || usage.RequestBytes < 0 || usage.ResponseBytes < 0 || usage.ArtifactBytes < 0 || usage.Processes < 0 || usage.InputTokens < 0 || usage.OutputTokens < 0 {
		return ErrInvalidConsumption
	}
	return nil
}

func (usage Usage) add(other Usage) Usage {
	return Usage{
		Requests:      usage.Requests + other.Requests,
		RequestBytes:  usage.RequestBytes + other.RequestBytes,
		ResponseBytes: usage.ResponseBytes + other.ResponseBytes,
		ArtifactBytes: usage.ArtifactBytes + other.ArtifactBytes,
		Processes:     usage.Processes + other.Processes,
		InputTokens:   usage.InputTokens + other.InputTokens,
		OutputTokens:  usage.OutputTokens + other.OutputTokens,
	}
}

func (usage Usage) subtract(other Usage) Usage {
	return Usage{
		Requests:      usage.Requests - other.Requests,
		RequestBytes:  usage.RequestBytes - other.RequestBytes,
		ResponseBytes: usage.ResponseBytes - other.ResponseBytes,
		ArtifactBytes: usage.ArtifactBytes - other.ArtifactBytes,
		Processes:     usage.Processes - other.Processes,
		InputTokens:   usage.InputTokens - other.InputTokens,
		OutputTokens:  usage.OutputTokens - other.OutputTokens,
	}
}

type Snapshot struct {
	Consumed        Usage     `json:"consumed"`
	Reserved        Usage     `json:"reserved"`
	CleanupConsumed Usage     `json:"cleanup_consumed"`
	Overshoot       Usage     `json:"overshoot"`
	StartedAt       time.Time `json:"started_at"`
	Deadline        time.Time `json:"deadline"`
	Exhausted       bool      `json:"exhausted"`
}

type Ledger struct {
	mu              sync.Mutex
	policy          schema.BudgetPolicy
	startedAt       time.Time
	deadline        time.Time
	now             func() time.Time
	consumed        Usage
	reserved        Usage
	cleanupConsumed Usage
	overshoot       Usage
	exhausted       bool
	nextID          uint64
	open            map[uint64]*Reservation
}

func New(policy schema.BudgetPolicy, now func() time.Time) (*Ledger, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	started := now()
	return &Ledger{
		policy:    policy,
		startedAt: started,
		deadline:  started.Add(policy.Hard.MaxDuration.Duration()),
		now:       now,
		open:      make(map[uint64]*Reservation),
	}, nil
}

type Reservation struct {
	ledger  *Ledger
	id      uint64
	planned Usage
	closed  bool
}

func (ledger *Ledger) Reserve(planned Usage) (*Reservation, error) {
	if err := planned.Validate(); err != nil {
		return nil, err
	}
	if planned.Requests == 0 && planned.Processes == 0 {
		return nil, errors.New("reservation must cover a request or process")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.checkTimeLocked(); err != nil {
		return nil, err
	}
	if ledger.exhausted {
		return nil, ErrExhausted
	}
	projected := ledger.consumed.add(ledger.reserved).add(planned)
	if reason := exceeds(projected, ledger.policy.Hard, ledger.policy.Reservation); reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrExhausted, reason)
	}
	ledger.nextID++
	reservation := &Reservation{ledger: ledger, id: ledger.nextID, planned: planned}
	ledger.open[reservation.id] = reservation
	ledger.reserved = ledger.reserved.add(planned)
	return reservation, nil
}

func (reservation *Reservation) Commit(actual Usage) error {
	if err := actual.Validate(); err != nil {
		return err
	}
	ledger := reservation.ledger
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if reservation.closed {
		return ErrReservationClosed
	}
	reservation.closed = true
	delete(ledger.open, reservation.id)
	ledger.reserved = ledger.reserved.subtract(reservation.planned)
	ledger.consumed = ledger.consumed.add(actual)
	ledger.overshoot = ledger.overshoot.add(positiveDifference(actual, reservation.planned))
	reason := exceeds(ledger.consumed, ledger.policy.Hard, ledger.policy.Reservation)
	if reason != "" {
		ledger.exhausted = true
		return fmt.Errorf("%w after in-flight completion: %s", ErrExhausted, reason)
	}
	return ledger.checkTimeLocked()
}

func (reservation *Reservation) Cancel() error {
	ledger := reservation.ledger
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if reservation.closed {
		return ErrReservationClosed
	}
	reservation.closed = true
	delete(ledger.open, reservation.id)
	ledger.reserved = ledger.reserved.subtract(reservation.planned)
	return nil
}

// ConsumeCleanup spends only the cleanup ledger.  Test steps can never call
// this through a normal reservation, so cleanup remains available after the
// ordinary hard budget is exhausted.
func (ledger *Ledger) ConsumeCleanup(actual Usage) error {
	if err := actual.Validate(); err != nil {
		return err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	projected := ledger.cleanupConsumed.add(actual)
	if reason := exceeds(projected, ledger.policy.Cleanup, schema.TokenBudget{}); reason != "" {
		return fmt.Errorf("%w: cleanup %s", ErrExhausted, reason)
	}
	ledger.cleanupConsumed = projected
	return nil
}

func (ledger *Ledger) Snapshot() Snapshot {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	_ = ledger.checkTimeLocked()
	return Snapshot{
		Consumed:        ledger.consumed,
		Reserved:        ledger.reserved,
		CleanupConsumed: ledger.cleanupConsumed,
		Overshoot:       ledger.overshoot,
		StartedAt:       ledger.startedAt,
		Deadline:        ledger.deadline,
		Exhausted:       ledger.exhausted,
	}
}

func (ledger *Ledger) checkTimeLocked() error {
	if !ledger.now().Before(ledger.deadline) {
		ledger.exhausted = true
		return fmt.Errorf("%w: duration", ErrExhausted)
	}
	return nil
}

func exceeds(usage Usage, hard schema.HardBudget, tokens schema.TokenBudget) string {
	switch {
	case usage.Requests > hard.MaxRequests:
		return "requests"
	case usage.RequestBytes > hard.MaxRequestBytes:
		return "request bytes"
	case usage.ResponseBytes > hard.MaxResponseBytes:
		return "response bytes"
	case usage.ArtifactBytes > hard.MaxArtifactBytes:
		return "artifact bytes"
	case usage.Processes > hard.MaxProcesses:
		return "processes"
	case tokens.MaxInputTokens > 0 && usage.InputTokens > tokens.MaxInputTokens:
		return "input tokens"
	case tokens.MaxOutputTokens > 0 && usage.OutputTokens > tokens.MaxOutputTokens:
		return "output tokens"
	default:
		return ""
	}
}

func positiveDifference(actual, planned Usage) Usage {
	difference := actual.subtract(planned)
	for _, value := range []*int64{&difference.Requests, &difference.RequestBytes, &difference.ResponseBytes, &difference.ArtifactBytes, &difference.Processes, &difference.InputTokens, &difference.OutputTokens} {
		if *value < 0 {
			*value = 0
		}
	}
	return difference
}
