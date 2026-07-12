package provenance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	JournalSchema                      = "urn:agentapi-doctor:run-journal-event:v1alpha1"
	MaxJournalEventBytes               = 1 << 20
	zeroDigest           schema.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

type RunStatus string

const (
	RunPlanned   RunStatus = "planned"
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunCancelled RunStatus = "cancelled"
	RunErrored   RunStatus = "errored"
)

type JournalEvent struct {
	SchemaVersion       string            `json:"schema_version"`
	RunID               schema.InstanceID `json:"run_id"`
	Sequence            uint64            `json:"sequence"`
	PreviousEventDigest schema.Digest     `json:"previous_event_digest"`
	EventType           string            `json:"event_type"`
	Status              RunStatus         `json:"status"`
	OccurredAt          schema.UTCTime    `json:"occurred_at"`
	MonotonicOffsetNS   int64             `json:"monotonic_offset_ns"`
	PayloadDigest       schema.Digest     `json:"payload_digest"`
	EventDigest         schema.Digest     `json:"event_digest"`
}

type EventInput struct {
	EventType         string
	Status            RunStatus
	OccurredAt        schema.UTCTime
	MonotonicOffsetNS int64
	PayloadDigest     schema.Digest
}

type Journal struct {
	runID  schema.InstanceID
	events []JournalEvent
}

func NewJournal(runID schema.InstanceID) (*Journal, error) {
	if err := runID.Validate(); err != nil {
		return nil, err
	}
	return &Journal{runID: runID}, nil
}

func (journal *Journal) Append(input EventInput) (JournalEvent, error) {
	if journal == nil {
		return JournalEvent{}, errors.New("journal is nil")
	}
	previous := zeroDigest
	previousStatus := RunStatus("")
	offset := int64(-1)
	if len(journal.events) > 0 {
		last := journal.events[len(journal.events)-1]
		previous = last.EventDigest
		previousStatus = last.Status
		offset = last.MonotonicOffsetNS
	}
	if err := validateTransition(previousStatus, input.Status); err != nil {
		return JournalEvent{}, err
	}
	if strings.TrimSpace(input.EventType) == "" || input.OccurredAt.IsZero() || input.MonotonicOffsetNS < 0 || input.MonotonicOffsetNS < offset {
		return JournalEvent{}, errors.New("journal event requires type, time, and monotonic nondecreasing offset")
	}
	if err := input.PayloadDigest.Validate(); err != nil {
		return JournalEvent{}, fmt.Errorf("payload digest: %w", err)
	}
	event := JournalEvent{SchemaVersion: JournalSchema, RunID: journal.runID, Sequence: uint64(len(journal.events) + 1), PreviousEventDigest: previous, EventType: input.EventType, Status: input.Status, OccurredAt: input.OccurredAt, MonotonicOffsetNS: input.MonotonicOffsetNS, PayloadDigest: input.PayloadDigest}
	digest, err := eventDigest(event)
	if err != nil {
		return JournalEvent{}, err
	}
	event.EventDigest = digest
	journal.events = append(journal.events, event)
	return event, nil
}

func (journal *Journal) Events() []JournalEvent {
	if journal == nil {
		return nil
	}
	return append([]JournalEvent(nil), journal.events...)
}

func (journal *Journal) Verify() error {
	if journal == nil {
		return errors.New("journal is nil")
	}
	previous := zeroDigest
	previousStatus := RunStatus("")
	offset := int64(-1)
	for index, event := range journal.events {
		if event.SchemaVersion != JournalSchema || event.RunID != journal.runID || event.Sequence != uint64(index+1) || event.PreviousEventDigest != previous {
			return fmt.Errorf("journal chain invalid at sequence %d", index+1)
		}
		if err := validateTransition(previousStatus, event.Status); err != nil {
			return fmt.Errorf("sequence %d: %w", index+1, err)
		}
		if event.MonotonicOffsetNS < 0 || event.MonotonicOffsetNS < offset || event.OccurredAt.IsZero() || strings.TrimSpace(event.EventType) == "" {
			return fmt.Errorf("journal event fields invalid at sequence %d", index+1)
		}
		if err := event.PayloadDigest.Validate(); err != nil {
			return err
		}
		digest, err := eventDigest(event)
		if err != nil || digest != event.EventDigest {
			return fmt.Errorf("journal event digest invalid at sequence %d", index+1)
		}
		previous = event.EventDigest
		previousStatus = event.Status
		offset = event.MonotonicOffsetNS
	}
	return nil
}

func (journal *Journal) EncodeJSONL() ([]byte, error) {
	if err := journal.Verify(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	for _, event := range journal.events {
		encoded, err := schema.CanonicalMarshal(event)
		if err != nil {
			return nil, err
		}
		output.Write(encoded)
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func DecodeJournal(reader io.Reader) (*Journal, error) {
	if reader == nil {
		return nil, errors.New("journal reader is required")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), MaxJournalEventBytes)
	var journal *Journal
	line := 0
	for scanner.Scan() {
		line++
		raw := append([]byte(nil), scanner.Bytes()...)
		canonical, err := schema.CanonicalizeJSON(raw)
		if err != nil || !bytes.Equal(raw, canonical) {
			return nil, fmt.Errorf("journal line %d is not strict canonical JSON", line)
		}
		var event JournalEvent
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, fmt.Errorf("journal line %d: %w", line, err)
		}
		if decoder.More() {
			return nil, fmt.Errorf("journal line %d contains trailing JSON", line)
		}
		if journal == nil {
			journal, err = NewJournal(event.RunID)
			if err != nil {
				return nil, err
			}
		}
		journal.events = append(journal.events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if journal == nil {
		return nil, errors.New("journal is empty")
	}
	if err := journal.Verify(); err != nil {
		return nil, err
	}
	return journal, nil
}

func eventDigest(event JournalEvent) (schema.Digest, error) {
	projection := struct {
		SchemaVersion string            `json:"schema_version"`
		RunID         schema.InstanceID `json:"run_id"`
		Sequence      uint64            `json:"sequence"`
		Previous      schema.Digest     `json:"previous_event_digest"`
		EventType     string            `json:"event_type"`
		Status        RunStatus         `json:"status"`
		OccurredAt    schema.UTCTime    `json:"occurred_at"`
		Monotonic     int64             `json:"monotonic_offset_ns"`
		Payload       schema.Digest     `json:"payload_digest"`
	}{event.SchemaVersion, event.RunID, event.Sequence, event.PreviousEventDigest, event.EventType, event.Status, event.OccurredAt, event.MonotonicOffsetNS, event.PayloadDigest}
	return schema.CanonicalDigest(projection)
}

func validateTransition(previous, next RunStatus) error {
	if previous == "" && next == RunPlanned {
		return nil
	}
	if previous == RunPlanned && next == RunRunning {
		return nil
	}
	if previous == RunRunning && (next == RunRunning || next == RunCompleted || next == RunCancelled || next == RunErrored) {
		return nil
	}
	return fmt.Errorf("invalid run lifecycle transition %q -> %q", previous, next)
}
