package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// UTCTime is a canonical RFC 3339 timestamp.  JSON accepts only a Z suffix
// and rejects equivalent-but-noncanonical offsets or fractional padding.
type UTCTime struct {
	time.Time
}

func NewUTCTime(value time.Time) UTCTime {
	return UTCTime{Time: value.UTC()}
}

func (value UTCTime) IsZero() bool {
	return value.Time.IsZero()
}

func (value UTCTime) String() string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (value UTCTime) MarshalJSON() ([]byte, error) {
	if value.IsZero() {
		return nil, errors.New("UTC timestamp is required")
	}
	return json.Marshal(value.String())
}

func (value *UTCTime) UnmarshalJSON(raw []byte) error {
	if value == nil {
		return errors.New("cannot unmarshal UTC timestamp into nil receiver")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("UTC timestamp must be a JSON string: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return fmt.Errorf("invalid RFC 3339 timestamp: %w", err)
	}
	canonical := parsed.UTC().Format(time.RFC3339Nano)
	if text != canonical || !bytes.HasSuffix([]byte(text), []byte("Z")) {
		return fmt.Errorf("timestamp %q is not canonical UTC; expected %q", text, canonical)
	}
	value.Time = parsed.UTC()
	return nil
}
