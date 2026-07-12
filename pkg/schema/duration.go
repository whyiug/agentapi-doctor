package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Duration is a positive, canonical Go-style duration used by authored and
// resolved plans.  It serializes as a string (for example, "15m0s").
type Duration time.Duration

func NewDuration(value time.Duration) Duration { return Duration(value) }
func (value Duration) Duration() time.Duration { return time.Duration(value) }
func (value Duration) String() string          { return time.Duration(value).String() }

func (value Duration) Validate() error {
	if value <= 0 {
		return errors.New("duration must be positive")
	}
	return nil
}

func (value Duration) MarshalJSON() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value.String())
}

func (value *Duration) UnmarshalJSON(raw []byte) error {
	if value == nil {
		return errors.New("cannot unmarshal duration into nil receiver")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("duration must be a JSON string: %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	canonical := parsed.String()
	if text != canonical {
		return fmt.Errorf("duration %q is not canonical; expected %q", text, canonical)
	}
	if parsed <= 0 {
		return errors.New("duration must be positive")
	}
	*value = Duration(parsed)
	return nil
}

func (value Duration) MarshalText() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return []byte(value.String()), nil
}

func (value *Duration) UnmarshalText(raw []byte) error {
	if value == nil {
		return errors.New("cannot unmarshal duration into nil receiver")
	}
	parsed, err := time.ParseDuration(string(raw))
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	if parsed <= 0 {
		return errors.New("duration must be positive")
	}
	if string(raw) != parsed.String() {
		return fmt.Errorf("duration %q is not canonical; expected %q", raw, parsed.String())
	}
	*value = Duration(parsed)
	return nil
}
