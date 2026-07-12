package schema

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// InstanceID is a UUIDv7 used for Run, Invocation, Attempt, and other event
// instances.  Content-addressed objects additionally carry a Digest.
type InstanceID string

var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// NewInstanceID creates a UUIDv7 using the supplied wall clock and CSPRNG.
// Passing nil selects time.Now and crypto/rand.Reader.
func NewInstanceID(now func() time.Time, random io.Reader) (InstanceID, error) {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	millis := now().UTC().UnixMilli()
	if millis < 0 || millis >= 1<<48 {
		return "", errors.New("UUIDv7 timestamp is outside the 48-bit range")
	}
	var raw [16]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", fmt.Errorf("read UUIDv7 randomness: %w", err)
	}
	raw[0] = byte(millis >> 40)
	raw[1] = byte(millis >> 32)
	raw[2] = byte(millis >> 24)
	raw[3] = byte(millis >> 16)
	raw[4] = byte(millis >> 8)
	raw[5] = byte(millis)
	raw[6] = (raw[6] & 0x0f) | 0x70
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return InstanceID(encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]), nil
}

// ParseInstanceID accepts a canonical lowercase UUIDv7.  The reserved run
// reference "latest" is intentionally not an InstanceID.
func ParseInstanceID(value string) (InstanceID, error) {
	if strings.EqualFold(value, "latest") {
		return "", errors.New("latest is a run reference, not an instance ID")
	}
	if !uuidV7Pattern.MatchString(value) {
		return "", fmt.Errorf("invalid UUIDv7 instance ID %q", value)
	}
	return InstanceID(value), nil
}

func (id InstanceID) Validate() error {
	_, err := ParseInstanceID(string(id))
	return err
}
