package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUTCTimeCanonicalJSON(t *testing.T) {
	value := NewUTCTime(time.Date(2026, 7, 12, 1, 2, 3, 120000000, time.FixedZone("offset", 8*60*60)))
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), `"2026-07-11T17:02:03.12Z"`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
	var decoded UTCTime
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`"2026-07-11T17:02:03+00:00"`, `"2026-07-11T17:02:03.120Z"`, `null`} {
		if err := json.Unmarshal([]byte(invalid), &decoded); err == nil {
			t.Fatalf("accepted noncanonical timestamp %s", invalid)
		}
	}
}
