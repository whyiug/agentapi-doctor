package schema

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanonicalizeRFC8785Vector(t *testing.T) {
	raw := []byte(`{
      "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
      "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
      "literals": [null, true, false]
    }`)
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := CanonicalizeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestCanonicalizeRejectsAmbiguousJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "duplicate", raw: []byte(`{"a":1,"a":2}`), want: ErrDuplicateJSONKey},
		{name: "trailing", raw: []byte(`{} []`), want: ErrTrailingJSONValue},
		{name: "invalid utf8", raw: []byte{'{', '"', 0xff, '"', ':', '1', '}'}, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalizeJSON(test.raw)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestUUIDv7GenerationAndParsing(t *testing.T) {
	id, err := NewInstanceID(func() time.Time { return time.UnixMilli(0) }, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(id), "00000000-0000-7000-8000-000000000000"; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
	if _, err := ParseInstanceID(string(id)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"latest", strings.ToUpper("0190abcd-abcd-7abc-8abc-abcdefabcdef"), "00000000-0000-6000-8000-000000000000"} {
		if _, err := ParseInstanceID(invalid); err == nil {
			t.Fatalf("accepted invalid instance ID %q", invalid)
		}
	}
}
