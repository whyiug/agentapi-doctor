package redaction

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func newTestRedactor(t *testing.T) *Redactor {
	t.Helper()
	redactor, err := New([]string{"x-private-field"}, [][]byte{[]byte("CANARY-DO-NOT-PERSIST")})
	if err != nil {
		t.Fatal(err)
	}
	return redactor
}

func TestHeadersAndURLAreSanitized(t *testing.T) {
	redactor := newTestRedactor(t)
	headers, report := redactor.RedactHeaders(http.Header{
		"Authorization": []string{"Bearer synthetic-token-value"},
		"X-Trace":       []string{"safe"},
	})
	if headers.Get("Authorization") != Replacement || headers.Get("X-Trace") != "safe" || report.Empty() {
		t.Fatalf("unexpected header redaction: %#v %#v", headers, report)
	}
	parsed, _ := url.Parse("https://example.invalid/v1?api_key=synthetic&safe=value")
	output, report, err := redactor.RedactURL(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if output.Query().Get("api_key") != Replacement || output.Query().Get("safe") != "value" || report.Empty() {
		t.Fatalf("unexpected URL redaction: %s %#v", output, report)
	}
}

func TestJSONAndTextNeverPersistCanaryOrCredential(t *testing.T) {
	redactor := newTestRedactor(t)
	raw := []byte(`{"authorization":"Bearer top-secret-token","nested":{"refresh_token":"refresh-value"},"text":"CANARY-DO-NOT-PERSIST","safe":1}`)
	output, report, err := redactor.RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("top-secret-token"), []byte("refresh-value"), []byte("CANARY-DO-NOT-PERSIST")} {
		if bytes.Contains(output, forbidden) {
			t.Fatalf("secret remained in %s", output)
		}
	}
	if report.Empty() || bytes.Count(output, []byte(Replacement)) != 3 {
		t.Fatalf("unexpected report/output: %#v %s", report, output)
	}
	text, report := redactor.RedactText([]byte("Authorization: Bearer abcdefghijklmnop CANARY-DO-NOT-PERSIST"))
	if bytes.Contains(text, []byte("abcdefghijklmnop")) || bytes.Contains(text, []byte("CANARY")) || report.Empty() {
		t.Fatalf("text was not sanitized: %s %#v", text, report)
	}
}

func TestCanaryMinimumLength(t *testing.T) {
	if _, err := New(nil, [][]byte{[]byte("short")}); err == nil {
		t.Fatal("accepted low-entropy canary")
	}
}

func FuzzRedactionNeverReturnsConfiguredCanary(fuzz *testing.F) {
	const canary = "CANARY-DO-NOT-PERSIST"
	fuzz.Add([]byte(`{"authorization":"Bearer synthetic-token-value","value":"` + canary + `"}`))
	fuzz.Add([]byte("ordinary text"))
	fuzz.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		redactor, err := New(nil, [][]byte{[]byte(canary)})
		if err != nil {
			t.Fatal(err)
		}
		text, _ := redactor.RedactText(input)
		if bytes.Contains(text, []byte(canary)) {
			t.Fatal("text redaction returned the configured canary")
		}
		if json.Valid(input) {
			output, _, redactErr := redactor.RedactJSON(input)
			if redactErr != nil {
				return // valid JSON may be a scalar; JSON observations require objects elsewhere.
			}
			if !json.Valid(output) || bytes.Contains(output, []byte(canary)) {
				t.Fatal("JSON redaction returned invalid JSON or the configured canary")
			}
		}
	})
}
