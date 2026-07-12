// Package redaction sanitizes application-layer observations before any
// persistence boundary.  It never returns a hash of a detected secret.
package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const Replacement = "[REDACTED]"

var defaultSensitiveNames = []string{
	"authorization",
	"proxy-authorization",
	"x-api-key",
	"api-key",
	"api_key",
	"cookie",
	"set-cookie",
	"access_token",
	"refresh_token",
	"client_secret",
	"password",
	"secret",
	"token",
}

var detectors = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{id: "private-key", pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)},
	{id: "bearer-token", pattern: regexp.MustCompile(`(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{8,}`)},
	{id: "jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{id: "github-token", pattern: regexp.MustCompile(`\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)},
	{id: "aws-access-key", pattern: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
}

type Finding struct {
	RuleID string
	Count  int
}

type Report struct {
	Findings []Finding
}

func (report Report) Empty() bool { return len(report.Findings) == 0 }

// SanitizedPayload is the only payload type accepted by the evidence CAS.
// Its bytes are unexported so callers must pass through a Redactor constructor.
type SanitizedPayload struct {
	data   []byte
	report Report
	class  string
}

func (payload SanitizedPayload) Bytes() []byte  { return append([]byte(nil), payload.data...) }
func (payload SanitizedPayload) Size() int      { return len(payload.data) }
func (payload SanitizedPayload) Report() Report { return payload.report }
func (payload SanitizedPayload) Class() string  { return payload.class }

type Redactor struct {
	sensitiveNames map[string]struct{}
	canaries       [][]byte
}

func New(extraNames []string, canaries [][]byte) (*Redactor, error) {
	names := make(map[string]struct{}, len(defaultSensitiveNames)+len(extraNames))
	for _, name := range append(append([]string(nil), defaultSensitiveNames...), extraNames...) {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized == "" {
			return nil, errors.New("sensitive field name cannot be empty")
		}
		names[normalized] = struct{}{}
	}
	copyCanaries := make([][]byte, 0, len(canaries))
	for _, canary := range canaries {
		if len(canary) < 8 {
			return nil, errors.New("secret canary must contain at least 8 bytes")
		}
		copyCanaries = append(copyCanaries, append([]byte(nil), canary...))
	}
	return &Redactor{sensitiveNames: names, canaries: copyCanaries}, nil
}

func (redactor *Redactor) RedactHeaders(headers http.Header) (http.Header, Report) {
	output := make(http.Header, len(headers))
	counts := map[string]int{}
	for name, values := range headers {
		if redactor.isSensitiveName(name) {
			output[name] = []string{Replacement}
			counts["sensitive-header"] += len(values)
			continue
		}
		for _, value := range values {
			sanitized, report := redactor.RedactText([]byte(value))
			output.Add(name, string(sanitized))
			mergeCounts(counts, report)
		}
	}
	return output, makeReport(counts)
}

func (redactor *Redactor) RedactURL(input *url.URL) (*url.URL, Report, error) {
	if input == nil {
		return nil, Report{}, errors.New("URL is required")
	}
	output := *input
	output.User = nil
	query := output.Query()
	counts := map[string]int{}
	for name, values := range query {
		if redactor.isSensitiveName(name) {
			query[name] = []string{Replacement}
			counts["sensitive-query"] += len(values)
			continue
		}
		for index, value := range values {
			sanitized, report := redactor.RedactText([]byte(value))
			query[name][index] = string(sanitized)
			mergeCounts(counts, report)
		}
	}
	output.RawQuery = query.Encode()
	return &output, makeReport(counts), nil
}

func (redactor *Redactor) RedactJSON(raw []byte) ([]byte, Report, error) {
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		return nil, Report{}, fmt.Errorf("validate JSON for redaction: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, Report{}, fmt.Errorf("decode JSON for redaction: %w", err)
	}
	counts := map[string]int{}
	redactor.walk(value, counts)
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, Report{}, fmt.Errorf("encode redacted JSON: %w", err)
	}
	if err := redactor.AssertNoCanary(encoded); err != nil {
		return nil, Report{}, err
	}
	return encoded, makeReport(counts), nil
}

func (redactor *Redactor) SanitizeJSON(raw []byte) (SanitizedPayload, error) {
	data, report, err := redactor.RedactJSON(raw)
	if err != nil {
		return SanitizedPayload{}, err
	}
	return SanitizedPayload{data: data, report: report, class: "redacted_json"}, nil
}

func (redactor *Redactor) SanitizeText(raw []byte) (SanitizedPayload, error) {
	data, report := redactor.RedactText(raw)
	if err := redactor.AssertNoCanary(data); err != nil {
		return SanitizedPayload{}, err
	}
	return SanitizedPayload{data: data, report: report, class: "redacted_text"}, nil
}

func (redactor *Redactor) walk(value any, counts map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if redactor.isSensitiveName(key) {
				typed[key] = Replacement
				counts["sensitive-json-field"]++
				continue
			}
			redactor.walk(item, counts)
		}
	case []any:
		for _, item := range typed {
			redactor.walk(item, counts)
		}
	case string:
		// A non-sensitive field can still contain a structured credential.
		// The parent container is updated by redactCompositeStrings.
	}
	redactor.redactCompositeStrings(value, counts)
}

func (redactor *Redactor) redactCompositeStrings(value any, counts map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			text, ok := item.(string)
			if !ok || text == Replacement {
				continue
			}
			sanitized, report := redactor.RedactText([]byte(text))
			typed[key] = string(sanitized)
			mergeCounts(counts, report)
		}
	case []any:
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				continue
			}
			sanitized, report := redactor.RedactText([]byte(text))
			typed[index] = string(sanitized)
			mergeCounts(counts, report)
		}
	}
}

func (redactor *Redactor) RedactText(raw []byte) ([]byte, Report) {
	output := append([]byte(nil), raw...)
	counts := map[string]int{}
	for _, detector := range detectors {
		matches := detector.pattern.FindAllIndex(output, -1)
		if len(matches) == 0 {
			continue
		}
		output = detector.pattern.ReplaceAll(output, []byte(Replacement))
		counts[detector.id] += len(matches)
	}
	for _, canary := range redactor.canaries {
		count := bytes.Count(output, canary)
		if count > 0 {
			output = bytes.ReplaceAll(output, canary, []byte(Replacement))
			counts["secret-canary"] += count
		}
	}
	return output, makeReport(counts)
}

func (redactor *Redactor) AssertNoCanary(raw []byte) error {
	for _, canary := range redactor.canaries {
		if bytes.Contains(raw, canary) {
			return errors.New("secret canary remained after redaction")
		}
	}
	return nil
}

func (redactor *Redactor) isSensitiveName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if _, exists := redactor.sensitiveNames[normalized]; exists {
		return true
	}
	for _, suffix := range []string{"_token", "-token", "_secret", "-secret", "_password", "-password", "_api_key", "-api-key"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func mergeCounts(counts map[string]int, report Report) {
	for _, finding := range report.Findings {
		counts[finding.RuleID] += finding.Count
	}
}

func makeReport(counts map[string]int) Report {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	report := Report{Findings: make([]Finding, 0, len(keys))}
	for _, key := range keys {
		report.Findings = append(report.Findings, Finding{RuleID: key, Count: counts[key]})
	}
	return report
}
