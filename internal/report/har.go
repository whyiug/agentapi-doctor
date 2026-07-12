package report

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
)

// HTTPExchange can only be constructed from payloads that crossed the
// redaction boundary. URL and headers are intentionally omitted because their
// independent sanitization belongs to the recorder.
type HTTPExchange struct {
	started  time.Time
	duration time.Duration
	method   string
	status   int
	request  redaction.SanitizedPayload
	response redaction.SanitizedPayload
}

func NewHTTPExchange(started time.Time, duration time.Duration, method string, status int, request, response redaction.SanitizedPayload) (HTTPExchange, error) {
	if started.IsZero() || duration < 0 || method == "" || status < 100 || status > 599 || request.Size() == 0 || response.Size() == 0 {
		return HTTPExchange{}, errors.New("HAR exchange requires time, method, valid status, and sanitized payloads")
	}
	return HTTPExchange{started: started.UTC(), duration: duration, method: method, status: status, request: request, response: response}, nil
}

func HAR(exchanges []HTTPExchange) ([]byte, error) {
	type content struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	}
	type request struct {
		Method      string  `json:"method"`
		URL         string  `json:"url"`
		HTTPVersion string  `json:"httpVersion"`
		Headers     []any   `json:"headers"`
		QueryString []any   `json:"queryString"`
		Cookies     []any   `json:"cookies"`
		HeadersSize int     `json:"headersSize"`
		BodySize    int     `json:"bodySize"`
		PostData    content `json:"postData"`
	}
	type response struct {
		Status      int     `json:"status"`
		StatusText  string  `json:"statusText"`
		HTTPVersion string  `json:"httpVersion"`
		Headers     []any   `json:"headers"`
		Cookies     []any   `json:"cookies"`
		Content     content `json:"content"`
		RedirectURL string  `json:"redirectURL"`
		HeadersSize int     `json:"headersSize"`
		BodySize    int     `json:"bodySize"`
	}
	type entry struct {
		Started  string             `json:"startedDateTime"`
		Time     float64            `json:"time"`
		Request  request            `json:"request"`
		Response response           `json:"response"`
		Cache    map[string]any     `json:"cache"`
		Timings  map[string]float64 `json:"timings"`
		Comment  string             `json:"comment"`
	}
	entries := make([]entry, 0, len(exchanges))
	for _, exchange := range exchanges {
		req := exchange.request.Bytes()
		resp := exchange.response.Bytes()
		entries = append(entries, entry{Started: exchange.started.Format(time.RFC3339Nano), Time: float64(exchange.duration.Microseconds()) / 1000, Request: request{Method: exchange.method, URL: "urn:agentapi-doctor:redacted-target", HTTPVersion: "HTTP/1.1", Headers: []any{}, QueryString: []any{}, Cookies: []any{}, HeadersSize: -1, BodySize: len(req), PostData: content{Size: len(req), MimeType: "application/json", Text: string(req)}}, Response: response{Status: exchange.status, StatusText: "", HTTPVersion: "HTTP/1.1", Headers: []any{}, Cookies: []any{}, Content: content{Size: len(resp), MimeType: "application/json", Text: string(resp)}, HeadersSize: -1, BodySize: len(resp)}, Cache: map[string]any{}, Timings: map[string]float64{"send": 0, "wait": float64(exchange.duration.Microseconds()) / 1000, "receive": 0}, Comment: "URL and headers omitted by the privacy boundary"})
	}
	return json.MarshalIndent(map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "agentapi-doctor", "version": "0.1.0"}, "entries": entries}}, "", "  ")
}
