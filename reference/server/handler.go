package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	SyntheticBearerToken = "synthetic-test-token"
	SyntheticAPIKey      = "synthetic-test-key"
)

type Config struct {
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	Transformer    Transformer
}

type Handler struct {
	maxBodyBytes   int64
	requestTimeout time.Duration
	transformer    Transformer
}

func New(config Config) (*Handler, error) {
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 2 * time.Second
	}
	if config.MaxBodyBytes < 1 || config.RequestTimeout <= 0 {
		return nil, errors.New("reference server body and time limits must be positive")
	}
	return &Handler{
		maxBodyBytes:   config.MaxBodyBytes,
		requestTimeout: config.RequestTimeout,
		transformer:    config.Transformer,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	if request.URL.RawQuery != "" || path.Clean(request.URL.Path) != request.URL.Path || strings.Contains(request.URL.Path, "\\") {
		writeError(writer, http.StatusBadRequest, "canonical_path_without_query_required")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !syntheticCredentialsOnly(request) {
		writeError(writer, http.StatusBadRequest, "real_credentials_not_accepted")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.requestTimeout)
	defer cancel()
	request = request.WithContext(ctx)

	var exchange Exchange
	var err error
	switch request.URL.Path {
	case "/v1/chat/completions":
		exchange, err = handler.buildChat(writer, request)
	case "/v1/responses":
		exchange, err = handler.buildResponses(writer, request)
	case "/v1/messages":
		if request.Header.Get("anthropic-version") != "2023-06-01" {
			writeError(writer, http.StatusBadRequest, "anthropic_version_required")
			return
		}
		exchange, err = handler.buildAnthropic(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		if errors.Is(err, errResponseWritten) {
			return
		}
		writeError(writer, http.StatusUnprocessableEntity, "invalid_fixture_request")
		return
	}
	select {
	case <-ctx.Done():
		writeError(writer, http.StatusRequestTimeout, "request_timeout")
		return
	default:
	}
	if handler.transformer != nil {
		if err := handler.transformer.Apply(&exchange); err != nil {
			writeError(writer, http.StatusUnprocessableEntity, "mutation_not_applicable")
			return
		}
		exchange.MutationID = handler.transformer.ID()
		writer.Header().Set("X-AgentAPI-Mutant", exchange.MutationID)
	}
	select {
	case <-ctx.Done():
		writeError(writer, http.StatusRequestTimeout, "request_timeout")
		return
	default:
	}
	writeExchange(writer, exchange)
}

var errResponseWritten = errors.New("HTTP error response already written")

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 || request.Header.Get("Content-Encoding") != "" {
		writeError(writer, http.StatusUnsupportedMediaType, "application_json_required")
		return errResponseWritten
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, "application_json_required")
		return errResponseWritten
	}
	for key, value := range parameters {
		if !strings.EqualFold(key, "charset") || !strings.EqualFold(value, "utf-8") {
			writeError(writer, http.StatusUnsupportedMediaType, "utf8_json_required")
			return errResponseWritten
		}
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxBodyBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeError(writer, http.StatusBadRequest, "invalid_body")
		}
		return errResponseWritten
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "ambiguous_json")
		return errResponseWritten
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json_contract")
		return errResponseWritten
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(writer, http.StatusBadRequest, "multiple_json_values")
		return errResponseWritten
	}
	return nil
}

func syntheticCredentialsOnly(request *http.Request) bool {
	for _, value := range request.Header.Values("Authorization") {
		if value != "Bearer "+SyntheticBearerToken {
			return false
		}
	}
	if len(request.Header.Values("Authorization")) > 1 {
		return false
	}
	for _, value := range request.Header.Values("x-api-key") {
		if value != SyntheticAPIKey {
			return false
		}
	}
	return len(request.Header.Values("x-api-key")) <= 1
}

func writeExchange(writer http.ResponseWriter, exchange Exchange) {
	for name, values := range exchange.Headers {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	status := exchange.Status
	if status == 0 {
		status = http.StatusOK
	}
	if !exchange.Streaming {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(exchange.JSON)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(status)
	for _, event := range exchange.Events {
		if event.Event != "" {
			_, _ = io.WriteString(writer, "event: "+event.Event+"\n")
		}
		data := event.RawData
		if data == nil {
			data, _ = json.Marshal(event.Data)
		}
		_, _ = writer.Write([]byte("data: "))
		_, _ = writer.Write(data)
		_, _ = writer.Write([]byte("\n\n"))
	}
	_, _ = writer.Write(exchange.RawSuffix)
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code}})
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-AgentAPI-Fixture", "non-authoritative-synthetic")
}
