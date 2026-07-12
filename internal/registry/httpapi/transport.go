package httpapi

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/internal/registry/store"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func (server *Server) authenticate(writer http.ResponseWriter, request *http.Request, scope domain.Scope, now time.Time) (domain.Principal, bool) {
	// Kept as a separate method to make every protected handler state its
	// exact required scope.  Query-string tokens are never accepted.
	if request.URL.Query().Has("token") || request.URL.Query().Has("access_token") {
		writeError(writer, http.StatusBadRequest, "query_token_forbidden", "Bearer tokens are not accepted in the query string")
		return domain.Principal{}, false
	}
	headers := request.Header.Values("Authorization")
	if len(headers) != 1 {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="agentapi-doctor-registry"`)
		writeError(writer, http.StatusUnauthorized, "invalid_token", "a single Bearer token is required")
		return domain.Principal{}, false
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) < 16 || len(parts[1]) > 4096 {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="agentapi-doctor-registry"`)
		writeError(writer, http.StatusUnauthorized, "invalid_token", "a valid Bearer token is required")
		return domain.Principal{}, false
	}
	hash := store.HashBearerToken(parts[1])
	principal, err := server.store.LookupBearerToken(request.Context(), hash, now)
	if err != nil {
		writeDomainError(writer, err)
		return domain.Principal{}, false
	}
	if err := principal.RequireScope(scope); err != nil {
		writeDomainError(writer, err)
		return domain.Principal{}, false
	}
	return principal, true
}

func (server *Server) readJSON(writer http.ResponseWriter, request *http.Request, limit int64, target any) bool {
	if !strictJSONContentType(request) {
		writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, http.StatusRequestEntityTooLarge, "body_too_large", "the request body exceeds the configured byte limit")
			return false
		}
		writeError(writer, http.StatusBadRequest, "invalid_body", "the request body could not be read")
		return false
	}
	if len(raw) == 0 {
		writeError(writer, http.StatusBadRequest, "empty_body", "a JSON request body is required")
		return false
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json", "the request body is not strict unambiguous JSON")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json_contract", "the JSON body has unknown, missing, or invalid fields")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(writer, http.StatusBadRequest, "invalid_json", "the request body must contain exactly one JSON value")
		return false
	}
	return true
}

func (server *Server) readObservationUpload(writer http.ResponseWriter, request *http.Request, limit int64) (registryObservation, bool) {
	if !strictJSONContentType(request) {
		writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return registryObservation{}, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, http.StatusRequestEntityTooLarge, "body_too_large", "the uploaded observation exceeds its prepared byte limit")
			return registryObservation{}, false
		}
		writeError(writer, http.StatusBadRequest, "invalid_body", "the observation upload could not be read")
		return registryObservation{}, false
	}
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json", "the observation is not strict unambiguous JSON")
		return registryObservation{}, false
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json", "the observation must be a JSON object")
		return registryObservation{}, false
	}
	allowed := []string{
		"schema_version", "observation_id", "observation_class_id", "subject", "test",
		"environment", "result", "manifest_digest", "provenance", "registry_derived",
	}
	for name := range members {
		if !slices.Contains(allowed, name) {
			writeError(writer, http.StatusBadRequest, "unknown_field", "the observation contains an unknown top-level field")
			return registryObservation{}, false
		}
	}
	var observation registryObservation
	if err := json.Unmarshal(canonical, &observation.Observation); err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "invalid_observation", "the observation ID or immutable projection is invalid")
		return registryObservation{}, false
	}
	observation.RawBytes = int64(len(raw))
	observation.UploadDigest = schema.NewDigest(raw)
	return observation, true
}

func strictJSONContentType(request *http.Request) bool {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 || request.Header.Get("Content-Encoding") != "" {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func (server *Server) randomToken(bytesCount int) (string, error) {
	raw := make([]byte, bytesCount)
	if _, err := io.ReadFull(server.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func challengeMatches(expected [32]byte, supplied string) bool {
	if len(supplied) < 16 || len(supplied) > 4096 {
		return false
	}
	actual := store.HashBearerToken(supplied)
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "encoding_failure", "the Registry response could not be encoded")
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(raw, '\n'))
}

func writePublicJSON(writer http.ResponseWriter, request *http.Request, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "encoding_failure", "the Registry response could not be encoded")
		return
	}
	writePublicBytes(writer, request, "application/json; charset=utf-8", append(raw, '\n'))
}

func writePublicBytes(writer http.ResponseWriter, request *http.Request, contentType string, raw []byte) {
	etag := `"` + string(schema.NewDigest(raw)) + `"`
	writer.Header().Set("ETag", etag)
	writer.Header().Set("Cache-Control", "public, max-age=60")
	writer.Header().Set("Content-Type", contentType)
	if etagMatches(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(raw)
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

func strictQuery(request *http.Request, allowed ...string) bool {
	for name := range request.URL.Query() {
		if !slices.Contains(allowed, name) {
			return false
		}
		if len(request.URL.Query()[name]) != 1 {
			return false
		}
	}
	return true
}

func validURLValue(value string, maxBytes int) bool {
	if len(value) > maxBytes || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return true
}

func internalError(writer http.ResponseWriter, err error) {
	_ = err // Never serialize the internal error or its potentially sensitive context.
	writeError(writer, http.StatusInternalServerError, "internal_error", "the Registry could not complete the request")
}

func requireNoRequestBody(writer http.ResponseWriter, request *http.Request) bool {
	if request.Body != nil && request.Body != http.NoBody {
		writeError(writer, http.StatusBadRequest, "unexpected_body", "this endpoint does not accept a request body")
		return false
	}
	return true
}
