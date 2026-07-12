package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/internal/registry/store"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(errorBody{Error: errorDetail{Code: code, Message: message}})
}

func writeDomainError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrUnauthenticated), errors.Is(err, store.ErrTokenExpired):
		writer.Header().Set("WWW-Authenticate", `Bearer realm="agentapi-doctor-registry"`)
		writeError(writer, http.StatusUnauthorized, "invalid_token", "a valid Bearer token is required")
	case errors.Is(err, domain.ErrForbidden), errors.Is(err, domain.ErrNotOwner):
		writeError(writer, http.StatusForbidden, "forbidden", "the authenticated principal is not authorized")
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "the requested Registry object was not found")
	case errors.Is(err, store.ErrInvalidCursor):
		writeError(writer, http.StatusBadRequest, "invalid_cursor", "the pagination cursor is invalid")
	case errors.Is(err, domain.ErrExpired):
		writeError(writer, http.StatusGone, "expired", "the Registry object has expired")
	case errors.Is(err, domain.ErrDigestMismatch):
		writeError(writer, http.StatusConflict, "digest_mismatch", "the submitted digest does not match the prepared digest")
	case errors.Is(err, domain.ErrInvalidTransition):
		writeError(writer, http.StatusConflict, "invalid_state", "the Registry object is not in a valid state for this operation")
	case errors.Is(err, domain.ErrConflict), errors.Is(err, store.ErrAlreadyExists):
		writeError(writer, http.StatusConflict, "conflict", "the operation conflicts with existing Registry state")
	case errors.Is(err, store.ErrNotImplemented):
		writeError(writer, http.StatusNotImplemented, "not_implemented", "this persistent hosted capability is not implemented")
	default:
		writeError(writer, http.StatusUnprocessableEntity, "invalid_request", "the request did not satisfy the Registry contract")
	}
}
