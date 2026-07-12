package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/internal/registry/store"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

type registryObservation struct {
	registryapi.Observation
	RawBytes     int64
	UploadDigest schema.Digest
}

type prepareRequest struct {
	ObservationDigest schema.Digest `json:"observation_digest"`
	UploadDigest      schema.Digest `json:"upload_digest"`
	SizeBytes         int64         `json:"size_bytes"`
}

type prepareResponse struct {
	SessionID       schema.InstanceID  `json:"session_id"`
	ObservationID   schema.Digest      `json:"observation_digest"`
	UploadDigest    schema.Digest      `json:"upload_digest"`
	UploadURL       string             `json:"upload_url"`
	UploadChallenge string             `json:"upload_challenge"`
	ChallengeHeader string             `json:"challenge_header"`
	MaxBytes        int64              `json:"max_bytes"`
	ExpiresAt       time.Time          `json:"expires_at"`
	Ephemeral       bool               `json:"ephemeral"`
	Capabilities    store.Capabilities `json:"capabilities"`
}

func (server *Server) prepare(writer http.ResponseWriter, request *http.Request, now time.Time) {
	principal, ok := server.authenticate(writer, request, domain.ScopeObservationPrepare, now)
	if !ok {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	var input prepareRequest
	if !server.readJSON(writer, request, server.maxJSONBytes, &input) {
		return
	}
	if err := input.ObservationDigest.Validate(); err != nil || input.UploadDigest.Validate() != nil || input.SizeBytes < 1 || input.SizeBytes > server.maxUploadBytes {
		writeError(writer, http.StatusUnprocessableEntity, "invalid_prepare", "observation_digest, upload_digest, and an allowed positive size_bytes are required")
		return
	}
	sessionID, err := schema.NewInstanceID(func() time.Time { return now }, server.random)
	if err != nil {
		internalError(writer, err)
		return
	}
	challenge, err := server.randomToken(32)
	if err != nil {
		internalError(writer, err)
		return
	}
	expiresAt := now.Add(server.sessionTTL)
	session, err := domain.PrepareIngest(principal, sessionID, input.ObservationDigest, expiresAt, now)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := server.store.CreateIngest(request.Context(), store.IngestRecord{
		Session:       session,
		DeclaredBytes: input.SizeBytes,
		UploadDigest:  input.UploadDigest,
		ChallengeHash: store.HashBearerToken(challenge),
	}); err != nil {
		writeDomainError(writer, err)
		return
	}
	capabilities := server.store.Capabilities()
	writeJSON(writer, http.StatusCreated, prepareResponse{
		SessionID:       sessionID,
		ObservationID:   input.ObservationDigest,
		UploadDigest:    input.UploadDigest,
		UploadURL:       "/v1/uploads/" + string(sessionID),
		UploadChallenge: challenge,
		ChallengeHeader: "X-Upload-Challenge",
		MaxBytes:        input.SizeBytes,
		ExpiresAt:       expiresAt.UTC(),
		Ephemeral:       !capabilities.DurablePersistence,
		Capabilities:    capabilities,
	})
}

func (server *Server) stageUpload(writer http.ResponseWriter, request *http.Request, rawID string, now time.Time) {
	principal, ok := server.authenticate(writer, request, domain.ScopeObservationPrepare, now)
	if !ok {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	id, err := schema.ParseInstanceID(rawID)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_session_id", "session_id must be a canonical UUIDv7")
		return
	}
	record, err := server.store.GetIngest(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if record.Session.Snapshot().Owner != principal.ID() {
		writeDomainError(writer, domain.ErrNotOwner)
		return
	}
	challengeHeaders := request.Header.Values("X-Upload-Challenge")
	if len(challengeHeaders) != 1 || !challengeMatches(record.ChallengeHash, challengeHeaders[0]) {
		writeError(writer, http.StatusForbidden, "invalid_upload_challenge", "the upload challenge is invalid")
		return
	}
	observation, ok := server.readObservationUpload(writer, request, min(record.DeclaredBytes, server.maxUploadBytes))
	if !ok {
		return
	}
	if observation.RawBytes != record.DeclaredBytes {
		writeError(writer, http.StatusConflict, "size_mismatch", "the uploaded byte count does not match the prepared size")
		return
	}
	if observation.UploadDigest != record.UploadDigest {
		writeDomainError(writer, domain.ErrDigestMismatch)
		return
	}
	derived := observation.RegistryDerived()
	if len(derived.TrustLabels) != 0 || derived.Freshness != "" || derived.PublishedAt != nil || len(derived.DisputeIDs) != 0 || derived.SupersededBy != "" || derived.Tombstoned {
		writeError(writer, http.StatusUnprocessableEntity, "derived_fields_forbidden", "submitters cannot set Registry-derived observation fields")
		return
	}
	if observation.ID() != record.Session.Snapshot().ExpectedDigest {
		writeDomainError(writer, domain.ErrDigestMismatch)
		return
	}
	if _, err := record.Session.Stage(principal, observation.ID(), now); err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := server.store.UpdateIngest(request.Context(), record); err != nil {
		internalError(writer, err)
		return
	}
	if err := server.store.PutStagedObservation(request.Context(), id, observation.Observation); err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

type commitRequest struct {
	SessionID         schema.InstanceID `json:"session_id"`
	ObservationDigest schema.Digest     `json:"observation_digest"`
	UploadDigest      schema.Digest     `json:"upload_digest"`
}

type commitResponse struct {
	SessionID          schema.InstanceID   `json:"session_id"`
	ObservationDigest  schema.Digest       `json:"observation_digest"`
	Status             domain.IngestStatus `json:"status"`
	VerificationStatus string              `json:"verification_status"`
	Ephemeral          bool                `json:"ephemeral"`
	Capabilities       store.Capabilities  `json:"capabilities"`
}

func (server *Server) commit(writer http.ResponseWriter, request *http.Request, now time.Time) {
	principal, ok := server.authenticate(writer, request, domain.ScopeObservationCommit, now)
	if !ok {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	var input commitRequest
	if !server.readJSON(writer, request, server.maxJSONBytes, &input) {
		return
	}
	if err := input.SessionID.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_session_id", "session_id must be a canonical UUIDv7")
		return
	}
	if err := input.ObservationDigest.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_digest", "observation_digest must be a canonical sha256 digest")
		return
	}
	if err := input.UploadDigest.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_digest", "upload_digest must be a canonical sha256 digest")
		return
	}
	record, err := server.store.GetIngest(request.Context(), input.SessionID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if record.Session.Snapshot().Owner != principal.ID() {
		writeDomainError(writer, domain.ErrNotOwner)
		return
	}
	if input.UploadDigest != record.UploadDigest {
		writeDomainError(writer, domain.ErrDigestMismatch)
		return
	}
	staged, err := server.store.GetStagedObservation(request.Context(), input.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(writer, http.StatusConflict, "upload_not_staged", "the prepared observation has not been staged")
			return
		}
		writeDomainError(writer, err)
		return
	}
	if staged.ID() != input.ObservationDigest {
		writeDomainError(writer, domain.ErrDigestMismatch)
		return
	}
	snapshot, err := record.Session.Commit(principal, input.ObservationDigest, now)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := server.store.UpdateIngest(request.Context(), record); err != nil {
		internalError(writer, err)
		return
	}
	capabilities := server.store.Capabilities()
	if err := server.store.EnqueueVerification(request.Context(), input.SessionID); err != nil {
		if !errors.Is(err, store.ErrNotImplemented) {
			writeDomainError(writer, err)
			return
		}
		// The exact commit is retained according to the selected store's
		// capability so a retry is deterministic, but 2xx would falsely imply
		// that a durable verifier queue accepted the work.
		writeError(writer, http.StatusNotImplemented, "hosted_verifier_unavailable", verifierUnavailableMessage(capabilities))
		return
	}
	writeJSON(writer, http.StatusAccepted, commitResponse{
		SessionID:          input.SessionID,
		ObservationDigest:  input.ObservationDigest,
		Status:             snapshot.Status,
		VerificationStatus: "queued",
		Ephemeral:          !capabilities.DurablePersistence,
		Capabilities:       capabilities,
	})
}

func verifierUnavailableMessage(capabilities store.Capabilities) string {
	retention := "in memory"
	if capabilities.DurablePersistence {
		retention = "in durable local storage"
	}
	return "the exact commit was recorded " + retention + ", but hosted verification and publication are not configured"
}

func (server *Server) getObservation(writer http.ResponseWriter, request *http.Request, rawDigest string) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	digest, err := schema.ParseDigest(rawDigest)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_digest", "the observation digest is invalid")
		return
	}
	observation, err := server.store.GetObservation(request.Context(), digest)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writePublicJSON(writer, request, observation)
}

type observationListResponse struct {
	Items      []registryapi.Observation `json:"items"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

func (server *Server) listObservations(writer http.ResponseWriter, request *http.Request) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	allowed := []string{"subject", "version", "pack", "profile", "trust", "fresh", "cursor", "limit"}
	if !strictQuery(request, allowed...) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "the observation query contains unknown or repeated parameters")
		return
	}
	query := request.URL.Query()
	limit, ok := parseLimit(query.Get("limit"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "invalid_limit", "limit must be an integer between 1 and 100")
		return
	}
	filter := store.ObservationFilter{
		Subject: query.Get("subject"),
		Version: query.Get("version"),
		Pack:    query.Get("pack"),
		Profile: query.Get("profile"),
		Trust:   query.Get("trust"),
		Fresh:   query.Get("fresh"),
	}
	for _, value := range []string{filter.Subject, filter.Version, filter.Pack, filter.Profile, filter.Trust, filter.Fresh, query.Get("cursor")} {
		if !validURLValue(value, 1024) {
			writeError(writer, http.StatusBadRequest, "invalid_query", "a query value is invalid")
			return
		}
	}
	page, err := server.store.ListObservations(request.Context(), filter, query.Get("cursor"), limit)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writePublicJSON(writer, request, observationListResponse{Items: page.Items, NextCursor: page.NextCursor})
}

func (server *Server) getSubject(writer http.ResponseWriter, request *http.Request, owner, project string) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	if !strictQuery(request, "cursor", "limit") {
		writeError(writer, http.StatusBadRequest, "unknown_query", "the subject query contains unknown or repeated parameters")
		return
	}
	subject := domain.SubjectNamespace(owner + "/" + project)
	if err := subject.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_subject", "the subject namespace is invalid")
		return
	}
	limit, ok := parseLimit(request.URL.Query().Get("limit"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "invalid_limit", "limit must be an integer between 1 and 100")
		return
	}
	page, err := server.store.ListObservations(request.Context(), store.ObservationFilter{Subject: string(subject)}, request.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writePublicJSON(writer, request, struct {
		Subject    string                    `json:"subject"`
		Items      []registryapi.Observation `json:"observations"`
		NextCursor string                    `json:"next_cursor,omitempty"`
	}{string(subject), page.Items, page.NextCursor})
}

func parseLimit(raw string) (int, bool) {
	if raw == "" {
		return 25, true
	}
	value, err := strconv.Atoi(raw)
	return value, err == nil && value >= 1 && value <= 100
}

func (server *Server) getArtifact(writer http.ResponseWriter, request *http.Request, kind store.ArtifactKind, name, version string) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	if !validURLValue(name, 256) || !validURLValue(version, 128) || name == "" || version == "" {
		writeError(writer, http.StatusBadRequest, "invalid_artifact", "artifact name and version are invalid")
		return
	}
	artifact, err := server.store.GetArtifact(request.Context(), kind, name, version)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writePublicJSON(writer, request, struct {
		Kind     store.ArtifactKind `json:"kind"`
		Name     string             `json:"name"`
		Version  string             `json:"version"`
		Digest   schema.Digest      `json:"digest"`
		Document json.RawMessage    `json:"document"`
	}{artifact.Kind, artifact.Name, artifact.Version, artifact.Digest, json.RawMessage(artifact.Document)})
}

type ownershipChallengeRequest struct {
	Subject string                 `json:"subject"`
	Method  domain.OwnershipMethod `json:"method"`
}

func (server *Server) createOwnershipChallenge(writer http.ResponseWriter, request *http.Request, now time.Time) {
	principal, ok := server.authenticate(writer, request, domain.ScopeOwnershipManage, now)
	if !ok {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	var input ownershipChallengeRequest
	if !server.readJSON(writer, request, server.maxJSONBytes, &input) {
		return
	}
	subject := domain.SubjectNamespace(input.Subject)
	if err := subject.Validate(); err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "invalid_subject", "subject must be an exact owner/project namespace")
		return
	}
	id, err := schema.NewInstanceID(func() time.Time { return now }, server.random)
	if err != nil {
		internalError(writer, err)
		return
	}
	nonce, err := server.randomToken(32)
	if err != nil {
		internalError(writer, err)
		return
	}
	challenge, err := domain.NewOwnershipChallenge(principal, id, subject, input.Method, nonce, now.Add(server.challengeTTL), now)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := server.store.PutOwnershipChallenge(request.Context(), challenge); err != nil {
		writeDomainError(writer, err)
		return
	}
	snapshot := challenge.Snapshot(now)
	writeJSON(writer, http.StatusCreated, struct {
		ID                    schema.InstanceID       `json:"challenge_id"`
		Subject               domain.SubjectNamespace `json:"subject"`
		Method                domain.OwnershipMethod  `json:"method"`
		Nonce                 string                  `json:"nonce"`
		ExpiresAt             time.Time               `json:"expires_at"`
		Status                domain.ChallengeStatus  `json:"status"`
		VerificationAvailable bool                    `json:"verification_available"`
	}{snapshot.ID, snapshot.Subject, snapshot.Method, snapshot.Nonce, snapshot.ExpiresAt, snapshot.Status, server.store.Capabilities().OwnershipVerification})
}

type createDisputeRequest struct {
	ObservationID schema.Digest `json:"observation_id"`
	Statement     string        `json:"statement"`
}

func (server *Server) createDispute(writer http.ResponseWriter, request *http.Request, now time.Time) {
	principal, ok := server.authenticate(writer, request, domain.ScopeDisputeCreate, now)
	if !ok {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	var input createDisputeRequest
	if !server.readJSON(writer, request, server.maxJSONBytes, &input) {
		return
	}
	if err := input.ObservationID.Validate(); err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "invalid_observation", "observation_id must be a canonical sha256 digest")
		return
	}
	observation, err := server.store.GetObservation(request.Context(), input.ObservationID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	index, err := store.IndexObservation(observation)
	if err != nil {
		internalError(writer, err)
		return
	}
	subject := domain.SubjectNamespace(index.Subject)
	ownership, err := server.store.CurrentOwnership(request.Context(), subject, now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(writer, http.StatusConflict, "ownership_required", "a current verified subject owner is required before this dispute can be recorded")
			return
		}
		writeDomainError(writer, err)
		return
	}
	id, err := schema.NewInstanceID(func() time.Time { return now }, server.random)
	if err != nil {
		internalError(writer, err)
		return
	}
	dispute, err := domain.NewDispute(principal, id, input.ObservationID, subject, ownership.Snapshot().Owner, input.Statement, now)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if err := server.store.PutDispute(request.Context(), dispute); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, disputeResponse(dispute.Snapshot()))
}

func (server *Server) getDispute(writer http.ResponseWriter, request *http.Request, rawID string) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "this endpoint does not accept query parameters")
		return
	}
	id, err := schema.ParseInstanceID(rawID)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_dispute_id", "the dispute ID must be a canonical UUIDv7")
		return
	}
	dispute, err := server.store.GetDispute(request.Context(), id)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writePublicJSON(writer, request, disputeResponse(dispute.Snapshot()))
}

type disputeEventResponse struct {
	Sequence      uint64                  `json:"sequence"`
	Kind          domain.DisputeEventKind `json:"kind"`
	Actor         domain.PrincipalID      `json:"actor"`
	At            time.Time               `json:"at"`
	Statement     string                  `json:"statement,omitempty"`
	ReplacementID schema.Digest           `json:"replacement_id,omitempty"`
}

type disputeView struct {
	ID            schema.InstanceID       `json:"dispute_id"`
	ObservationID schema.Digest           `json:"observation_id"`
	Subject       domain.SubjectNamespace `json:"subject"`
	Status        domain.DisputeStatus    `json:"status"`
	Events        []disputeEventResponse  `json:"events"`
}

func disputeResponse(snapshot domain.DisputeSnapshot) disputeView {
	events := make([]disputeEventResponse, len(snapshot.Events))
	for index, event := range snapshot.Events {
		events[index] = disputeEventResponse{event.Sequence, event.Kind, event.Actor, event.At, event.Statement, event.ReplacementID}
	}
	return disputeView{snapshot.ID, snapshot.ObservationID, snapshot.Subject, snapshot.Status, events}
}

func (server *Server) getBadge(writer http.ResponseWriter, request *http.Request, owner, project, profile string) {
	if !requireNoRequestBody(writer, request) {
		return
	}
	if !strictQuery(request) {
		writeError(writer, http.StatusBadRequest, "unknown_query", "the badge endpoint does not accept query parameters")
		return
	}
	subject := domain.SubjectNamespace(owner + "/" + project)
	if err := subject.Validate(); err != nil || profile == "" || !validURLValue(profile, 256) {
		writeError(writer, http.StatusBadRequest, "invalid_badge", "the badge subject or profile is invalid")
		return
	}
	page, err := server.store.ListObservations(request.Context(), store.ObservationFilter{Subject: string(subject), Profile: profile}, "", 1)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if len(page.Items) == 0 {
		writeDomainError(writer, store.ErrNotFound)
		return
	}
	observation := page.Items[0]
	index, err := store.IndexObservation(observation)
	if err != nil {
		internalError(writer, err)
		return
	}
	trust := "self-reported"
	if len(index.TrustLabels) > 0 {
		trust = strings.Join(index.TrustLabels, ",")
	}
	freshness := index.Freshness
	if freshness == "" {
		freshness = "unknown"
	}
	label := fmt.Sprintf("%s / %s %s / %s / %s / %s", profile, index.Pack, index.PackVersion, freshness, trust, observation.ID())
	escaped := html.EscapeString(label)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="28" role="img" aria-label="` + escaped + `"><rect width="1200" height="28" fill="#24292f"/><text x="10" y="19" fill="#fff" font-family="Verdana,Arial,sans-serif" font-size="12">` + escaped + `</text></svg>`)
	writer.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	writePublicBytes(writer, request, "image/svg+xml; charset=utf-8", svg)
}
