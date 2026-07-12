package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/internal/registry/store"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
)

const (
	ownerToken       = "owner-token-000000000000"
	attackerToken    = "attacker-token-00000000"
	reporterToken    = "reporter-token-00000000"
	prepareOnlyToken = "prepare-only-0000000000"
)

var httpTestNow = time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)

type deterministicReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *deterministicReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for index := range target {
		reader.next++
		target[index] = reader.next
	}
	return len(target), nil
}

type testHarness struct {
	handler  http.Handler
	memory   *store.Memory
	owner    domain.Principal
	attacker domain.Principal
	reporter domain.Principal
}

func newHarness(t *testing.T, mutate func(*Config)) testHarness {
	t.Helper()
	memory := store.NewMemory()
	owner := mustPrincipal(t, "owner", domain.ScopeObservationPrepare, domain.ScopeObservationCommit, domain.ScopeOwnershipManage, domain.ScopeDisputeCreate)
	attacker := mustPrincipal(t, "attacker", domain.ScopeObservationPrepare, domain.ScopeObservationCommit)
	reporter := mustPrincipal(t, "reporter", domain.ScopeDisputeCreate)
	prepareOnly := mustPrincipal(t, "prepare-only", domain.ScopeObservationPrepare)
	for token, principal := range map[string]domain.Principal{
		ownerToken: owner, attackerToken: attacker, reporterToken: reporter, prepareOnlyToken: prepareOnly,
	} {
		if err := memory.AddBearerToken(token, principal, httpTestNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{
		Store:          memory,
		Clock:          func() time.Time { return httpTestNow },
		Random:         &deterministicReader{},
		MaxJSONBytes:   1024,
		MaxUploadBytes: 16 << 10,
		RateLimit:      1000,
		RateWindow:     time.Minute,
	}
	if mutate != nil {
		mutate(&config)
	}
	handler, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return testHarness{handler: handler, memory: memory, owner: owner, attacker: attacker, reporter: reporter}
}

func mustPrincipal(t *testing.T, id string, scopes ...domain.Scope) domain.Principal {
	t.Helper()
	principal, err := domain.NewPrincipal(domain.PrincipalID(id), scopes...)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func mustCanonicalObject(t *testing.T, value any) registryapi.CanonicalObject {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	object, err := registryapi.ParseCanonicalObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func syntheticObservation(t *testing.T, subject, version, pack, packVersion, profile string) registryapi.Observation {
	t.Helper()
	observation, err := registryapi.NewObservation(registryapi.ObservationProjection{
		SchemaVersion: registryapi.ObservationSchemaV1,
		Subject: mustCanonicalObject(t, map[string]any{
			"project": subject,
			"version": version,
		}),
		Test: mustCanonicalObject(t, map[string]any{
			"pack":         pack,
			"pack_version": packVersion,
			"profile":      profile,
		}),
		Environment: mustCanonicalObject(t, map[string]any{
			"arch": "amd64",
			"os":   "synthetic-local",
		}),
		Result: mustCanonicalObject(t, map[string]any{
			"profile_outcome": "inconclusive",
			"verdict_counts":  map[string]int{"inconclusive": 1},
		}),
		ManifestDigest: schema.NewDigest([]byte("synthetic-local-manifest-" + version + profile)),
	}, schema.NewDigest([]byte("synthetic-local-class-"+version+profile)), nil, registryapi.RegistryDerived{
		TrustLabels: []string{"self-reported"},
		Freshness:   registryapi.FreshnessFresh,
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func uploadableObservation(t *testing.T, observation registryapi.Observation) registryapi.Observation {
	t.Helper()
	uploadable, err := observation.WithRegistryDerived(registryapi.RegistryDerived{})
	if err != nil {
		t.Fatal(err)
	}
	return uploadable
}

func serve(handler http.Handler, method, target string, body []byte, token, contentType string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.RemoteAddr = "127.0.0.1:54321"
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type preparedUpload struct {
	SessionID       string `json:"session_id"`
	UploadURL       string `json:"upload_url"`
	UploadChallenge string `json:"upload_challenge"`
	UploadDigest    string `json:"upload_digest"`
	Ephemeral       bool   `json:"ephemeral"`
}

func prepareObservation(t *testing.T, harness testHarness, observation registryapi.Observation) (preparedUpload, []byte) {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := json.Marshal(prepareRequest{ObservationDigest: observation.ID(), UploadDigest: schema.NewDigest(raw), SizeBytes: int64(len(raw))})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(harness.handler, http.MethodPost, "/v1/observations:prepare", requestBody, ownerToken, "application/json; charset=utf-8")
	if response.Code != http.StatusCreated {
		t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
	}
	var prepared preparedUpload
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	if !prepared.Ephemeral || !strings.HasPrefix(prepared.UploadURL, "/v1/uploads/") {
		t.Fatalf("prepare did not disclose safe ephemeral upload: %#v", prepared)
	}
	return prepared, raw
}

func stagePrepared(t *testing.T, harness testHarness, prepared preparedUpload, raw []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, prepared.UploadURL, bytes.NewReader(raw))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Upload-Challenge", prepared.UploadChallenge)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func TestPrepareStageCommitIsOwnedExactAndIdempotent(t *testing.T) {
	harness := newHarness(t, nil)
	observation := uploadableObservation(t, syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses"))
	prepared, raw := prepareObservation(t, harness, observation)

	if response := stagePrepared(t, harness, prepared, raw, attackerToken); response.Code != http.StatusForbidden {
		t.Fatalf("attacker staged owner session: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := stagePrepared(t, harness, prepared, raw, ownerToken); response.Code != http.StatusNoContent {
		t.Fatalf("stage status=%d body=%s", response.Code, response.Body.String())
	}

	commitBody, err := json.Marshal(commitRequest{SessionID: schema.InstanceID(prepared.SessionID), ObservationDigest: observation.ID(), UploadDigest: schema.Digest(prepared.UploadDigest)})
	if err != nil {
		t.Fatal(err)
	}
	if response := serve(harness.handler, http.MethodPost, "/v1/observations:commit", commitBody, attackerToken, "application/json"); response.Code != http.StatusForbidden {
		t.Fatalf("attacker committed owner session: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serve(harness.handler, http.MethodPost, "/v1/observations:commit", commitBody, prepareOnlyToken, "application/json"); response.Code != http.StatusForbidden {
		t.Fatalf("prepare-only token used commit scope: status=%d body=%s", response.Code, response.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := serve(harness.handler, http.MethodPost, "/v1/observations:commit", commitBody, ownerToken, "application/json")
		if response.Code != http.StatusNotImplemented {
			t.Fatalf("commit %d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"code":"hosted_verifier_unavailable"`) {
			t.Fatalf("commit hid unavailable hosted verifier: %s", response.Body.String())
		}
	}
	sessionID, err := schema.ParseInstanceID(prepared.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := harness.memory.GetIngest(t.Context(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := record.Session.Snapshot().Status; got != domain.IngestCommitted {
		t.Fatalf("exact idempotent commit was not retained: %s", got)
	}
	if response := serve(harness.handler, http.MethodGet, "/v1/observations/"+string(observation.ID()), nil, "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("commit falsely published unverified observation: status=%d", response.Code)
	}
}

func TestVerifierUnavailableMessageMatchesPersistenceCapability(t *testing.T) {
	if message := verifierUnavailableMessage(store.Capabilities{}); !strings.Contains(message, "recorded in memory") || strings.Contains(message, "durable") {
		t.Fatalf("ephemeral message is misleading: %q", message)
	}
	if message := verifierUnavailableMessage(store.Capabilities{DurablePersistence: true}); !strings.Contains(message, "recorded in durable local storage") {
		t.Fatalf("durable message is misleading: %q", message)
	}
}

func TestPrepareAndUploadEnforceAuthContentTypeStrictJSONAndQuota(t *testing.T) {
	harness := newHarness(t, func(config *Config) { config.MaxJSONBytes = 512 })
	validDigest := schema.NewDigest([]byte("synthetic-local-observation"))
	uploadDigest := schema.NewDigest([]byte("synthetic-local-upload"))
	validBody := []byte(fmt.Sprintf(`{"observation_digest":%q,"upload_digest":%q,"size_bytes":128}`, validDigest, uploadDigest))

	tests := []struct {
		name        string
		body        []byte
		token       string
		contentType string
		want        int
	}{
		{name: "missing auth", body: validBody, contentType: "application/json", want: http.StatusUnauthorized},
		{name: "wrong content type", body: validBody, token: ownerToken, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "wrong charset", body: validBody, token: ownerToken, contentType: "application/json; charset=iso-8859-1", want: http.StatusUnsupportedMediaType},
		{name: "unknown field", body: []byte(fmt.Sprintf(`{"observation_digest":%q,"upload_digest":%q,"size_bytes":128,"endpoint_url":"http://127.0.0.1"}`, validDigest, uploadDigest)), token: ownerToken, contentType: "application/json", want: http.StatusBadRequest},
		{name: "duplicate key", body: []byte(fmt.Sprintf(`{"observation_digest":%q,"observation_digest":%q,"upload_digest":%q,"size_bytes":128}`, validDigest, validDigest, uploadDigest)), token: ownerToken, contentType: "application/json", want: http.StatusBadRequest},
		{name: "body quota", body: []byte(`{"observation_digest":"` + strings.Repeat("a", 800) + `","size_bytes":128}`), token: ownerToken, contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(harness.handler, http.MethodPost, "/v1/observations:prepare", test.body, test.token, test.contentType)
			if response.Code != test.want {
				t.Fatalf("want %d, got %d: %s", test.want, response.Code, response.Body.String())
			}
			assertSecurityHeaders(t, response)
		})
	}

	response := serve(harness.handler, http.MethodPost, "/v1/observations:prepare?access_token=forbidden", validBody, ownerToken, "application/json")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "query_token_forbidden") {
		t.Fatalf("query token was not explicitly rejected: status=%d body=%s", response.Code, response.Body.String())
	}
	encodedRequest := httptest.NewRequest(http.MethodPost, "/v1/observations:prepare", bytes.NewReader(validBody))
	encodedRequest.RemoteAddr = "127.0.0.1:54321"
	encodedRequest.Header.Set("Authorization", "Bearer "+ownerToken)
	encodedRequest.Header.Set("Content-Type", "application/json")
	encodedRequest.Header.Set("Content-Encoding", "gzip")
	encodedResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(encodedResponse, encodedRequest)
	if encodedResponse.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("encoded request was accepted: status=%d body=%s", encodedResponse.Code, encodedResponse.Body.String())
	}

	observation := uploadableObservation(t, syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses"))
	prepared, raw := prepareObservationWithSize(t, harness, observation, int64(lenMust(t, rawObservation(t, observation))-1))
	_ = raw
	response = stagePrepared(t, harness, prepared, rawObservation(t, observation), ownerToken)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload quota status=%d body=%s", response.Code, response.Body.String())
	}
}

func rawObservation(t *testing.T, observation registryapi.Observation) []byte {
	t.Helper()
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func lenMust(_ *testing.T, value []byte) int { return len(value) }

func prepareObservationWithSize(t *testing.T, harness testHarness, observation registryapi.Observation, size int64) (preparedUpload, []byte) {
	t.Helper()
	raw := rawObservation(t, observation)
	body, err := json.Marshal(prepareRequest{ObservationDigest: observation.ID(), UploadDigest: schema.NewDigest(raw), SizeBytes: size})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(harness.handler, http.MethodPost, "/v1/observations:prepare", body, ownerToken, "application/json")
	if response.Code != http.StatusCreated {
		t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
	}
	var prepared preparedUpload
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	return prepared, raw
}

func TestUploadRejectsUnknownObservationFieldAndWrongChallenge(t *testing.T) {
	harness := newHarness(t, nil)
	observation := uploadableObservation(t, syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses"))
	raw := rawObservation(t, observation)
	mutated := append([]byte(`{"unexpected":"value",`), raw[1:]...)
	prepared, _ := prepareObservationWithSize(t, harness, observation, int64(len(mutated)))

	request := httptest.NewRequest(http.MethodPut, prepared.UploadURL, bytes.NewReader(mutated))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Authorization", "Bearer "+ownerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Upload-Challenge", prepared.UploadChallenge+"wrong")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong challenge status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, prepared.UploadURL, bytes.NewReader(mutated))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Authorization", "Bearer "+ownerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Upload-Challenge", prepared.UploadChallenge)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "unknown_field") {
		t.Fatalf("unknown observation field status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUploadBindsExactBytesAndRejectsSubmitterDerivedFields(t *testing.T) {
	harness := newHarness(t, nil)
	base := uploadableObservation(t, syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses"))
	attestationDigest := schema.NewDigest([]byte("synthetic-local-attestation"))
	preparedObservation, err := base.WithAttestation(registryapi.AttestationReference{Digest: attestationDigest, URI: "oci://synthetic.invalid/a"})
	if err != nil {
		t.Fatal(err)
	}
	mutatedObservation, err := base.WithAttestation(registryapi.AttestationReference{Digest: attestationDigest, URI: "oci://synthetic.invalid/b"})
	if err != nil {
		t.Fatal(err)
	}
	prepared, preparedRaw := prepareObservation(t, harness, preparedObservation)
	mutatedRaw := rawObservation(t, mutatedObservation)
	if len(preparedRaw) != len(mutatedRaw) || preparedObservation.ID() != mutatedObservation.ID() {
		t.Fatal("exact-byte mutation fixture must preserve size and immutable observation ID")
	}
	response := stagePrepared(t, harness, prepared, mutatedRaw, ownerToken)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "digest_mismatch") {
		t.Fatalf("exact upload digest was not enforced: status=%d body=%s", response.Code, response.Body.String())
	}

	derived := syntheticObservation(t, "example/runtime", "1.1.0", "responses", "2026.07.0", "codex.responses")
	prepared, raw := prepareObservation(t, harness, derived)
	response = stagePrepared(t, harness, prepared, raw, ownerToken)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "derived_fields_forbidden") {
		t.Fatalf("submitter-controlled trust/freshness accepted: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPublicReadListSubjectArtifactsBadgeAndETag(t *testing.T) {
	harness := newHarness(t, nil)
	first := syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses")
	second := syntheticObservation(t, "example/runtime", "1.1.0", "responses", "2026.07.0", "codex.responses")
	for _, observation := range []registryapi.Observation{first, second} {
		if err := harness.memory.PutPublishedObservation(t.Context(), observation); err != nil {
			t.Fatal(err)
		}
	}

	response := serve(harness.handler, http.MethodGet, "/v1/observations/"+string(first.ID()), nil, "", "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("get status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	assertSecurityHeaders(t, response)
	request := httptest.NewRequest(http.MethodGet, "/v1/observations/"+string(first.ID()), nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("If-None-Match", response.Header().Get("ETag"))
	notModified := httptest.NewRecorder()
	harness.handler.ServeHTTP(notModified, request)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("conditional GET status=%d body=%s", notModified.Code, notModified.Body.String())
	}

	response = serve(harness.handler, http.MethodGet, "/v1/observations?subject=example%2Fruntime&limit=1", nil, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	var page struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("pagination contract failed: %#v", page)
	}
	response = serve(harness.handler, http.MethodGet, "/v1/observations?subject=example%2Fruntime&limit=1&cursor="+url.QueryEscape(page.NextCursor), nil, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("second page status=%d body=%s", response.Code, response.Body.String())
	}
	var finalPage struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &finalPage); err != nil {
		t.Fatal(err)
	}
	if len(finalPage.Items) != 1 || finalPage.NextCursor != "" {
		t.Fatalf("final pagination page %#v", finalPage)
	}
	response = serve(harness.handler, http.MethodGet, "/v1/observations?cursor=not-base64", nil, "", "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_cursor") {
		t.Fatalf("invalid cursor status=%d body=%s", response.Code, response.Body.String())
	}
	response = serve(harness.handler, http.MethodGet, "/v1/subjects/example/runtime?limit=100", nil, "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"subject":"example/runtime"`) {
		t.Fatalf("subject status=%d body=%s", response.Code, response.Body.String())
	}

	for kind, endpoint := range map[store.ArtifactKind]string{
		store.ArtifactPack:    "/v1/packs/responses/2026.07.0",
		store.ArtifactProfile: "/v1/profiles/codex.responses/1.0.0",
	} {
		name, version := "responses", "2026.07.0"
		if kind == store.ArtifactProfile {
			name, version = "codex.responses", "1.0.0"
		}
		document := []byte(fmt.Sprintf(`{"name":%q,"version":%q}`, name, version))
		canonical, err := schema.CanonicalizeJSON(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := harness.memory.PutArtifact(store.Artifact{Kind: kind, Name: name, Version: version, Digest: schema.NewDigest(canonical), Document: document}); err != nil {
			t.Fatal(err)
		}
		response = serve(harness.handler, http.MethodGet, endpoint, nil, "", "")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"document"`) {
			t.Fatalf("artifact %s status=%d body=%s", kind, response.Code, response.Body.String())
		}
	}

	response = serve(harness.handler, http.MethodGet, "/v1/badges/example/runtime/codex.responses.svg", nil, "", "")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/svg+xml; charset=utf-8" || !strings.Contains(response.Body.String(), string(first.ID())[:20]) {
		t.Fatalf("badge status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOwnershipDisputeAndXSSContracts(t *testing.T) {
	harness := newHarness(t, nil)
	badChallenge := []byte(`{"subject":"example/runtime","method":"dns_txt","url":"http://127.0.0.1/admin"}`)
	response := serve(harness.handler, http.MethodPost, "/v1/ownership/challenges", badChallenge, ownerToken, "application/json")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_json_contract") {
		t.Fatalf("arbitrary URL field accepted: status=%d body=%s", response.Code, response.Body.String())
	}
	validChallenge := []byte(`{"subject":"example/runtime","method":"dns_txt"}`)
	response = serve(harness.handler, http.MethodPost, "/v1/ownership/challenges", validChallenge, ownerToken, "application/json")
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"verification_available":false`) {
		t.Fatalf("challenge status=%d body=%s", response.Code, response.Body.String())
	}

	observation := syntheticObservation(t, "example/runtime", "1.0.0", "responses", "2026.07.0", "codex.responses")
	if err := harness.memory.PutPublishedObservation(t.Context(), observation); err != nil {
		t.Fatal(err)
	}
	putSyntheticOwnership(t, harness, "example/runtime")
	disputeBody, err := json.Marshal(createDisputeRequest{
		ObservationID: observation.ID(),
		Statement:     `<script>alert("xss")</script>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	response = serve(harness.handler, http.MethodPost, "/v1/disputes", disputeBody, reporterToken, "application/json")
	if response.Code != http.StatusCreated {
		t.Fatalf("dispute status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "<script>") || !strings.Contains(response.Body.String(), `\u003cscript\u003e`) {
		t.Fatalf("dispute JSON was not HTML-safe: %s", response.Body.String())
	}
	var created struct {
		ID string `json:"dispute_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = serve(harness.handler, http.MethodGet, "/v1/disputes/"+created.ID, nil, "", "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("get dispute status=%d body=%s", response.Code, response.Body.String())
	}

	maliciousProfile := `<script>alert(1)<script>`
	malicious := syntheticObservation(t, "example/runtime", "2.0.0", "responses", "2026.07.0", maliciousProfile)
	if err := harness.memory.PutPublishedObservation(t.Context(), malicious); err != nil {
		t.Fatal(err)
	}
	response = serve(harness.handler, http.MethodGet, "/v1/badges/example/runtime/"+url.PathEscape(maliciousProfile)+".svg", nil, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("malicious-label badge status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "<script>") || !strings.Contains(response.Body.String(), "&lt;script&gt;") {
		t.Fatalf("badge did not XML-escape label: %s", response.Body.String())
	}
}

func putSyntheticOwnership(t *testing.T, harness testHarness, subject domain.SubjectNamespace) {
	t.Helper()
	id, err := schema.ParseInstanceID("00000000-0000-7000-8000-000000000099")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := domain.NewOwnershipChallenge(harness.owner, id, subject, domain.OwnershipDNS, "synthetic-local-nonce", httpTestNow.Add(time.Hour), httpTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challenge.Verify(schema.NewDigest([]byte("synthetic-local-ownership-fixture")), httpTestNow); err != nil {
		t.Fatal(err)
	}
	ownership, err := domain.OwnershipFromChallenge(challenge, httpTestNow.Add(90*24*time.Hour), httpTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.memory.PutOwnership(t.Context(), ownership); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitAndStableHeaders(t *testing.T) {
	harness := newHarness(t, func(config *Config) { config.RateLimit = 2 })
	target := "/v1/observations/" + string(schema.NewDigest([]byte("missing")))
	for attempt := 1; attempt <= 3; attempt++ {
		response := serve(harness.handler, http.MethodGet, target, nil, "", "")
		if attempt < 3 && response.Code != http.StatusNotFound {
			t.Fatalf("attempt %d status=%d", attempt, response.Code)
		}
		if attempt == 3 {
			if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
				t.Fatalf("rate limit status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		}
		assertSecurityHeaders(t, response)
	}
}

func TestEmbeddedMatrixIsServedWithoutInlineScript(t *testing.T) {
	harness := newHarness(t, nil)
	response := serve(harness.handler, http.MethodGet, "/matrix", nil, "", "")
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status=%d type=%s body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	if strings.Contains(response.Body.String(), "<script>") || strings.Contains(response.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatalf("matrix has an unsafe inline execution surface")
	}
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{"Content-Security-Policy", "Permissions-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if response.Header().Get(name) == "" {
			t.Errorf("missing security header %s", name)
		}
	}
	if response.Header().Get("X-AgentAPI-Registry-Mode") != "ephemeral" {
		t.Errorf("ephemeral service did not disclose its mode")
	}
}

var _ io.Reader = (*deterministicReader)(nil)
