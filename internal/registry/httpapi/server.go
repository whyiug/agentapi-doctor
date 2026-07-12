// Package httpapi implements the Registry's standard-library HTTP contract.
// It never executes an endpoint URL or fetches an attestation URI.
package httpapi

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/whyiug/agentapi-doctor/internal/registry/store"
	matrixweb "github.com/whyiug/agentapi-doctor/web/matrix"
)

const (
	defaultJSONBytes   = int64(2 << 20)
	defaultUploadBytes = int64(8 << 20)
)

type Config struct {
	Store          store.Store
	Clock          func() time.Time
	Random         io.Reader
	MaxJSONBytes   int64
	MaxUploadBytes int64
	SessionTTL     time.Duration
	ChallengeTTL   time.Duration
	RateLimit      int
	RateWindow     time.Duration
}

type Server struct {
	store          store.Store
	clock          func() time.Time
	random         io.Reader
	maxJSONBytes   int64
	maxUploadBytes int64
	sessionTTL     time.Duration
	challengeTTL   time.Duration
	limiter        *fixedWindowLimiter
	matrix         http.Handler
}

func New(config Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("registry store is required")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MaxJSONBytes == 0 {
		config.MaxJSONBytes = defaultJSONBytes
	}
	if config.MaxUploadBytes == 0 {
		config.MaxUploadBytes = defaultUploadBytes
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = 15 * time.Minute
	}
	if config.ChallengeTTL == 0 {
		config.ChallengeTTL = 15 * time.Minute
	}
	if config.RateWindow == 0 {
		config.RateWindow = time.Minute
	}
	if config.MaxJSONBytes < 1 || config.MaxUploadBytes < 1 || config.SessionTTL <= 0 || config.ChallengeTTL <= 0 || config.RateLimit < 0 || config.RateWindow <= 0 {
		return nil, errors.New("registry HTTP limits and TTLs must be positive")
	}
	return &Server{
		store:          config.Store,
		clock:          config.Clock,
		random:         config.Random,
		maxJSONBytes:   config.MaxJSONBytes,
		maxUploadBytes: config.MaxUploadBytes,
		sessionTTL:     config.SessionTTL,
		challengeTTL:   config.ChallengeTTL,
		limiter:        newFixedWindowLimiter(config.RateLimit, config.RateWindow),
		matrix:         matrixweb.Handler(),
	}, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	if !server.store.Capabilities().DurablePersistence {
		writer.Header().Set("X-AgentAPI-Registry-Mode", "ephemeral")
	}
	now := server.clock().UTC()
	allowed, remaining, retry := server.limiter.allow(remoteRateKey(request), now)
	setRateHeaders(writer, server.limiter.limit, remaining)
	if !allowed {
		writer.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "the Registry request rate limit was exceeded")
		return
	}
	if request.URL.Path == "/matrix/" && request.URL.RawQuery == "" {
		http.Redirect(writer, request, "/matrix", http.StatusPermanentRedirect)
		return
	}
	if !safePath(request.URL.Path) {
		writeError(writer, http.StatusBadRequest, "invalid_path", "the request path is not canonical")
		return
	}
	server.route(writer, request, now)
}

func (server *Server) route(writer http.ResponseWriter, request *http.Request, now time.Time) {
	switch request.URL.Path {
	case "/", "/matrix", "/matrix/", "/matrix/app.js", "/matrix/style.css":
		server.matrix.ServeHTTP(writer, request)
		return
	}
	switch request.URL.Path {
	case "/v1/observations:prepare":
		server.requireMethod(writer, request, http.MethodPost, func() { server.prepare(writer, request, now) })
		return
	case "/v1/observations:commit":
		server.requireMethod(writer, request, http.MethodPost, func() { server.commit(writer, request, now) })
		return
	case "/v1/observations":
		server.requireMethod(writer, request, http.MethodGet, func() { server.listObservations(writer, request) })
		return
	case "/v1/ownership/challenges":
		server.requireMethod(writer, request, http.MethodPost, func() { server.createOwnershipChallenge(writer, request, now) })
		return
	case "/v1/disputes":
		server.requireMethod(writer, request, http.MethodPost, func() { server.createDispute(writer, request, now) })
		return
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	switch {
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "uploads":
		server.requireMethod(writer, request, http.MethodPut, func() { server.stageUpload(writer, request, segments[2], now) })
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "observations":
		server.requireMethod(writer, request, http.MethodGet, func() { server.getObservation(writer, request, segments[2]) })
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "subjects":
		server.requireMethod(writer, request, http.MethodGet, func() { server.getSubject(writer, request, segments[2], segments[3]) })
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "packs":
		server.requireMethod(writer, request, http.MethodGet, func() { server.getArtifact(writer, request, store.ArtifactPack, segments[2], segments[3]) })
	case len(segments) == 4 && segments[0] == "v1" && segments[1] == "profiles":
		server.requireMethod(writer, request, http.MethodGet, func() { server.getArtifact(writer, request, store.ArtifactProfile, segments[2], segments[3]) })
	case len(segments) == 3 && segments[0] == "v1" && segments[1] == "disputes":
		server.requireMethod(writer, request, http.MethodGet, func() { server.getDispute(writer, request, segments[2]) })
	case len(segments) == 5 && segments[0] == "v1" && segments[1] == "badges" && strings.HasSuffix(segments[4], ".svg"):
		server.requireMethod(writer, request, http.MethodGet, func() {
			server.getBadge(writer, request, segments[2], segments[3], strings.TrimSuffix(segments[4], ".svg"))
		})
	default:
		writeError(writer, http.StatusNotFound, "not_found", "the requested Registry route was not found")
	}
}

func (server *Server) requireMethod(writer http.ResponseWriter, request *http.Request, method string, next func()) {
	if request.Method != method {
		writer.Header().Set("Allow", method)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "the HTTP method is not allowed for this route")
		return
	}
	next()
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
}

func safePath(value string) bool {
	if value == "" || value[0] != '/' || path.Clean(value) != value || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func retryAfterSeconds(duration time.Duration) string {
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}
