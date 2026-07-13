// Package openaisdkcase runs one bounded, local OpenAI Python SDK Responses
// streaming case and exports a deterministic maintainer-ready evidence bundle.
package openaisdkcase

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	agentapidoctor "github.com/whyiug/agentapi-doctor"
	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

const (
	FixtureReference              = "reference"
	FixtureMissingTerminalEvent   = "missing-terminal-event"
	FixtureDuplicateTerminalEvent = "duplicate-terminal-event"
	FixtureNullCompletedOutput    = "null-completed-output"

	StatusConfirmed = "confirmed"
	StatusUnknown   = "unknown"

	PythonVersion = "3.12.12"
	OpenAIVersion = "2.38.0"

	defaultTimeout = 15 * time.Second
	maxTimeout     = 2 * time.Minute
	outputLimit    = 64 << 10
	maxWireBytes   = 1 << 20

	observationSchema     = "agentapi-doctor.openai-sdk-observation.v1"
	bundleSchema          = "agentapi-doctor.openai-sdk-case-bundle.v1"
	runnerAssetPath       = "runners/python/openai-responses/runner.py"
	fixtureAssetPath      = "runners/python/openai-responses/fixture.json"
	requirementsAssetPath = "runners/python/openai-responses/requirements-linux-x86_64-py312.lock"
)

// Request identifies the pinned Python executable and synthetic fixture to run.
// Timeout defaults to 15 seconds and cannot exceed two minutes.
type Request struct {
	Python  string
	Fixture string
	Timeout time.Duration
}

// Result is a compact, JSON-friendly summary. Bundle contains a deterministic
// ZIP and is deliberately excluded from JSON output.
type Result struct {
	Fixture           string `json:"fixture"`
	Status            string `json:"status"`
	RawTerminalCount  int    `json:"raw_terminal_count"`
	RawOutputKind     string `json:"raw_output_kind"`
	SDKStatus         string `json:"sdk_status"`
	SDKTerminalCount  int    `json:"sdk_terminal_count"`
	SDKOutputKind     string `json:"sdk_output_kind"`
	SDKExceptionPhase string `json:"sdk_exception_phase,omitempty"`
	SDKExceptionClass string `json:"sdk_exception_class,omitempty"`
	FaultDomain       string `json:"fault_domain"`
	Summary           string `json:"summary"`
	Bundle            []byte `json:"-"`
}

// SupportedFixtures returns the stable fixture IDs accepted by Run.
func SupportedFixtures() []string {
	return []string{
		FixtureReference,
		FixtureMissingTerminalEvent,
		FixtureDuplicateTerminalEvent,
		FixtureNullCompletedOutput,
	}
}

type fixtureSpec struct {
	ID                    string `json:"id"`
	MutationID            string `json:"mutation_id,omitempty"`
	ExpectedTerminalCount int    `json:"expected_terminal_count"`
	ExpectedOutputKind    string `json:"expected_output_kind"`
	Description           string `json:"description"`
}

func fixtureFor(id string) (fixtureSpec, referenceserver.Transformer, error) {
	if id == "" {
		id = FixtureReference
	}
	var spec fixtureSpec
	var mutation mutantserver.ID
	switch id {
	case FixtureReference:
		spec = fixtureSpec{id, "", 1, "array", "unmodified synthetic Responses stream"}
	case FixtureMissingTerminalEvent:
		mutation = mutantserver.MissingTerminalEvent
		spec = fixtureSpec{id, string(mutation), 0, "unavailable", "response.completed is omitted"}
	case FixtureDuplicateTerminalEvent:
		mutation = mutantserver.DuplicateTerminalEvent
		spec = fixtureSpec{id, string(mutation), 2, "array", "response.completed is emitted twice"}
	case FixtureNullCompletedOutput:
		mutation = mutantserver.NullCompletedOutput
		spec = fixtureSpec{id, string(mutation), 1, "null", "response.completed contains a null output field"}
	default:
		return fixtureSpec{}, nil, fmt.Errorf("unsupported OpenAI SDK fixture %q", id)
	}
	if mutation == "" {
		return spec, nil, nil
	}
	transformer, err := mutantserver.New(mutation)
	if err != nil {
		return fixtureSpec{}, nil, fmt.Errorf("construct fixture %q: %w", id, err)
	}
	return spec, transformer, nil
}

// Run executes exactly one local SDK request, correlates the captured raw SSE
// with the strictly decoded SDK observation, and creates an evidence ZIP.
func Run(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("context is required")
	}
	if strings.TrimSpace(request.Python) == "" {
		return Result{}, errors.New("python executable is required")
	}
	if !filepath.IsAbs(request.Python) {
		return Result{}, errors.New("python executable must be an absolute path")
	}
	pythonInfo, err := os.Stat(request.Python)
	if err != nil || !pythonInfo.Mode().IsRegular() || pythonInfo.Mode().Perm()&0o111 == 0 {
		return Result{}, fmt.Errorf("python executable must be an executable regular file: %s", request.Python)
	}
	pythonExecutableSHA256, err := sha256File(request.Python)
	if err != nil {
		return Result{}, fmt.Errorf("hash python executable: %w", err)
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return Result{}, fmt.Errorf("the frozen OpenAI SDK reproduction baseline supports linux/amd64 only, not %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	spec, transformer, err := fixtureFor(request.Fixture)
	if err != nil {
		return Result{}, err
	}
	timeout := request.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 || timeout > maxTimeout {
		return Result{}, fmt.Errorf("timeout must be positive and at most %s", maxTimeout)
	}

	handler, err := referenceserver.New(referenceserver.Config{
		MaxBodyBytes:   64 << 10,
		RequestTimeout: 5 * time.Second,
		Transformer:    transformer,
	})
	if err != nil {
		return Result{}, fmt.Errorf("create reference handler: %w", err)
	}
	recorder := &exchangeRecorder{next: handler}
	server, err := newLocalServer(recorder)
	if err != nil {
		return Result{}, err
	}
	defer server.Close()

	temporaryHome, err := os.MkdirTemp("", "agentapi-doctor-openai-sdk-")
	if err != nil {
		return Result{}, fmt.Errorf("create isolated HOME: %w", err)
	}
	defer os.RemoveAll(temporaryHome)
	if err := os.Chmod(temporaryHome, 0o700); err != nil {
		return Result{}, fmt.Errorf("protect isolated HOME: %w", err)
	}

	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	assets, err := loadCanonicalAssets()
	if err != nil {
		return Result{}, err
	}
	observation, err := runHelper(runContext, request.Python, server.URL+"/v1", temporaryHome, assets.runner)
	if err != nil {
		return Result{}, err
	}
	pythonInfoAfter, err := os.Stat(request.Python)
	if err != nil || !os.SameFile(pythonInfo, pythonInfoAfter) {
		return Result{}, errors.New("python executable identity changed during reproduction")
	}
	pythonExecutableSHA256After, err := sha256File(request.Python)
	if err != nil {
		return Result{}, fmt.Errorf("rehash python executable: %w", err)
	}
	if pythonExecutableSHA256After != pythonExecutableSHA256 {
		return Result{}, errors.New("python executable content changed during reproduction")
	}
	captures := recorder.capturesCopy()
	if len(captures) > 1 {
		return Result{}, fmt.Errorf("pinned SDK helper made %d local HTTP requests; at most one is permitted", len(captures))
	}
	capture := capturedExchange{}
	var rawErr error
	if len(captures) == 0 {
		rawErr = errors.New("the SDK helper made no loopback request")
	} else {
		capture = captures[0]
		if capture.path != "/v1/responses" || capture.method != http.MethodPost {
			return Result{}, fmt.Errorf("unexpected local SDK request %s %s", capture.method, capture.path)
		}
		if capture.truncated {
			return Result{}, errors.New("captured SSE exceeded the one MiB evidence bound")
		}
	}

	raw := rawObservation{OutputKind: "unavailable"}
	if rawErr == nil {
		raw, rawErr = inspectSSE(capture.body)
	}
	result := evaluate(spec, observation, raw, rawErr, capture)
	bundle, err := buildBundle(spec, result, observation, capture.body, assets, pythonExecutableSHA256)
	if err != nil {
		return Result{}, fmt.Errorf("build evidence bundle: %w", err)
	}
	result.Bundle = bundle
	return result, nil
}

func newLocalServer(handler http.Handler) (*httptest.Server, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on local fixture address: %w", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server, nil
}

type helperObservation struct {
	SchemaVersion string            `json:"schema_version"`
	Version       helperVersion     `json:"version"`
	Environment   helperEnvironment `json:"environment"`
	EventTypes    []string          `json:"event_types"`
	EventCount    int               `json:"event_count"`
	Final         helperFinal       `json:"final"`
	Exception     *helperException  `json:"exception"`
}

type helperVersion struct {
	Python string  `json:"python"`
	OpenAI *string `json:"openai"`
}

type helperEnvironment struct {
	Implementation string                      `json:"implementation"`
	PythonVersion  string                      `json:"python_version"`
	System         string                      `json:"system"`
	Machine        string                      `json:"machine"`
	Dependencies   []helperDistribution        `json:"dependencies"`
	BootstrapTools []helperDistribution        `json:"bootstrap_tools"`
	MatchesLock    bool                        `json:"matches_lock"`
	Mismatches     []helperEnvironmentMismatch `json:"mismatches"`
}

type helperDistribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type helperEnvironmentMismatch struct {
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	Expected *string `json:"expected"`
	Observed *string `json:"observed"`
}

var expectedLockedDependencies = []helperDistribution{
	{"annotated-types", "0.7.0"},
	{"anyio", "4.14.2"},
	{"certifi", "2026.6.17"},
	{"distro", "1.9.0"},
	{"h11", "0.16.0"},
	{"httpcore", "1.0.9"},
	{"httpx", "0.28.1"},
	{"idna", "3.18"},
	{"jiter", "0.16.0"},
	{"openai", OpenAIVersion},
	{"pydantic", "2.13.4"},
	{"pydantic-core", "2.46.4"},
	{"sniffio", "1.3.1"},
	{"tqdm", "4.68.4"},
	{"typing-extensions", "4.16.0"},
	{"typing-inspection", "0.4.2"},
}

type helperFinal struct {
	Status      *string `json:"status"`
	OutputCount *int    `json:"output_count"`
}

type helperException struct {
	Phase            string `json:"phase"`
	Class            string `json:"class"`
	SanitizedMessage string `json:"sanitized_message"`
}

func runHelper(ctx context.Context, executable, baseURL, temporaryHome string, runner []byte) (helperObservation, error) {
	command := exec.CommandContext(ctx, executable, "-I", "-c", string(runner), baseURL)
	command.Env = []string{
		"HOME=" + temporaryHome,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + temporaryHome,
		"TZ=UTC",
	}
	command.Dir = temporaryHome
	var stdout, stderr boundedBuffer
	stdout.limit = outputLimit
	stderr.limit = outputLimit
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return helperObservation{}, fmt.Errorf("pinned SDK helper timed out or was cancelled: %w", ctx.Err())
	}
	if stdout.exceeded || stderr.exceeded {
		return helperObservation{}, errors.New("pinned SDK helper exceeded the 64 KiB stdout/stderr bound")
	}
	if err != nil {
		return helperObservation{}, fmt.Errorf("pinned SDK helper failed without a valid observation: %w", err)
	}
	observation, err := decodeObservation(stdout.Bytes())
	if err != nil {
		return helperObservation{}, err
	}
	return observation, nil
}

func decodeObservation(data []byte) (helperObservation, error) {
	if len(data) == 0 || len(data) > outputLimit || !utf8.Valid(data) {
		return helperObservation{}, errors.New("SDK helper observation must be non-empty bounded UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var observation helperObservation
	if err := decoder.Decode(&observation); err != nil {
		return helperObservation{}, fmt.Errorf("decode SDK helper observation: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return helperObservation{}, errors.New("SDK helper observation must contain exactly one JSON value")
	}
	if err := observation.validate(); err != nil {
		return helperObservation{}, err
	}
	return observation, nil
}

func (observation helperObservation) validate() error {
	if observation.SchemaVersion != observationSchema {
		return fmt.Errorf("unexpected SDK observation schema %q", observation.SchemaVersion)
	}
	if observation.Version.Python == "" {
		return errors.New("SDK observation Python version is required")
	}
	if err := observation.Environment.validate(); err != nil {
		return err
	}
	if observation.Version.Python != observation.Environment.PythonVersion {
		return errors.New("SDK observation Python version disagrees with its environment attestation")
	}
	if observation.EventCount < 0 || observation.EventCount > 128 || len(observation.EventTypes) != observation.EventCount {
		return errors.New("SDK observation event counts exceed bounds")
	}
	for _, eventType := range observation.EventTypes {
		if eventType == "" || len(eventType) > 80 {
			return errors.New("SDK observation contains an invalid event type")
		}
	}
	if observation.Final.OutputCount != nil && (*observation.Final.OutputCount < 0 || *observation.Final.OutputCount > 128) {
		return errors.New("SDK final output count exceeds bounds")
	}
	if observation.Final.Status != nil && (*observation.Final.Status == "" || len(*observation.Final.Status) > 80) {
		return errors.New("SDK final status exceeds bounds")
	}
	if observation.Exception != nil {
		if observation.Exception.Phase == "" || len(observation.Exception.Phase) > 80 || observation.Exception.Class == "" || len(observation.Exception.Class) > 80 || observation.Exception.SanitizedMessage == "" || len(observation.Exception.SanitizedMessage) > 512 {
			return errors.New("SDK exception observation exceeds bounds")
		}
		if observation.Final.Status != nil || observation.Final.OutputCount != nil {
			return errors.New("exception SDK observation cannot contain a final response")
		}
	}
	return nil
}

func (environment helperEnvironment) validate() error {
	for name, value := range map[string]string{
		"implementation": environment.Implementation,
		"python version": environment.PythonVersion,
		"system":         environment.System,
		"machine":        environment.Machine,
	} {
		if value == "" || len(value) > 80 {
			return fmt.Errorf("SDK environment %s is invalid", name)
		}
	}
	if len(environment.Dependencies) > 128 || len(environment.BootstrapTools) > 3 || len(environment.Mismatches) > 128 {
		return errors.New("SDK environment attestation exceeds bounds")
	}
	if err := validateDistributions(environment.Dependencies, nil); err != nil {
		return fmt.Errorf("SDK environment dependencies: %w", err)
	}
	allowedBootstrap := map[string]bool{"pip": true, "setuptools": true, "wheel": true}
	if err := validateDistributions(environment.BootstrapTools, allowedBootstrap); err != nil {
		return fmt.Errorf("SDK environment bootstrap tools: %w", err)
	}
	for _, mismatch := range environment.Mismatches {
		if mismatch.Kind == "" || len(mismatch.Kind) > 80 || mismatch.Name == "" || len(mismatch.Name) > 80 || !boundedOptionalString(mismatch.Expected) || !boundedOptionalString(mismatch.Observed) {
			return errors.New("SDK environment mismatch evidence is invalid")
		}
	}
	if environment.MatchesLock != (len(environment.Mismatches) == 0) {
		return errors.New("SDK environment lock verdict disagrees with mismatch evidence")
	}
	if environment.MatchesLock {
		if environment.Implementation != "CPython" || environment.PythonVersion != PythonVersion || environment.System != "Linux" || environment.Machine != "x86_64" {
			return errors.New("SDK environment claims a lock match outside the frozen runtime platform")
		}
		if !slices.Equal(environment.Dependencies, expectedLockedDependencies) {
			return errors.New("SDK environment claims a lock match without the exact dependency set")
		}
	}
	return nil
}

func validateDistributions(distributions []helperDistribution, allowedNames map[string]bool) error {
	previous := ""
	for _, distribution := range distributions {
		if distribution.Name == "" || len(distribution.Name) > 80 || distribution.Version == "" || len(distribution.Version) > 80 {
			return errors.New("distribution identity is invalid")
		}
		if allowedNames != nil && !allowedNames[distribution.Name] {
			return fmt.Errorf("distribution %q is not an allowed bootstrap tool", distribution.Name)
		}
		identity := distribution.Name + "\x00" + distribution.Version
		if identity <= previous {
			return errors.New("distribution identities must be unique and sorted")
		}
		previous = identity
	}
	return nil
}

func boundedOptionalString(value *string) bool {
	return value == nil || len(*value) <= 160
}

type boundedBuffer struct {
	data     bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.data.Len()
	if remaining > 0 {
		written := len(data)
		if written > remaining {
			written = remaining
		}
		_, _ = buffer.data.Write(data[:written])
	}
	if len(data) > remaining {
		buffer.exceeded = true
	}
	return len(data), nil
}

func (buffer *boundedBuffer) Bytes() []byte { return buffer.data.Bytes() }

type capturedExchange struct {
	method      string
	path        string
	status      int
	contentType string
	mutationID  string
	body        []byte
	truncated   bool
}

type exchangeRecorder struct {
	next     http.Handler
	mu       sync.Mutex
	captures []capturedExchange
}

func (recorder *exchangeRecorder) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	captureWriter := &captureResponseWriter{ResponseWriter: writer, limit: maxWireBytes}
	recorder.next.ServeHTTP(captureWriter, request)
	status := captureWriter.status
	if status == 0 {
		status = http.StatusOK
	}
	capture := capturedExchange{
		method: request.Method, path: request.URL.Path, status: status,
		contentType: writer.Header().Get("Content-Type"),
		mutationID:  writer.Header().Get("X-AgentAPI-Mutant"),
		body:        slices.Clone(captureWriter.body.Bytes()),
		truncated:   captureWriter.truncated,
	}
	recorder.mu.Lock()
	recorder.captures = append(recorder.captures, capture)
	recorder.mu.Unlock()
}

func (recorder *exchangeRecorder) capturesCopy() []capturedExchange {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	result := make([]capturedExchange, len(recorder.captures))
	copy(result, recorder.captures)
	for index := range result {
		result[index].body = slices.Clone(result[index].body)
	}
	return result
}

type captureResponseWriter struct {
	http.ResponseWriter
	status    int
	body      bytes.Buffer
	limit     int
	truncated bool
}

func (writer *captureResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *captureResponseWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	remaining := writer.limit - writer.body.Len()
	if remaining > 0 {
		count := len(data)
		if count > remaining {
			count = remaining
		}
		_, _ = writer.body.Write(data[:count])
	}
	if len(data) > remaining {
		writer.truncated = true
	}
	return writer.ResponseWriter.Write(data)
}

type rawObservation struct {
	TerminalCount int
	OutputKind    string
}

func inspectSSE(data []byte) (rawObservation, error) {
	if len(data) == 0 || !utf8.Valid(data) {
		return rawObservation{OutputKind: "unavailable"}, errors.New("captured SSE is empty or invalid UTF-8")
	}
	observation := rawObservation{OutputKind: "unavailable"}
	frames := bytes.Split(data, []byte("\n\n"))
	for _, frame := range frames {
		if len(bytes.TrimSpace(frame)) == 0 {
			continue
		}
		var dataLines [][]byte
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				value := bytes.TrimPrefix(line, []byte("data:"))
				value = bytes.TrimPrefix(value, []byte(" "))
				dataLines = append(dataLines, value)
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		payload := bytes.Join(dataLines, []byte("\n"))
		var event struct {
			Type     string `json:"type"`
			Response struct {
				Output json.RawMessage `json:"output"`
			} `json:"response"`
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		if err := decoder.Decode(&event); err != nil {
			return observation, fmt.Errorf("decode captured SSE data: %w", err)
		}
		if event.Type != "response.completed" {
			continue
		}
		observation.TerminalCount++
		kind := jsonKind(event.Response.Output)
		if observation.OutputKind == "unavailable" {
			observation.OutputKind = kind
		} else if observation.OutputKind != kind {
			observation.OutputKind = "inconsistent"
		}
	}
	return observation, nil
}

func jsonKind(data json.RawMessage) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "missing"
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return "null"
	}
	if trimmed[0] == '[' {
		return "array"
	}
	return "other"
}

func evaluate(spec fixtureSpec, sdk helperObservation, raw rawObservation, rawErr error, capture capturedExchange) Result {
	result := Result{
		Fixture: spec.ID, Status: StatusUnknown, RawTerminalCount: raw.TerminalCount,
		RawOutputKind: raw.OutputKind, SDKStatus: sdk.status(),
		SDKTerminalCount: sdk.terminalCount(), SDKOutputKind: sdk.outputKind(),
		FaultDomain: "unknown",
	}
	if sdk.Exception != nil {
		result.SDKExceptionPhase = sdk.Exception.Phase
		result.SDKExceptionClass = sdk.Exception.Class
	}
	if !sdk.Environment.MatchesLock || sdk.Version.Python != PythonVersion || sdk.openaiVersion() != OpenAIVersion {
		result.SDKStatus = "environment_mismatch"
		result.Summary = fmt.Sprintf("UNKNOWN: frozen reproduction requires CPython %s, openai %s, Linux x86_64, and the exact dependency lock; observed %s %s, openai %s, %s/%s, lock_match=%t.", PythonVersion, OpenAIVersion, sdk.Environment.Implementation, sdk.Version.Python, sdk.observedOpenAIVersion(), sdk.Environment.System, sdk.Environment.Machine, sdk.Environment.MatchesLock)
		return result
	}
	if rawErr != nil || capture.status != http.StatusOK || !strings.HasPrefix(strings.ToLower(capture.contentType), "text/event-stream") {
		result.Summary = "UNKNOWN: the local application-layer response was not a valid 200 SSE stream."
		return result
	}
	if capture.mutationID != spec.MutationID {
		result.Summary = "UNKNOWN: the observed fixture identity did not match the requested fixture."
		return result
	}
	if raw.TerminalCount != spec.ExpectedTerminalCount || raw.OutputKind != spec.ExpectedOutputKind {
		result.Summary = "UNKNOWN: captured wire semantics did not match the requested deterministic fixture."
		return result
	}
	if !matchesSDKExpectation(spec.ID, sdk) {
		result.Summary = "UNKNOWN: the pinned SDK observation did not match this fixture's frozen expected behavior."
		return result
	}

	result.Status = StatusConfirmed
	if spec.ID == FixtureReference {
		result.FaultDomain = "none"
		result.Summary = "CONFIRMED: the pinned SDK completed the reference stream and observed one terminal event with an output array."
		return result
	}
	result.FaultDomain = "wire"
	result.Summary = fmt.Sprintf("CONFIRMED: raw SSE proves fixture %s and the pinned SDK reproduced its frozen observation; the exception is co-observed evidence, not standalone endpoint attribution.", spec.ID)
	return result
}

func (observation helperObservation) openaiVersion() string {
	if observation.Version.OpenAI == nil {
		return "unavailable"
	}
	return *observation.Version.OpenAI
}

func (observation helperObservation) observedOpenAIVersion() string {
	if observation.Version.OpenAI != nil {
		return *observation.Version.OpenAI
	}
	for _, distribution := range observation.Environment.Dependencies {
		if distribution.Name == "openai" {
			return distribution.Version
		}
	}
	return "unavailable"
}

func (observation helperObservation) status() string {
	if observation.Exception != nil {
		return "exception"
	}
	return "completed"
}

func (observation helperObservation) terminalCount() int {
	count := 0
	for _, eventType := range observation.EventTypes {
		if eventType == "response.completed" {
			count++
		}
	}
	return count
}

func (observation helperObservation) outputKind() string {
	if observation.Final.OutputCount != nil {
		return "array"
	}
	return "unavailable"
}

func matchesSDKExpectation(fixture string, observation helperObservation) bool {
	completed := observation.Exception == nil && observation.Final.Status != nil && *observation.Final.Status == "completed" && observation.Final.OutputCount != nil && *observation.Final.OutputCount == 1
	switch fixture {
	case FixtureReference:
		return completed && observation.terminalCount() == 1
	case FixtureMissingTerminalEvent:
		return observation.terminalCount() == 0 && exceptionMatches(observation.Exception, "final_response", "RuntimeError")
	case FixtureDuplicateTerminalEvent:
		return completed && observation.terminalCount() == 2
	case FixtureNullCompletedOutput:
		return observation.terminalCount() == 0 && exceptionMatches(observation.Exception, "event_iteration", "TypeError")
	default:
		return false
	}
}

func exceptionMatches(exception *helperException, phase, class string) bool {
	return exception != nil && exception.Phase == phase && exception.Class == class
}

type bundleEnvironment struct {
	Observed     bundleObservedEnvironment `json:"observed"`
	Expected     bundleExpectedEnvironment `json:"expected"`
	Runner       string                    `json:"runner"`
	BaselineNote string                    `json:"baseline_note"`
}

type bundleObservedEnvironment struct {
	Implementation         string                      `json:"implementation"`
	Python                 string                      `json:"python"`
	OpenAI                 string                      `json:"openai"`
	System                 string                      `json:"system"`
	Machine                string                      `json:"machine"`
	Dependencies           []helperDistribution        `json:"dependencies"`
	BootstrapTools         []helperDistribution        `json:"bootstrap_tools"`
	MatchesLock            bool                        `json:"matches_lock"`
	Mismatches             []helperEnvironmentMismatch `json:"mismatches"`
	PythonExecutableSHA256 string                      `json:"python_executable_sha256"`
}

type bundleExpectedEnvironment struct {
	Implementation         string `json:"implementation"`
	Python                 string `json:"python"`
	OpenAI                 string `json:"openai"`
	System                 string `json:"system"`
	Machine                string `json:"machine"`
	RequirementsLockSHA256 string `json:"requirements_lock_sha256"`
}

type bundleManifest struct {
	SchemaVersion        string            `json:"schema_version"`
	Fixture              string            `json:"fixture"`
	Status               string            `json:"status"`
	Files                []string          `json:"files"`
	CanonicalInputSHA256 map[string]string `json:"canonical_input_sha256"`
}

type bundleGenerator struct {
	Name             string         `json:"name"`
	Build            buildinfo.Info `json:"build"`
	ExecutableSHA256 string         `json:"executable_sha256"`
	GoVersion        string         `json:"go_version"`
	Platform         string         `json:"platform"`
	ModulePath       string         `json:"module_path"`
	ModuleVersion    string         `json:"module_version"`
	ModuleSum        string         `json:"module_sum,omitempty"`
	VCSRevision      string         `json:"vcs_revision,omitempty"`
	VCSModified      string         `json:"vcs_modified"`
}

type canonicalAssets struct {
	runner       []byte
	fixture      []byte
	requirements []byte
}

func loadCanonicalAssets() (canonicalAssets, error) {
	read := func(name string) ([]byte, error) {
		data, err := agentapidoctor.ReadAsset(name)
		if err != nil {
			return nil, fmt.Errorf("read canonical asset %s: %w", name, err)
		}
		return data, nil
	}
	runner, err := read(runnerAssetPath)
	if err != nil {
		return canonicalAssets{}, err
	}
	fixture, err := read(fixtureAssetPath)
	if err != nil {
		return canonicalAssets{}, err
	}
	requirements, err := read(requirementsAssetPath)
	if err != nil {
		return canonicalAssets{}, err
	}
	return canonicalAssets{runner: runner, fixture: fixture, requirements: requirements}, nil
}

func buildBundle(spec fixtureSpec, result Result, observation helperObservation, wire []byte, assets canonicalAssets, pythonExecutableSHA256 string) ([]byte, error) {
	result.Bundle = nil
	resultJSON, err := marshalIndented(result)
	if err != nil {
		return nil, err
	}
	observationJSON, err := marshalIndented(observation)
	if err != nil {
		return nil, err
	}
	environmentJSON, err := marshalIndented(bundleEnvironment{
		Observed: bundleObservedEnvironment{
			Implementation:         observation.Environment.Implementation,
			Python:                 observation.Version.Python,
			OpenAI:                 observation.observedOpenAIVersion(),
			System:                 observation.Environment.System,
			Machine:                observation.Environment.Machine,
			Dependencies:           slices.Clone(observation.Environment.Dependencies),
			BootstrapTools:         slices.Clone(observation.Environment.BootstrapTools),
			MatchesLock:            observation.Environment.MatchesLock,
			Mismatches:             slices.Clone(observation.Environment.Mismatches),
			PythonExecutableSHA256: pythonExecutableSHA256,
		},
		Expected: bundleExpectedEnvironment{
			Implementation:         "CPython",
			Python:                 PythonVersion,
			OpenAI:                 OpenAIVersion,
			System:                 "Linux",
			Machine:                "x86_64",
			RequirementsLockSHA256: sha256Hex(assets.requirements),
		},
		Runner:       "python -I -c <canonical-runner-bytes> <loopback-base-url>",
		BaselineNote: "Frozen reproduction baseline only; not a recommendation for production Python environments.",
	})
	if err != nil {
		return nil, err
	}
	generator, err := currentBundleGenerator()
	if err != nil {
		return nil, err
	}
	generatorJSON, err := marshalIndented(generator)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"SUMMARY.md":              summaryMarkdown(spec, result),
		"environment.json":        environmentJSON,
		"fixture.json":            slices.Clone(assets.fixture),
		"generator.json":          generatorJSON,
		"repro/README.md":         reproductionREADME(spec),
		"repro/requirements.lock": slices.Clone(assets.requirements),
		"repro/runner.py":         slices.Clone(assets.runner),
		"result.json":             resultJSON,
		"sdk-observation.json":    observationJSON,
		"wire.sse":                slices.Clone(wire),
	}
	names := append(sortedNames(files), "manifest.json", "SHA256SUMS")
	sort.Strings(names)
	manifestJSON, err := marshalIndented(bundleManifest{
		SchemaVersion: bundleSchema,
		Fixture:       spec.ID,
		Status:        result.Status,
		Files:         names,
		CanonicalInputSHA256: map[string]string{
			"fixture.json":            sha256Hex(assets.fixture),
			"repro/requirements.lock": sha256Hex(assets.requirements),
			"repro/runner.py":         sha256Hex(assets.runner),
		},
	})
	if err != nil {
		return nil, err
	}
	files["manifest.json"] = manifestJSON
	files["SHA256SUMS"] = checksumFile(files)
	return deterministicZIP(files)
}

func currentBundleGenerator() (bundleGenerator, error) {
	executable := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return bundleGenerator{}, fmt.Errorf("resolve generating executable: %w", err)
		}
	}
	executableSHA256, err := sha256File(executable)
	if err != nil {
		return bundleGenerator{}, fmt.Errorf("hash generating executable: %w", err)
	}

	generator := bundleGenerator{
		Name:             "agentapi-doctor",
		Build:            buildinfo.Current(),
		ExecutableSHA256: executableSHA256,
		GoVersion:        runtime.Version(),
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		VCSModified:      "unavailable",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		generator.ModulePath = info.Main.Path
		generator.ModuleVersion = info.Main.Version
		generator.ModuleSum = info.Main.Sum
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				generator.VCSRevision = setting.Value
			case "vcs.modified":
				generator.VCSModified = setting.Value
			}
		}
	}
	return generator, nil
}

func sha256File(name string) (string, error) {
	stream, err := os.Open(name)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, stream)
	closeErr := stream.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func marshalIndented(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func summaryMarkdown(spec fixtureSpec, result Result) []byte {
	clientError := "none"
	if result.SDKExceptionClass != "" {
		clientError = result.SDKExceptionClass + " during " + result.SDKExceptionPhase
	}
	return []byte(fmt.Sprintf("# OpenAI Python SDK case\n\n- Fixture: `%s`\n- Verdict: `%s`\n- Frozen runtime: CPython `%s`, `openai==%s`, Linux x86_64\n- Fault domain: `%s`\n- Expected raw terminal events/output: `%d` / `%s`\n- Actual raw terminal events/output: `%d` / `%s`\n- SDK outcome: `%s`\n- SDK terminal events/final output: `%d` / `%s`\n- SDK error: %s\n\n%s\n\n## Reproduce\n\n```text\ndoctor reproduce openai-python-responses --python <python-3.12.12> --fixture %s --bundle rerun.zip\n```\n\nThen run the repaired reference regression:\n\n```text\ndoctor reproduce openai-python-responses --python <python-3.12.12> --fixture reference --bundle reference.zip\n```\n\nThe exception observation, if present, is co-observed evidence and is not by itself proof of endpoint causality.\n", result.Fixture, result.Status, PythonVersion, OpenAIVersion, result.FaultDomain, spec.ExpectedTerminalCount, spec.ExpectedOutputKind, result.RawTerminalCount, result.RawOutputKind, result.SDKStatus, result.SDKTerminalCount, result.SDKOutputKind, clientError, result.Summary, spec.ID))
}

func reproductionREADME(spec fixtureSpec) []byte {
	return []byte(fmt.Sprintf("# Reproduce %s\n\nThis is a frozen Linux x86_64 reproduction baseline, not a production Python recommendation. Use CPython %s and install the exact wheel set:\n\n```text\npython3.12 -m pip install --require-hashes --only-binary=:all: -r requirements.lock\n```\n\nRun the complete bounded case (it creates and removes its own random loopback fixture):\n\n```text\ndoctor reproduce openai-python-responses --python <python-3.12.12> --fixture %s --bundle rerun.zip\n```\n\nConfirm the repaired/reference path separately:\n\n```text\ndoctor reproduce openai-python-responses --python <python-3.12.12> --fixture reference --bundle reference.zip\n```\n\n`runner.py` is the exact helper executed by Doctor. It accepts only a task-owned `http://127.0.0.1:<port>/v1` fixture. The synthetic token is not a real credential. `environment.json` records the interpreter digest and installed distribution metadata; the lock hashes govern environment construction and are not a claim that every installed package file was rehashed. Compare `wire.sse` with `sdk-observation.json`; do not infer endpoint causality from an exception alone.\n", spec.ID, PythonVersion, spec.ID))
}

func checksumFile(files map[string][]byte) []byte {
	names := sortedNames(files)
	var output strings.Builder
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		fmt.Fprintf(&output, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	return []byte(output.String())
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func deterministicZIP(files map[string][]byte) ([]byte, error) {
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	fixed := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range sortedNames(files) {
		if path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("invalid bundle path %q", name)
		}
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		header.Modified = fixed
		header.SetMode(0o644)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
