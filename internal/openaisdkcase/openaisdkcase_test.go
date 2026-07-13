package openaisdkcase

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

func TestSupportedFixturesReturnsStableCopy(t *testing.T) {
	want := []string{
		FixtureReference,
		FixtureMissingTerminalEvent,
		FixtureDuplicateTerminalEvent,
		FixtureNullCompletedOutput,
	}
	first := SupportedFixtures()
	if !slices.Equal(first, want) {
		t.Fatalf("SupportedFixtures() = %v, want %v", first, want)
	}
	first[0] = "changed"
	if slices.Equal(first, SupportedFixtures()) {
		t.Fatal("SupportedFixtures returned shared mutable state")
	}
}

func TestExpectedDependencyAttestationMatchesCanonicalLock(t *testing.T) {
	assets, err := loadCanonicalAssets()
	if err != nil {
		t.Fatal(err)
	}
	var locked []helperDistribution
	for _, line := range strings.Split(string(assets.requirements), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || !strings.Contains(fields[0], "==") {
			continue
		}
		parts := strings.SplitN(fields[0], "==", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Fatalf("invalid locked requirement line %q", line)
		}
		locked = append(locked, helperDistribution{Name: parts[0], Version: parts[1]})
	}
	if !slices.Equal(locked, expectedLockedDependencies) {
		t.Fatalf("Go dependency attestation = %+v, lock = %+v", expectedLockedDependencies, locked)
	}
}

func TestBundleGeneratorHashesLoadedProcessImage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/exe is a Linux process-image identity")
	}
	want, err := sha256File("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := currentBundleGenerator()
	if err != nil {
		t.Fatal(err)
	}
	if generator.ExecutableSHA256 != want {
		t.Fatalf("generator executable digest = %q, loaded image digest = %q", generator.ExecutableSHA256, want)
	}
}

func TestFixtureRawSemantics(t *testing.T) {
	tests := []struct {
		fixture   string
		terminals int
		output    string
		mutation  string
	}{
		{FixtureReference, 1, "array", ""},
		{FixtureMissingTerminalEvent, 0, "unavailable", string(mutantserver.MissingTerminalEvent)},
		{FixtureDuplicateTerminalEvent, 2, "array", string(mutantserver.DuplicateTerminalEvent)},
		{FixtureNullCompletedOutput, 1, "null", string(mutantserver.NullCompletedOutput)},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			capture := renderFixture(t, test.fixture)
			observation, err := inspectSSE(capture.body)
			if err != nil {
				t.Fatalf("inspectSSE() error = %v", err)
			}
			if observation.TerminalCount != test.terminals || observation.OutputKind != test.output {
				t.Fatalf("raw observation = %+v, want terminals=%d output=%s", observation, test.terminals, test.output)
			}
			if capture.mutationID != test.mutation {
				t.Fatalf("mutation header = %q, want %q", capture.mutationID, test.mutation)
			}
		})
	}
}

func TestEvaluateUsesFixtureSpecificSDKExpectations(t *testing.T) {
	tests := []struct {
		fixture string
		sdk     helperObservation
	}{
		{FixtureReference, completedObservation(1)},
		{FixtureMissingTerminalEvent, exceptionObservation(0, "final_response", "RuntimeError")},
		{FixtureDuplicateTerminalEvent, completedObservation(2)},
		{FixtureNullCompletedOutput, exceptionObservation(0, "event_iteration", "TypeError")},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			spec, _, err := fixtureFor(test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			capture := renderFixture(t, test.fixture)
			raw, rawErr := inspectSSE(capture.body)
			result := evaluate(spec, test.sdk, raw, rawErr, capture)
			if result.Status != StatusConfirmed {
				t.Fatalf("status = %q, summary = %q", result.Status, result.Summary)
			}
			if test.fixture == FixtureReference && result.FaultDomain != "none" {
				t.Fatalf("reference fault domain = %q", result.FaultDomain)
			}
			if test.fixture != FixtureReference && result.FaultDomain != "wire" {
				t.Fatalf("mutant fault domain = %q", result.FaultDomain)
			}
		})
	}
}

func TestEvaluateDoesNotAttributeArbitraryException(t *testing.T) {
	spec, _, err := fixtureFor(FixtureNullCompletedOutput)
	if err != nil {
		t.Fatal(err)
	}
	capture := renderFixture(t, FixtureNullCompletedOutput)
	raw, rawErr := inspectSSE(capture.body)
	sdk := exceptionObservation(0, "stream_open", "APIConnectionError")
	result := evaluate(spec, sdk, raw, rawErr, capture)
	if result.Status != StatusUnknown || result.FaultDomain != "unknown" {
		t.Fatalf("arbitrary exception was attributed: %+v", result)
	}
}

func TestEvaluateRejectsVersionDrift(t *testing.T) {
	spec, _, _ := fixtureFor(FixtureReference)
	capture := renderFixture(t, FixtureReference)
	raw, rawErr := inspectSSE(capture.body)
	sdk := completedObservation(1)
	other := "2.38.1"
	sdk.Version.OpenAI = &other
	result := evaluate(spec, sdk, raw, rawErr, capture)
	if result.Status != StatusUnknown || result.SDKStatus != "environment_mismatch" {
		t.Fatalf("version drift result = %+v", result)
	}
}

func TestDecodeObservationIsStrict(t *testing.T) {
	valid, err := json.Marshal(completedObservation(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeObservation(valid); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"unknown field": bytes.Replace(valid, []byte(`"event_count":`), []byte(`"extra":true,"event_count":`), 1),
		"trailing JSON": append(slices.Clone(valid), []byte(` {}`)...),
		"invalid UTF-8": {0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeObservation(data); err == nil {
				t.Fatal("invalid observation was accepted")
			}
		})
	}
}

func TestDecodeObservationRejectsFalseLockAttestation(t *testing.T) {
	observation := completedObservation(1)
	observation.Environment.Dependencies = nil
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeObservation(data); err == nil || !strings.Contains(err.Error(), "exact dependency set") {
		t.Fatalf("false lock attestation error = %v", err)
	}
}

func TestRunUsesLoopbackOnlyAndDoesNotInheritSecretsOrProxies(t *testing.T) {
	requireLinuxAMD64(t)
	t.Setenv("ARK_API_KEY", "must-not-be-inherited")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid")
	t.Setenv("ALL_PROXY", "http://proxy.invalid")
	t.Setenv("NO_PROXY", "must-not-be-inherited")
	python := fakePython(t, completedObservation(1))
	result, err := Run(context.Background(), Request{Python: python, Fixture: FixtureReference, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusConfirmed || result.RawTerminalCount != 1 || result.SDKTerminalCount != 1 {
		t.Fatalf("Run() = %+v", result)
	}
	if len(result.Bundle) == 0 {
		t.Fatal("Run() returned an empty evidence bundle")
	}
	for name, content := range readZIP(t, result.Bundle) {
		for _, forbidden := range []string{"must-not-be-inherited", "proxy.invalid"} {
			if bytes.Contains(content, []byte(forbidden)) {
				t.Fatalf("%s retained ephemeral or ambient value %q", name, forbidden)
			}
		}
		if name != "repro/runner.py" && name != "repro/README.md" && bytes.Contains(content, []byte("http://127.0.0.1:")) {
			t.Fatalf("%s retained the ephemeral loopback origin", name)
		}
	}
}

func TestRunRejectsPythonExecutableMutation(t *testing.T) {
	requireLinuxAMD64(t)
	python := fakeMutatingPython(t, completedObservation(1))
	_, err := Run(context.Background(), Request{Python: python, Fixture: FixtureReference})
	if err == nil || !strings.Contains(err.Error(), "content changed") {
		t.Fatalf("mutating Python executable error = %v", err)
	}
}

func TestRunAllFixtureVerdictsWithDeterministicObservations(t *testing.T) {
	requireLinuxAMD64(t)
	tests := []struct {
		fixture string
		sdk     helperObservation
	}{
		{FixtureReference, completedObservation(1)},
		{FixtureMissingTerminalEvent, exceptionObservation(0, "final_response", "RuntimeError")},
		{FixtureDuplicateTerminalEvent, completedObservation(2)},
		{FixtureNullCompletedOutput, exceptionObservation(0, "event_iteration", "TypeError")},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			result, err := Run(context.Background(), Request{Python: fakePython(t, test.sdk), Fixture: test.fixture})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != StatusConfirmed {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestRunReturnsUnknownWhenPinnedEnvironmentDoesNotMakeARequest(t *testing.T) {
	requireLinuxAMD64(t)
	observation := completedObservation(1)
	observation.Version.OpenAI = nil
	expected, observed := OpenAIVersion, "2.38.1"
	for index := range observation.Environment.Dependencies {
		if observation.Environment.Dependencies[index].Name == "openai" {
			observation.Environment.Dependencies[index].Version = observed
		}
	}
	observation.Environment.MatchesLock = false
	observation.Environment.Mismatches = []helperEnvironmentMismatch{{
		Kind: "distribution_version_mismatch", Name: "openai",
		Expected: &expected, Observed: &observed,
	}}
	result, err := Run(context.Background(), Request{
		Python: fakePythonWithoutRequest(t, observation), Fixture: FixtureReference,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusUnknown || result.SDKStatus != "environment_mismatch" || len(result.Bundle) == 0 {
		t.Fatalf("Run() = %+v", result)
	}
	files := readZIP(t, result.Bundle)
	var environment bundleEnvironment
	if err := json.Unmarshal(files["environment.json"], &environment); err != nil {
		t.Fatal(err)
	}
	if environment.Observed.OpenAI != observed || environment.Observed.MatchesLock || environment.Expected.OpenAI != OpenAIVersion || environment.Expected.RequirementsLockSHA256 != sha256Hex(files["repro/requirements.lock"]) {
		t.Fatalf("mismatch environment evidence = %+v", environment)
	}
}

func TestBundleIsDeterministicAndContainsCanonicalAssets(t *testing.T) {
	originalBuild := buildinfo.Current()
	buildinfo.Version = "0.1.0-test"
	buildinfo.Commit = strings.Repeat("a", 40)
	buildinfo.BuiltAt = "2026-07-13T00:00:00Z"
	defer func() {
		buildinfo.Version = originalBuild.Version
		buildinfo.Commit = originalBuild.Commit
		buildinfo.BuiltAt = originalBuild.BuiltAt
	}()

	assets, err := loadCanonicalAssets()
	if err != nil {
		t.Fatal(err)
	}
	spec, _, _ := fixtureFor(FixtureReference)
	result := Result{
		Fixture: FixtureReference, Status: StatusConfirmed, RawTerminalCount: 1,
		RawOutputKind: "array", SDKStatus: "completed", SDKTerminalCount: 1,
		SDKOutputKind: "array", FaultDomain: "none", Summary: "deterministic fixture",
	}
	observation := completedObservation(1)
	pythonDigest := strings.Repeat("b", 64)
	first, err := buildBundle(spec, result, observation, []byte("event: response.completed\n\ndata: {}\n\n"), assets, pythonDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildBundle(spec, result, observation, []byte("event: response.completed\n\ndata: {}\n\n"), assets, pythonDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same evidence did not produce byte-identical ZIPs")
	}
	files := readZIP(t, first)
	wantNames := []string{
		"SHA256SUMS", "SUMMARY.md", "environment.json", "fixture.json", "generator.json", "manifest.json",
		"repro/README.md", "repro/requirements.lock", "repro/runner.py", "result.json",
		"sdk-observation.json", "wire.sse",
	}
	gotNames := make([]string, 0, len(files))
	for name := range files {
		gotNames = append(gotNames, name)
	}
	sort.Strings(gotNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("bundle names = %v, want %v", gotNames, wantNames)
	}
	for name, want := range map[string][]byte{
		"fixture.json":            assets.fixture,
		"repro/runner.py":         assets.runner,
		"repro/requirements.lock": assets.requirements,
	} {
		if !bytes.Equal(files[name], want) {
			t.Fatalf("%s does not match canonical embedded bytes", name)
		}
	}
	var generator bundleGenerator
	if err := json.Unmarshal(files["generator.json"], &generator); err != nil {
		t.Fatal(err)
	}
	if generator.Name != "agentapi-doctor" || generator.Build.Version != "0.1.0-test" || generator.Build.Commit != strings.Repeat("a", 40) || len(generator.ExecutableSHA256) != 64 || generator.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("generator identity = %+v", generator)
	}
	if _, err := hex.DecodeString(generator.ExecutableSHA256); err != nil {
		t.Fatalf("generator executable digest is not hex: %v", err)
	}
	var environment bundleEnvironment
	if err := json.Unmarshal(files["environment.json"], &environment); err != nil {
		t.Fatal(err)
	}
	if environment.Observed.PythonExecutableSHA256 != pythonDigest || !environment.Observed.MatchesLock || environment.Expected.RequirementsLockSHA256 != sha256Hex(assets.requirements) {
		t.Fatalf("environment evidence = %+v", environment)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"fixture.json":            sha256Hex(assets.fixture),
		"repro/requirements.lock": sha256Hex(assets.requirements),
		"repro/runner.py":         sha256Hex(assets.runner),
	} {
		if manifest.CanonicalInputSHA256[name] != want {
			t.Fatalf("manifest digest for %s = %q, want %q", name, manifest.CanonicalInputSHA256[name], want)
		}
	}
	verifyChecksums(t, files)
}

func TestBoundedBufferConsumesButDoesNotRetainOverflow(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	data := []byte("123456789")
	written, err := buffer.Write(data)
	if err != nil || written != len(data) || string(buffer.Bytes()) != "1234" || !buffer.exceeded {
		t.Fatalf("boundedBuffer.Write = (%d, %v), data=%q exceeded=%v", written, err, buffer.Bytes(), buffer.exceeded)
	}
}

func TestRealPinnedSDK(t *testing.T) {
	requireLinuxAMD64(t)
	python := os.Getenv("AGENTAPI_DOCTOR_OPENAI_PYTHON")
	if python == "" {
		t.Skip("set AGENTAPI_DOCTOR_OPENAI_PYTHON to a Python 3.12.12 environment with the hashed openai 2.38.0 lock installed")
	}
	for _, fixture := range SupportedFixtures() {
		t.Run(fixture, func(t *testing.T) {
			result, err := Run(context.Background(), Request{Python: python, Fixture: fixture})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != StatusConfirmed {
				t.Fatalf("real pinned result = %+v", result)
			}
			files := readZIP(t, result.Bundle)
			var environment bundleEnvironment
			if err := json.Unmarshal(files["environment.json"], &environment); err != nil {
				t.Fatal(err)
			}
			if !environment.Observed.MatchesLock || environment.Observed.Python != PythonVersion || environment.Observed.OpenAI != OpenAIVersion || len(environment.Observed.Dependencies) != len(expectedLockedDependencies) || len(environment.Observed.PythonExecutableSHA256) != 64 {
				t.Fatalf("real pinned environment = %+v", environment)
			}
			var generator bundleGenerator
			if err := json.Unmarshal(files["generator.json"], &generator); err != nil {
				t.Fatal(err)
			}
			if generator.Name != "agentapi-doctor" || len(generator.ExecutableSHA256) != 64 {
				t.Fatalf("real pinned generator = %+v", generator)
			}
			verifyChecksums(t, files)
		})
	}
}

func requireLinuxAMD64(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the frozen OpenAI SDK reproduction baseline is Linux x86_64 only")
	}
}

func renderFixture(t *testing.T, fixture string) capturedExchange {
	t.Helper()
	_, transformer, err := fixtureFor(fixture)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := referenceserver.New(referenceserver.Config{Transformer: transformer})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"model":"fixture-model","input":"synthetic","stream":true,"max_output_tokens":32}`
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+referenceserver.SyntheticBearerToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fixture %s HTTP status = %d body=%s", fixture, response.Code, response.Body.String())
	}
	return capturedExchange{
		method: http.MethodPost, path: "/v1/responses", status: response.Code,
		contentType: response.Header().Get("Content-Type"), mutationID: response.Header().Get("X-AgentAPI-Mutant"),
		body: slices.Clone(response.Body.Bytes()),
	}
}

func completedObservation(terminals int) helperObservation {
	openai := OpenAIVersion
	status := "completed"
	outputCount := 1
	events := []string{"response.created"}
	for range terminals {
		events = append(events, "response.completed")
	}
	return helperObservation{
		SchemaVersion: observationSchema,
		Version:       helperVersion{Python: PythonVersion, OpenAI: &openai},
		Environment:   pinnedHelperEnvironment(),
		EventTypes:    events,
		EventCount:    len(events),
		Final:         helperFinal{Status: &status, OutputCount: &outputCount},
	}
}

func exceptionObservation(terminals int, phase, class string) helperObservation {
	openai := OpenAIVersion
	events := []string{"response.created"}
	for range terminals {
		events = append(events, "response.completed")
	}
	return helperObservation{
		SchemaVersion: observationSchema,
		Version:       helperVersion{Python: PythonVersion, OpenAI: &openai},
		Environment:   pinnedHelperEnvironment(),
		EventTypes:    events,
		EventCount:    len(events),
		Exception: &helperException{
			Phase: phase, Class: class,
			SanitizedMessage: "SDK raised a bounded synthetic observation",
		},
	}
}

func pinnedHelperEnvironment() helperEnvironment {
	return helperEnvironment{
		Implementation: "CPython",
		PythonVersion:  PythonVersion,
		System:         "Linux",
		Machine:        "x86_64",
		Dependencies:   slices.Clone(expectedLockedDependencies),
		BootstrapTools: []helperDistribution{},
		MatchesLock:    true,
		Mismatches:     []helperEnvironmentMismatch{},
	}
}

func fakePython(t *testing.T, observation helperObservation) string {
	t.Helper()
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "python-fixture")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
for name in ARK_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY; do
  eval "value=\${$name-}"
  test -z "$value"
done
case "$HOME" in /tmp/agentapi-doctor-openai-sdk-*) ;; *) exit 91 ;; esac
/usr/bin/curl --silent --show-error --fail \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer synthetic-test-token' \
  --data '{"model":"fixture-model","input":"synthetic","stream":true,"max_output_tokens":32}' \
  "$4/responses" >/dev/null
printf '%%s\n' '%s'
`, string(data))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakePythonWithoutRequest(t *testing.T, observation helperObservation) string {
	t.Helper()
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "python-fixture-no-request")
	script := fmt.Sprintf("#!/bin/sh\nset -eu\nprintf '%%s\\n' '%s'\n", string(data))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeMutatingPython(t *testing.T, observation helperObservation) string {
	t.Helper()
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "python-fixture-mutating")
	script := fmt.Sprintf("#!/bin/sh\nset -eu\nprintf '\\n# mutation\\n' >>\"$0\"\nprintf '%%s\\n' '%s'\n", string(data))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func readZIP(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		result[file.Name] = content
	}
	return result
}

func verifyChecksums(t *testing.T, files map[string][]byte) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(files["SHA256SUMS"])), "\n")
	if len(lines) != len(files)-1 {
		t.Fatalf("SHA256SUMS has %d entries, want %d", len(lines), len(files)-1)
	}
	for _, line := range lines {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid checksum line %q", line)
		}
		content, exists := files[parts[1]]
		if !exists {
			t.Fatalf("checksum names missing file %q", parts[1])
		}
		digest := sha256.Sum256(content)
		if parts[0] != hex.EncodeToString(digest[:]) {
			t.Fatalf("checksum mismatch for %s", parts[1])
		}
	}
}
