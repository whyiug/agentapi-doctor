package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

func run(t *testing.T, directory string, args ...string) (int, result) {
	t.Helper()
	return runWithDependencies(t, Dependencies{WorkingDir: directory, Executable: os.Args[0]}, args...)
}

func runWithDependencies(t *testing.T, dependencies Dependencies, args ...string) (int, result) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	dependencies.Stdout = &stdout
	dependencies.Stderr = &stderr
	code := Run(context.Background(), args, dependencies)
	raw := stdout.Bytes()
	if code != 0 {
		raw = stderr.Bytes()
	}
	var decoded result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode CLI output %q: %v", raw, err)
	}
	return code, decoded
}

func saveTargetConfig(t *testing.T, directory, name string, target config.Target) {
	t.Helper()
	value := config.Default()
	value.Targets = map[string]config.Target{name: target}
	if err := config.SaveFile(filepath.Join(directory, ".agentapi", "config.yaml"), value, false); err != nil {
		t.Fatal(err)
	}
}

func TestInitAndTargetLifecycle(t *testing.T) {
	directory := t.TempDir()
	code, initialized := run(t, directory, "init")
	if code != ExitSuccess || initialized.Status != "pass" {
		t.Fatalf("init failed: %#v", initialized)
	}
	path := filepath.Join(directory, ".agentapi", "config.yaml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows exposes synthesized POSIX mode bits; ACLs are the native access
	// control mechanism and are not represented by FileMode.Perm.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config permissions are too broad: %o", info.Mode().Perm())
	}
	if code, _ := run(t, directory, "init"); code != ExitInput {
		t.Fatal("init overwrote existing config")
	}
	code, added := run(t, directory, "target", "add", "second", "--base-url", "https://example.invalid/v1", "--protocol", "openai-chat", "--model", "synthetic", "--auth-ref", "env://SYNTHETIC_TOKEN")
	if code != ExitSuccess || added.Status != "pass" {
		t.Fatalf("target add failed: %#v", added)
	}
	code, listed := run(t, directory, "target", "list")
	if code != ExitSuccess || listed.Status != "pass" {
		t.Fatalf("target list failed: %#v", listed)
	}
	code, inspected := run(t, directory, "target", "inspect", "second")
	if code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("target inspect failed: %#v", inspected)
	}
	encoded, _ := json.Marshal(inspected)
	if bytes.Contains(encoded, []byte("SYNTHETIC_TOKEN")) {
		t.Fatalf("secret reference detail leaked: %s", encoded)
	}
}

func TestExitPriorityAndUnknownCommand(t *testing.T) {
	if got := PrimaryExitCode([]int{ExitTargetFailure, ExitIncomplete, ExitPermission, ExitInfrastructure}); got != ExitPermission {
		t.Fatalf("wrong primary exit: %d", got)
	}
	code, output := run(t, t.TempDir(), "unknown")
	if code != ExitInput || output.PrimaryExitCode != ExitInput || len(output.Conditions) != 1 {
		t.Fatalf("unexpected error: %#v", output)
	}
}

func TestSelfCheckMakesNoNetworkClaim(t *testing.T) {
	code, output := run(t, t.TempDir(), "self-check")
	if code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("self-check failed: %#v", output)
	}
	encoded, _ := json.Marshal(output.Data)
	if !bytes.Contains(encoded, []byte(`"network_calls":0`)) {
		t.Fatalf("missing offline proof: %s", encoded)
	}
}

func TestRunInspectAndOfflineReport(t *testing.T) {
	directory := t.TempDir()
	runs, err := runstore.Open(filepath.Join(directory, ".agentapi", "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	id := schema.InstanceID("018f22e2-79b0-7cc3-98c4-dc0c0c07398f")
	digest := func(value string) schema.Digest { return schema.NewDigest([]byte(value)) }
	pass := schema.VerdictPass
	bundle := report.Bundle{SchemaVersion: report.SchemaVersion, RunID: id, IntentPlanRef: schema.ObjectRef{Kind: "IntentPlan", InstanceID: id, ContentDigest: digest("intent")}, ResolvedPlanRef: schema.ObjectRef{Kind: "ResolvedRunPlan", InstanceID: id, ContentDigest: digest("resolved")}, Profile: schema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "test.profile", Version: "1.0.0", Digest: digest("profile")}, Artifacts: []schema.ArtifactPin{{Kind: "ProtocolPack", Name: "test-pack", Version: "2026.07.0", Digest: digest("pack")}}, SupportLock: digest("support"), Denominators: schema.DenominatorSummary{CandidateDigest: digest("candidate"), CandidateCount: 1, ApplicableDigest: digest("applicable"), ApplicableCount: 1, ExecutedDigest: digest("executed"), ExecutedCount: 1}, Outcome: schema.ProfileCompatible, Dimensions: map[string]schema.DimensionOutcome{"protocol": schema.DimensionPass}, Cases: []schema.CaseResult{{ScenarioID: "one", PlanDisposition: schema.DispositionExecute, AttemptIDs: []schema.InstanceID{id}, ExecutionStatus: schema.ExecutionCompleted, Verdict: &pass, CandidateMember: true, ApplicableMember: true, ExecutedMember: true, AttemptAggregation: "all"}}, Conditions: []report.Condition{}, PrimaryExitCode: 0}
	encoded, err := report.JSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runs.Put(id, encoded); err != nil {
		t.Fatal(err)
	}
	if code, output := run(t, directory, "run", "inspect", "latest"); code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("inspect=%#v", output)
	}
	outputPath := filepath.Join(directory, "report.html")
	if code, output := run(t, directory, "report", "html", "latest", "--output", outputPath); code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("report=%#v", output)
	}
	html, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte("Content-Security-Policy")) {
		t.Fatalf("unsafe report: %s", html)
	}
}

func TestCompletionAndScaffold(t *testing.T) {
	directory := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"completion", "bash"}, Dependencies{Stdout: &stdout, Stderr: &stderr, WorkingDir: directory}); code != ExitSuccess || !bytes.Contains(stdout.Bytes(), []byte("complete -F")) {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	code, output := run(t, directory, "dev", "scaffold", "scenario", "sample.case", "--output", "drafts")
	if code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("scaffold=%#v", output)
	}
	path := filepath.Join(directory, "drafts", "sample.case.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if code, _ := run(t, directory, "dev", "scaffold", "scenario", "sample.case", "--output", "drafts"); code != ExitInput {
		t.Fatalf("existing scaffold code=%d", code)
	}
}

func TestTestPlanOnlyMakesNoRequestOrPersistentRun(t *testing.T) {
	directory := t.TempDir()
	var requests atomic.Int64
	server := httptest.NewServer(httpHandlerFunc(func() { requests.Add(1) }))
	defer server.Close()
	saveTargetConfig(t, directory, "offline", config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
		Auth: &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://MUST_NOT_BE_READ"}},
	})
	code, output := runWithDependencies(t, Dependencies{
		WorkingDir: directory,
		LookupEnv: func(string) (string, bool) {
			t.Fatal("plan-only resolved a credential")
			return "", false
		},
	}, "test", "offline", "--plan-only", "--resolve")
	if code != ExitSuccess || output.Status != "pass" || requests.Load() != 0 {
		t.Fatalf("plan-only result=%#v requests=%d", output, requests.Load())
	}
	if _, err := os.Stat(filepath.Join(directory, ".agentapi", "runs")); !os.IsNotExist(err) {
		t.Fatalf("plan-only created a run store: %v", err)
	}
	encoded, _ := json.Marshal(output.Data)
	if bytes.Contains(encoded, []byte("MUST_NOT_BE_READ")) {
		// Secret reference names are visible in a resolved plan, but secret
		// values must never be. This synthetic marker is the reference name;
		// verify the test did not accidentally use a value with the same text.
		if bytes.Contains(encoded, []byte(`"Authorization"`)) {
			t.Fatalf("plan contains a resolved authentication header: %s", encoded)
		}
	}
}

func TestTestReferencePassesAndPersistsReport(t *testing.T) {
	directory := t.TempDir()
	handler, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	saveTargetConfig(t, directory, "reference", config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
		Auth: &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://SYNTHETIC_TOKEN"}},
	})
	code, output := runWithDependencies(t, Dependencies{
		WorkingDir: directory,
		LookupEnv: func(name string) (string, bool) {
			if name != "SYNTHETIC_TOKEN" {
				return "", false
			}
			return referenceserver.SyntheticBearerToken, true
		},
	}, "test", "reference")
	if code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("test result=%#v", output)
	}
	if code, inspected := run(t, directory, "run", "inspect", "latest"); code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("persisted run=%#v", inspected)
	}
}

func TestTestTargetedMutantReturnsFailureAndKeepsReport(t *testing.T) {
	directory := t.TempDir()
	mutation, err := mutantserver.New(mutantserver.InvalidFinishReason)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := referenceserver.New(referenceserver.Config{Transformer: mutation})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	saveTargetConfig(t, directory, "mutant", config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"})
	code, output := run(t, directory, "test", "mutant")
	if code != ExitTargetFailure || output.Status != "fail" || output.PrimaryExitCode != ExitTargetFailure {
		t.Fatalf("mutant result=%#v code=%d", output, code)
	}
	if code, inspected := run(t, directory, "run", "inspect", "latest"); code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("failed run was not persisted: %#v", inspected)
	}
}

func TestTestRejectsExistingOutputBeforeNetwork(t *testing.T) {
	directory := t.TempDir()
	var requests atomic.Int64
	server := httptest.NewServer(httpHandlerFunc(func() { requests.Add(1) }))
	defer server.Close()
	saveTargetConfig(t, directory, "target", config.Target{BaseURL: server.URL, Protocol: "openai-chat", Model: "fixture-model"})
	outputPath := filepath.Join(directory, "existing.json")
	if err := os.WriteFile(outputPath, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, output := run(t, directory, "test", "target", "--output", outputPath)
	if code != ExitInput || output.Conditions[0].Code != "output_exists" || requests.Load() != 0 {
		t.Fatalf("code=%d output=%#v requests=%d", code, output, requests.Load())
	}
	if value, err := os.ReadFile(outputPath); err != nil || string(value) != "owned" {
		t.Fatalf("existing output changed: %q, %v", value, err)
	}
}

func TestWriteNewFileRejectsSymlinkAncestor(t *testing.T) {
	directory := t.TempDir()
	directory = absolutePath(directory, directory)
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeNewFile(filepath.Join(link, "output.json"), []byte("data")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink ancestor accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realDirectory, "output.json")); !os.IsNotExist(err) {
		t.Fatalf("output escaped through symlink: %v", err)
	}
}

func TestAbsolutePathCanonicalizesOnlyTrustedWorkingDirectory(t *testing.T) {
	directory := t.TempDir()
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolved, "nested", "output.json")
	got := absolutePath(directory, filepath.Join(directory, "nested", "output.json"))
	if got != want {
		t.Fatalf("absolutePath() = %q, want canonical path %q", got, want)
	}

	realDirectory := filepath.Join(resolved, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	trustedLink := filepath.Join(resolved, "trusted-link")
	if err := os.Symlink(realDirectory, trustedLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	canonicalTrusted, err := filepath.EvalSymlinks(trustedLink)
	if err != nil {
		t.Fatal(err)
	}
	safe := absolutePath(trustedLink, filepath.Join(trustedLink, "safe.json"))
	if safe != filepath.Join(canonicalTrusted, "safe.json") {
		t.Fatalf("trusted ancestor was not canonicalized: got %q", safe)
	}
	if err := writeNewFile(safe, []byte("safe")); err != nil {
		t.Fatalf("write through canonical trusted ancestor: %v", err)
	}

	escapeDirectory := filepath.Join(resolved, "escape")
	if err := os.Mkdir(escapeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	untrustedLink := filepath.Join(canonicalTrusted, "untrusted-link")
	if err := os.Symlink(escapeDirectory, untrustedLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	unsafe := absolutePath(trustedLink, filepath.Join(trustedLink, "untrusted-link", "escaped.json"))
	if err := writeNewFile(unsafe, []byte("unsafe")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink below trusted ancestor accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(escapeDirectory, "escaped.json")); !os.IsNotExist(err) {
		t.Fatalf("output escaped through untrusted symlink: %v", err)
	}

	leafTarget := filepath.Join(escapeDirectory, "leaf-target.json")
	if err := os.WriteFile(leafTarget, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	leafLink := filepath.Join(canonicalTrusted, "leaf-link.json")
	if err := os.Symlink(leafTarget, leafLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	leaf := absolutePath(trustedLink, filepath.Join(trustedLink, "leaf-link.json"))
	if err := writeNewFile(leaf, []byte("replacement")); err == nil {
		t.Fatal("symlink destination accepted")
	}
	if data, err := os.ReadFile(leafTarget); err != nil || string(data) != "unchanged" {
		t.Fatalf("symlink destination was replaced: %q, %v", data, err)
	}
}

type httpHandlerFunc func()

func (handler httpHandlerFunc) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	handler()
	writer.WriteHeader(http.StatusInternalServerError)
}
