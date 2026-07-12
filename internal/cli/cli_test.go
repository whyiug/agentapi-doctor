package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/productrun"
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
	code, stdout, stderr := runRawWithDependencies(t, dependencies, args...)
	raw := []byte(stdout)
	if code != 0 {
		raw = []byte(stderr)
	}
	var decoded result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode CLI output %q: %v", raw, err)
	}
	return code, decoded
}

func runRawWithDependencies(t *testing.T, dependencies Dependencies, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	dependencies.Stdout = &stdout
	dependencies.Stderr = &stderr
	code := Run(context.Background(), args, dependencies)
	return code, stdout.String(), stderr.String()
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

func TestQuickPathHelpIsSuccessfulAndSideEffectFree(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name     string
		args     []string
		contains []string
	}{
		{name: "general help", args: []string{"help"}, contains: []string{"Quick paths:", "doctor demo", "doctor help test"}},
		{name: "test topic", args: []string{"help", "test"}, contains: []string{"Check one authorized endpoint", "--base-url", "--auth-env"}},
		{name: "demo topic", args: []string{"help", "demo"}, contains: []string{"four compatibility checks", "no API key"}},
		{name: "report topic", args: []string{"help", "report"}, contains: []string{"Export a saved run", "markdown latest"}},
		{name: "test flag", args: []string{"test", "--help"}, contains: []string{"Check one authorized endpoint", "--plan-only"}},
		{name: "demo flag", args: []string{"demo", "--help"}, contains: []string{"four compatibility checks", "doctor demo"}},
		{name: "report flag", args: []string{"report", "--help"}, contains: []string{"Formats: terminal", "doctor-report.md"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: directory}, test.args...)
			if code != ExitSuccess || stderr != "" {
				t.Fatalf("help failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, fragment := range test.contains {
				if !strings.Contains(stdout, fragment) {
					t.Fatalf("help omitted %q:\n%s", fragment, stdout)
				}
			}
		})
	}
	if _, err := os.Stat(filepath.Join(directory, ".agentapi")); !os.IsNotExist(err) {
		t.Fatalf("help command created runtime data: %v", err)
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
	planBaseURL := "https://example.invalid/v1"
	planned, err := productrun.Build(productrun.PlanRequest{TargetName: "fixture", Target: config.Target{
		BaseURL: planBaseURL, Protocol: "openai-responses", Model: "fixture-model",
	}})
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := productrun.PlanJSON(planned)
	if err != nil {
		t.Fatal(err)
	}
	pass := schema.VerdictPass
	bundle := report.Bundle{SchemaVersion: report.SchemaVersion, RunID: id, IntentPlanRef: planned.Intent.ObjectRef, ResolvedPlanRef: planned.Resolved.ObjectRef, Profile: schema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "test.profile", Version: "1.0.0", Digest: digest("profile")}, Artifacts: []schema.ArtifactPin{{Kind: "ProtocolPack", Name: "test-pack", Version: "2026.07.0", Digest: digest("pack")}}, SupportLock: digest("support"), Denominators: schema.DenominatorSummary{CandidateDigest: digest("candidate"), CandidateCount: 1, ApplicableDigest: digest("applicable"), ApplicableCount: 1, ExecutedDigest: digest("executed"), ExecutedCount: 1}, Outcome: schema.ProfileCompatible, Dimensions: map[string]schema.DimensionOutcome{"protocol": schema.DimensionPass}, Cases: []schema.CaseResult{{ScenarioID: "one", PlanDisposition: schema.DispositionExecute, AttemptIDs: []schema.InstanceID{id}, ExecutionStatus: schema.ExecutionCompleted, Verdict: &pass, CandidateMember: true, ApplicableMember: true, ExecutedMember: true, AttemptAggregation: "all"}}, Conditions: []report.Condition{}, PrimaryExitCode: 0}
	encoded, err := report.JSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runs.Put(id, runstore.Payload{Bundle: encoded, Plan: planJSON}); err != nil {
		t.Fatal(err)
	}
	code, output := run(t, directory, "run", "inspect", "latest")
	if code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("inspect=%#v", output)
	}
	data, ok := output.Data.(map[string]any)
	if !ok || data["plan_available"] != true || data["plan_digest"] != string(schema.NewDigest(planJSON)) {
		t.Fatalf("inspect plan summary=%#v", output.Data)
	}
	if _, exposed := data["plan"]; exposed {
		t.Fatalf("inspect exposed plan without --include-plan: %#v", data)
	}
	code, included := run(t, directory, "run", "inspect", "latest", "--include-plan")
	if code != ExitSuccess || included.Status != "pass" {
		t.Fatalf("inspect include-plan=%#v", included)
	}
	includedData := included.Data.(map[string]any)
	includedPlan := includedData["plan"].(map[string]any)
	includedTarget := includedPlan["target"].(map[string]any)
	if includedTarget["baseURL"] != planBaseURL {
		t.Fatalf("included plan lost exact base URL: %#v", includedTarget)
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

func TestRunInspectReadsLegacyRecordWithoutInventingPlan(t *testing.T) {
	directory := t.TempDir()
	id := schema.InstanceID("018f22e2-79b0-7cc3-98c4-dc0c0c073990")
	currentBundle, err := report.Decode(validReportBytes(t, id,
		schema.ObjectRef{Kind: "IntentPlan", InstanceID: id, ContentDigest: schema.NewDigest([]byte("legacy-intent"))},
		schema.ObjectRef{Kind: "ResolvedRunPlan", InstanceID: id, ContentDigest: schema.NewDigest([]byte("legacy-resolved"))},
	))
	if err != nil {
		t.Fatal(err)
	}
	currentBundle.SchemaVersion = "urn:agentapi-doctor:report-bundle:v1alpha1"
	legacyBundle, err := report.JSON(currentBundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle := json.RawMessage(legacyBundle)
	legacyRecord := struct {
		SchemaVersion string            `json:"schema_version"`
		RunID         schema.InstanceID `json:"run_id"`
		BundleDigest  schema.Digest     `json:"bundle_digest"`
		Bundle        json.RawMessage   `json:"bundle"`
	}{
		SchemaVersion: "urn:agentapi-doctor:local-run-record:v1alpha1",
		RunID:         id,
		BundleDigest:  schema.NewDigest(bundle),
		Bundle:        bundle,
	}
	encoded, err := schema.CanonicalMarshal(legacyRecord)
	if err != nil {
		t.Fatal(err)
	}
	recordDirectory := filepath.Join(directory, ".agentapi", "runs", string(id))
	if err := os.MkdirAll(recordDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recordDirectory, "record.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	code, inspected := run(t, directory, "run", "inspect", string(id))
	if code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("legacy inspect failed: code=%d result=%#v", code, inspected)
	}
	data := inspected.Data.(map[string]any)
	if data["plan_available"] != false || data["plan_digest"] != "" {
		t.Fatalf("legacy inspect invented a plan: %#v", data)
	}
	if _, exists := data["plan"]; exists {
		t.Fatalf("legacy inspect exposed an invented plan: %#v", data)
	}
	code, unavailable := run(t, directory, "run", "inspect", string(id), "--include-plan")
	if code != ExitInput || len(unavailable.Conditions) != 1 || unavailable.Conditions[0].Code != "plan_unavailable" {
		t.Fatalf("legacy include-plan did not fail clearly: code=%d result=%#v", code, unavailable)
	}
}

func TestAllRunConsumersRejectCrossBoundPlanAndReport(t *testing.T) {
	directory := t.TempDir()
	runs, err := runstore.Open(filepath.Join(directory, ".agentapi", "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	id := schema.InstanceID("018f22e2-79b0-7cc3-98c4-dc0c0c073992")
	first, err := productrun.Build(productrun.PlanRequest{TargetName: "first", Target: config.Target{
		BaseURL: "https://first.example.invalid/v1", Protocol: "openai-chat", Model: "first-model",
	}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := productrun.Build(productrun.PlanRequest{TargetName: "second", Target: config.Target{
		BaseURL: "https://second.example.invalid/v1", Protocol: "openai-chat", Model: "second-model",
	}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := productrun.PlanJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	bundle := validReportBytes(t, id, second.Intent.ObjectRef, second.Resolved.ObjectRef)
	if _, err := runs.Put(id, runstore.Payload{Bundle: bundle, Plan: plan}); err != nil {
		t.Fatal(err)
	}

	for name, arguments := range map[string][]string{
		"inspect":         {"run", "inspect", string(id)},
		"report":          {"report", "json", string(id)},
		"compare":         {"compare", string(id), string(id)},
		"baseline accept": {"baseline", "accept", string(id), "--name", "cross-bound"},
	} {
		t.Run(name, func(t *testing.T) {
			code, output := run(t, directory, arguments...)
			if code == ExitSuccess || output.Status == "pass" {
				t.Fatalf("cross-bound run was consumed: code=%d output=%#v", code, output)
			}
		})
	}
}

func TestRunInspectRejectsSemanticallyInvalidPersistedPlan(t *testing.T) {
	directory := t.TempDir()
	runs, err := runstore.Open(filepath.Join(directory, ".agentapi", "runs"), 0)
	if err != nil {
		t.Fatal(err)
	}
	id := schema.InstanceID("018f22e2-79b0-7cc3-98c4-dc0c0c073991")
	invalidPlan := []byte(`{"schema_version":"urn:agentapi-doctor:local-plan-snapshot:v1alpha1","target_name":"fixture"}`)
	if _, err := runs.Put(id, runstore.Payload{Bundle: []byte(`{}`), Plan: invalidPlan}); err != nil {
		t.Fatal(err)
	}

	code, inspected := run(t, directory, "run", "inspect", string(id))
	if code != ExitInfrastructure || inspected.PrimaryExitCode != ExitInfrastructure || len(inspected.Conditions) != 1 || inspected.Conditions[0].Code != "run_corrupt" {
		t.Fatalf("semantically invalid plan was accepted: code=%d result=%#v", code, inspected)
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
		Auth:     &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://MUST_NOT_BE_READ"}},
		Metadata: map[string]string{"sensitive-note": "MUST_NOT_BE_PERSISTED"},
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
	for _, marker := range [][]byte{[]byte("MUST_NOT_BE_READ"), []byte("MUST_NOT_BE_PERSISTED")} {
		if bytes.Contains(encoded, marker) {
			t.Fatalf("resolved plan output exposed private target configuration %q: %s", marker, encoded)
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

func TestTestInlineReferencePassesWithoutConfigAndRedactsSecret(t *testing.T) {
	directory := t.TempDir()
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer "+referenceserver.SyntheticBearerToken {
			http.Error(writer, "missing synthetic bearer", http.StatusUnauthorized)
			return
		}
		requests.Add(1)
		reference.ServeHTTP(writer, request)
	}))
	defer server.Close()
	inlineBaseURL := server.URL + "/v1"

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{
		WorkingDir: directory,
		LookupEnv: func(name string) (string, bool) {
			if name != "DOCTOR_INLINE_TOKEN" {
				return "", false
			}
			return referenceserver.SyntheticBearerToken, true
		},
	}, "test",
		"--base-url", inlineBaseURL,
		"--protocol", "openai-responses",
		"--model", "fixture-model",
		"--auth-env", "DOCTOR_INLINE_TOKEN",
		"--allow-plain-http",
		"--format", "json",
	)
	if code != ExitSuccess || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var output result
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("inline JSON output is invalid: %v\n%s", err, stdout)
	}
	if output.Status != "pass" || output.SchemaVersion != resultSchema || requests.Load() != 4 {
		t.Fatalf("output=%#v requests=%d", output, requests.Load())
	}
	if strings.Contains(stdout+stderr, referenceserver.SyntheticBearerToken) {
		t.Fatalf("resolved bearer token leaked to CLI output: stdout=%q stderr=%q", stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(directory, ".agentapi", "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("inline mode created or touched config: %v", err)
	}
	for _, store := range []string{"evidence", "runs"} {
		entries, err := os.ReadDir(filepath.Join(directory, ".agentapi", store))
		if err != nil || len(entries) == 0 {
			t.Fatalf("inline mode did not persist %s: entries=%d err=%v", store, len(entries), err)
		}
	}
	var persisted bytes.Buffer
	if err := filepath.Walk(filepath.Join(directory, ".agentapi"), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		raw, err := os.ReadFile(path)
		if err == nil {
			persisted.Write(raw)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted.Bytes(), []byte(referenceserver.SyntheticBearerToken)) {
		t.Fatal("resolved inline credential reached evidence or run persistence")
	}
	code, inspected := run(t, directory, "run", "inspect", "latest")
	if code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("inline run was not inspectable: code=%d result=%#v", code, inspected)
	}
	inspectData := inspected.Data.(map[string]any)
	if inspectData["plan_available"] != true || inspectData["plan_digest"] == "" {
		t.Fatalf("inline inspect omitted plan summary: %#v", inspectData)
	}
	if _, exposed := inspectData["plan"]; exposed {
		t.Fatalf("inline inspect exposed plan by default: %#v", inspectData)
	}
	code, included := run(t, directory, "run", "inspect", "latest", "--include-plan")
	if code != ExitSuccess || included.Status != "pass" {
		t.Fatalf("inline include-plan failed: code=%d result=%#v", code, included)
	}
	includedPlan := included.Data.(map[string]any)["plan"].(map[string]any)
	includedTarget := includedPlan["target"].(map[string]any)
	if includedTarget["baseURL"] != inlineBaseURL {
		t.Fatalf("inline persisted plan base URL = %#v, want %q", includedTarget["baseURL"], inlineBaseURL)
	}
	includedJSON, err := json.Marshal(included.Data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(includedJSON, []byte(referenceserver.SyntheticBearerToken)) {
		t.Fatal("included inline plan contains the resolved credential")
	}
}

func TestTestInlineCustomHeaderDefaultsToTerminal(t *testing.T) {
	directory := t.TempDir()
	reference, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var unexpectedAuthorization atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			unexpectedAuthorization.Store(true)
		}
		if got := request.Header.Get("x-api-key"); got != referenceserver.SyntheticAPIKey {
			http.Error(writer, "missing synthetic API key", http.StatusUnauthorized)
			return
		}
		requests.Add(1)
		reference.ServeHTTP(writer, request)
	}))
	defer server.Close()

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{
		WorkingDir: directory,
		LookupEnv: func(name string) (string, bool) {
			if name != "DOCTOR_INLINE_API_KEY" {
				return "", false
			}
			return referenceserver.SyntheticAPIKey, true
		},
	}, "test",
		"--base-url", server.URL+"/v1",
		"--protocol", "openai-responses",
		"--model", "fixture-model",
		"--auth-env", "DOCTOR_INLINE_API_KEY",
		"--auth-header", "x-api-key",
		"--allow-plain-http",
	)
	if code != ExitSuccess || stderr != "" || requests.Load() != 4 || unexpectedAuthorization.Load() {
		t.Fatalf("code=%d requests=%d auth=%t stdout=%q stderr=%q", code, requests.Load(), unexpectedAuthorization.Load(), stdout, stderr)
	}
	if !strings.Contains(stdout, "Profile outcome: COMPATIBLE") || !strings.Contains(stdout, "Verdicts: PASS 4") {
		t.Fatalf("inline terminal report is not readable or complete:\n%s", stdout)
	}
	if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("inline mode unexpectedly defaulted to JSON: %s", stdout)
	}
	if strings.Contains(stdout+stderr, referenceserver.SyntheticAPIKey) {
		t.Fatalf("resolved API key leaked to CLI output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestTestInlinePlanOnlyMakesZeroRequestsAndCreatesZeroFiles(t *testing.T) {
	directory := t.TempDir()
	var requests atomic.Int64
	server := httptest.NewServer(httpHandlerFunc(func() { requests.Add(1) }))
	defer server.Close()
	secretValue := "must-never-be-resolved-or-rendered"

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{
		WorkingDir: directory,
		LookupEnv: func(string) (string, bool) {
			t.Fatal("inline plan-only resolved a credential")
			return secretValue, true
		},
	}, "test",
		"--base-url", server.URL+"/v1",
		"--protocol", "openai-responses",
		"--model", "fixture-model",
		"--auth-env", "PLAN_ONLY_TOKEN",
		"--allow-plain-http",
		"--plan-only",
		"--resolve",
		"--format", "json",
	)
	if code != ExitSuccess || stderr != "" || requests.Load() != 0 {
		t.Fatalf("code=%d requests=%d stdout=%q stderr=%q", code, requests.Load(), stdout, stderr)
	}
	var output result
	if err := json.Unmarshal([]byte(stdout), &output); err != nil || output.Status != "pass" {
		t.Fatalf("plan-only output=%#v err=%v raw=%s", output, err, stdout)
	}
	for _, marker := range []string{secretValue, "PLAN_ONLY_TOKEN"} {
		if strings.Contains(stdout+stderr, marker) {
			t.Fatalf("private credential material %q appeared in plan output: %q %q", marker, stdout, stderr)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("inline plan-only created files: %v", entries)
	}
}

func TestTestInlineHTTPConsentAndStrictArgumentErrors(t *testing.T) {
	directory := t.TempDir()
	code, output := run(t, directory, "test",
		"--base-url", "http://127.0.0.1:9/v1",
		"--protocol", "openai-responses",
		"--model", "fixture-model",
		"--allow-plain-http",
		"--plan-only",
		"--format", "json",
	)
	if code != ExitSuccess || output.Status != "pass" {
		t.Fatalf("explicit plain-HTTP consent was rejected: code=%d output=%#v", code, output)
	}
	if _, err := os.Stat(filepath.Join(directory, ".agentapi")); !os.IsNotExist(err) {
		t.Fatalf("HTTP plan-only created state: %v", err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "no arguments", args: []string{"test", "--format", "json"}},
		{name: "legacy and inline", args: []string{"test", "saved", "--format", "json", "--base-url", "https://example.invalid/v1"}},
		{name: "missing model", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--format", "json"}},
		{name: "inline config", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--config", "elsewhere.yaml", "--format", "json"}},
		{name: "header without env", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--auth-header", "x-api-key", "--format", "json"}},
		{name: "empty auth env", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--auth-env=", "--format", "json"}},
		{name: "empty auth header", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--auth-env", "TOKEN", "--auth-header=", "--format", "json"}},
		{name: "nonportable env", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--auth-env", "BAD-NAME", "--format", "json"}},
		{name: "HTTP without consent", args: []string{"test", "--base-url", "http://127.0.0.1:9/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--plan-only", "--format", "json"}},
		{name: "HTTP consent on HTTPS", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--allow-plain-http", "--plan-only", "--format", "json"}},
		{name: "extra positional", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--format", "json", "extra"}},
		{name: "resolve without plan-only", args: []string{"test", "--base-url", "https://example.invalid/v1", "--protocol", "openai-responses", "--model", "fixture-model", "--resolve", "--format", "json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, output := run(t, t.TempDir(), test.args...)
			if code != ExitInput || output.Status != "error" || len(output.Conditions) != 1 || output.Conditions[0].Code != "invalid_arguments" {
				t.Fatalf("code=%d output=%#v", code, output)
			}
		})
	}
}

func TestInlineAndDemoEarlyErrorsHonorPresentationFormat(t *testing.T) {
	inlineArgs := []string{
		"test", "--base-url", "https://example.invalid/v1",
		"--protocol", "unsupported", "--model", "fixture-model", "--plan-only",
	}
	code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: t.TempDir()}, inlineArgs...)
	if code != ExitInput || stdout != "" || !strings.Contains(stderr, "AgentAPI Doctor: ERROR") || strings.HasPrefix(strings.TrimSpace(stderr), "{") {
		t.Fatalf("inline terminal error: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, output := run(t, t.TempDir(), append(inlineArgs, "--format", "json")...)
	if code != ExitInput || output.Status != "error" || output.Conditions[0].Code != "plan_failed" {
		t.Fatalf("inline JSON error: code=%d output=%#v", code, output)
	}

	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "terminal parse", args: []string{"demo", "--unknown"}},
		{name: "JSON parse", args: []string{"demo", "--format", "json", "--unknown"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: t.TempDir()}, test.args...)
			if code != ExitInput || stdout != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if test.json {
				var output result
				if err := json.Unmarshal([]byte(stderr), &output); err != nil || output.Conditions[0].Code != "invalid_arguments" {
					t.Fatalf("JSON error=%#v err=%v raw=%q", output, err, stderr)
				}
			} else if !strings.Contains(stderr, "AgentAPI Doctor: ERROR") || strings.HasPrefix(strings.TrimSpace(stderr), "{") {
				t.Fatalf("terminal error=%q", stderr)
			}
		})
	}

	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "terminal demo plan"},
		{name: "JSON demo plan", args: []string{"--format", "json"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runDemoWithServer(context.Background(), test.args, Dependencies{
				WorkingDir: t.TempDir(), Stdout: &stdout, Stderr: &stderr,
			}, func() (string, func() error, error) {
				return "not-an-absolute-url", func() error { return nil }, nil
			})
			if code != ExitInfrastructure || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if test.json {
				var output result
				if err := json.Unmarshal(stderr.Bytes(), &output); err != nil || output.Conditions[0].Code != "demo_plan_failed" {
					t.Fatalf("JSON plan error=%#v err=%v raw=%q", output, err, stderr.String())
				}
			} else if !strings.Contains(stderr.String(), "AgentAPI Doctor: ERROR") || strings.HasPrefix(strings.TrimSpace(stderr.String()), "{") {
				t.Fatalf("terminal plan error=%q", stderr.String())
			}
		})
	}

	for _, args := range [][]string{
		{"test", "--format", "yaml"},
		{"test", "--format="},
	} {
		code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: t.TempDir()}, args...)
		if code != ExitInput || stdout != "" || !strings.Contains(stderr, "AgentAPI Doctor: ERROR") {
			t.Fatalf("invalid format did not fail in the default terminal presentation: args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestInlineCredentialValidationUsesPermissionExit(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		present    bool
		reasonCode string
	}{
		{name: "missing", present: false, reasonCode: "credential_unavailable"},
		{name: "empty", present: true, reasonCode: "credential_invalid"},
		{name: "short", value: "abc", present: true, reasonCode: "credential_invalid"},
		{name: "NUL", value: "synthetic\x00token", present: true, reasonCode: "credential_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, output := runWithDependencies(t, Dependencies{
				WorkingDir: t.TempDir(),
				LookupEnv:  func(string) (string, bool) { return test.value, test.present },
			}, "test",
				"--base-url", "https://example.invalid/v1",
				"--protocol", "openai-responses",
				"--model", "fixture-model",
				"--auth-env", "DOCTOR_TEST_TOKEN",
				"--format", "json",
			)
			if code != ExitPermission || output.PrimaryExitCode != ExitPermission || output.Conditions[0].Code != test.reasonCode {
				t.Fatalf("code=%d output=%#v", code, output)
			}
		})
	}

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{
		WorkingDir: t.TempDir(),
		LookupEnv:  func(string) (string, bool) { return "abc", true },
	}, "test",
		"--base-url", "https://example.invalid/v1",
		"--protocol", "openai-responses",
		"--model", "fixture-model",
		"--auth-env", "DOCTOR_TEST_TOKEN",
	)
	if code != ExitPermission || stdout != "" || !strings.Contains(stderr, "AgentAPI Doctor: ERROR") || strings.HasPrefix(strings.TrimSpace(stderr), "{") {
		t.Fatalf("terminal credential error: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestTestLegacyTargetDefaultsToUnchangedJSONAndSupportsTerminal(t *testing.T) {
	directory := t.TempDir()
	handler, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	saveTargetConfig(t, directory, "legacy", config.Target{
		BaseURL: server.URL + "/v1", Protocol: "openai-responses", Model: "fixture-model",
	})

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: directory}, "test", "legacy")
	if code != ExitSuccess || stderr != "" || !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("legacy default changed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("legacy default is not JSON: %v\n%s", err, stdout)
	}
	for _, key := range []string{"schema_version", "status", "primary_exit_code", "conditions", "data"} {
		if _, ok := envelope[key]; !ok {
			t.Fatalf("legacy JSON envelope lost %q: %s", key, stdout)
		}
	}
	if len(envelope) != 5 {
		t.Fatalf("legacy JSON envelope shape changed: keys=%v", envelope)
	}
	var output result
	if err := json.Unmarshal([]byte(stdout), &output); err != nil || output.Status != "pass" || output.SchemaVersion != resultSchema {
		t.Fatalf("legacy result=%#v err=%v", output, err)
	}

	code, stdout, stderr = runRawWithDependencies(t, Dependencies{WorkingDir: directory}, "test", "legacy", "--format", "terminal")
	if code != ExitSuccess || stderr != "" || !strings.Contains(stdout, "Verdicts: PASS 4") {
		t.Fatalf("legacy terminal output failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestDemoRunsFourChecksPersistsAndAutomaticallyStopsServer(t *testing.T) {
	directory := t.TempDir()
	var demoURL string
	var stopped atomic.Bool
	starter := func() (string, func() error, error) {
		baseURL, stop, err := startDemoReferenceServer()
		if err != nil {
			return "", nil, err
		}
		demoURL = baseURL
		return baseURL, func() error {
			err := stop()
			stopped.Store(true)
			return err
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runDemoWithServer(context.Background(), nil, Dependencies{
		WorkingDir: directory,
		Stdout:     &stdout,
		Stderr:     &stderr,
		LookupEnv: func(string) (string, bool) {
			t.Fatal("demo read an ambient credential")
			return "", false
		},
	}, starter)
	if code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !stopped.Load() {
		t.Fatal("demo returned without stopping its in-process server")
	}
	if !strings.Contains(stdout.String(), "Profile outcome: COMPATIBLE") || !strings.Contains(stdout.String(), "Verdicts: PASS 4") {
		t.Fatalf("demo did not complete all four checks:\n%s", stdout.String())
	}
	passRows := 0
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "PASS ") {
			passRows++
		}
	}
	if passRows != 4 {
		t.Fatalf("demo rendered %d PASS case rows, want 4:\n%s", passRows, stdout.String())
	}
	parsed, err := url.Parse(demoURL)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Port() == "0" {
		t.Fatalf("demo server did not use a random loopback port: url=%q err=%v", demoURL, err)
	}
	if connection, err := net.DialTimeout("tcp", parsed.Host, 200*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatalf("demo server remains reachable after command returned: %s", parsed.Host)
	}
	if _, err := os.Stat(filepath.Join(directory, ".agentapi", "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("demo created config: %v", err)
	}
	code, inspected := run(t, directory, "run", "inspect", "latest")
	if code != ExitSuccess || inspected.Status != "pass" {
		t.Fatalf("demo run was not persisted: code=%d result=%#v", code, inspected)
	}
	inspectData := inspected.Data.(map[string]any)
	if inspectData["plan_available"] != true {
		t.Fatalf("demo inspect omitted plan summary: %#v", inspectData)
	}
	if _, exposed := inspectData["plan"]; exposed {
		t.Fatalf("demo inspect exposed plan by default: %#v", inspectData)
	}
	code, included := run(t, directory, "run", "inspect", "latest", "--include-plan")
	if code != ExitSuccess || included.Status != "pass" {
		t.Fatalf("demo include-plan failed: code=%d result=%#v", code, included)
	}
	includedPlan := included.Data.(map[string]any)["plan"].(map[string]any)
	includedTarget := includedPlan["target"].(map[string]any)
	if includedTarget["baseURL"] != demoURL+"/v1" {
		t.Fatalf("demo persisted plan base URL = %#v, want %q", includedTarget["baseURL"], demoURL+"/v1")
	}
}

func TestDemoRejectsExistingOutputBeforeStartingServer(t *testing.T) {
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "existing.json")
	if err := os.WriteFile(outputPath, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var started atomic.Bool
	var stdout, stderr bytes.Buffer
	code := runDemoWithServer(context.Background(), []string{"--output", outputPath}, Dependencies{
		WorkingDir: directory, Stdout: &stdout, Stderr: &stderr,
	}, func() (string, func() error, error) {
		started.Store(true)
		return "", nil, errors.New("must not start")
	})
	if code != ExitInput || started.Load() || stdout.Len() != 0 || !strings.Contains(stderr.String(), "AgentAPI Doctor: ERROR") {
		t.Fatalf("code=%d started=%t stdout=%q stderr=%q", code, started.Load(), stdout.String(), stderr.String())
	}
	if value, err := os.ReadFile(outputPath); err != nil || string(value) != "owned" {
		t.Fatalf("existing output changed: %q err=%v", value, err)
	}
}

func TestDemoStopFailureCannotReturnPass(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "terminal"},
		{name: "JSON", args: []string{"--format", "json"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			outputPath := filepath.Join(directory, "demo-report.json")
			starter := func() (string, func() error, error) {
				baseURL, stop, err := startDemoReferenceServer()
				if err != nil {
					return "", nil, err
				}
				return baseURL, func() error {
					if err := stop(); err != nil {
						return err
					}
					return errors.New("synthetic demo stop failure")
				}, nil
			}
			var stdout, stderr bytes.Buffer
			arguments := append(append([]string(nil), test.args...), "--output", outputPath)
			code := runDemoWithServer(context.Background(), arguments, Dependencies{
				WorkingDir: directory, Stdout: &stdout, Stderr: &stderr,
			}, starter)
			if code != ExitInfrastructure || stdout.Len() != 0 || strings.Contains(stderr.String(), "Profile outcome: COMPATIBLE") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if test.json {
				var output result
				if err := json.Unmarshal(stderr.Bytes(), &output); err != nil || output.Conditions[0].Code != "demo_cleanup_failed" {
					t.Fatalf("JSON cleanup error=%#v err=%v raw=%q", output, err, stderr.String())
				}
			} else if !strings.Contains(stderr.String(), "AgentAPI Doctor: ERROR") || strings.HasPrefix(strings.TrimSpace(stderr.String()), "{") {
				t.Fatalf("terminal cleanup error=%q", stderr.String())
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("cleanup failure published report output: %v", err)
			}
			if _, err := os.Stat(filepath.Join(directory, ".agentapi", "runs")); !os.IsNotExist(err) {
				t.Fatalf("cleanup failure published a durable run: %v", err)
			}
		})
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

func validReportBytes(t *testing.T, runID schema.InstanceID, intentRef, resolvedRef schema.ObjectRef) []byte {
	t.Helper()
	digest := func(value string) schema.Digest { return schema.NewDigest([]byte(value)) }
	bundle := report.Bundle{
		SchemaVersion: report.SchemaVersion, RunID: runID, IntentPlanRef: intentRef, ResolvedPlanRef: resolvedRef,
		Profile:     schema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "test.profile", Version: "1.0.0", Digest: digest("profile")},
		Artifacts:   []schema.ArtifactPin{{Kind: "ProtocolPack", Name: "test-pack", Version: "2026.07.0", Digest: digest("pack")}},
		SupportLock: digest("support"),
		Denominators: schema.DenominatorSummary{
			CandidateDigest: digest("candidate"), ApplicableDigest: digest("applicable"), ExecutedDigest: digest("executed"),
		},
		Outcome: schema.ProfileCompatible, Dimensions: map[string]schema.DimensionOutcome{}, Cases: []schema.CaseResult{},
		Conditions: []report.Condition{}, PrimaryExitCode: ExitSuccess,
	}
	encoded, err := report.JSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type httpHandlerFunc func()

func (handler httpHandlerFunc) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	handler()
	writer.WriteHeader(http.StatusInternalServerError)
}
