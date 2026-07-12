package process_e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whyiug/agentapi-doctor/internal/cas"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestPersistedReportEvidenceGraphCloses(t *testing.T) {
	repositoryRoot := sourceRepositoryRoot(t)
	buildRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	buildEnvironment := isolatedEnvironment(t, filepath.Join(buildRoot, "environment"), true)
	runtimeEnvironment := isolatedEnvironment(t, filepath.Join(runtimeRoot, "environment"), false)
	assertNoAmbientCredentials(t, buildEnvironment)
	assertNoAmbientCredentials(t, runtimeEnvironment)

	doctor := buildBinary(t, repositoryRoot, buildRoot, buildEnvironment, "doctor", "./cmd/doctor")
	reference := buildBinary(t, repositoryRoot, buildRoot, buildEnvironment, "reference-server", "./cmd/reference-server")
	address, stopReference := startReferenceServer(t, reference, runtimeRoot, runtimeEnvironment)
	defer stopReference()
	waitForReferenceServer(t, address)

	workspace := filepath.Join(runtimeRoot, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	// The reference server accepts only this documented synthetic credential;
	// it still exercises the complete secret-resolution and redaction path.
	canary := []byte("synthetic-test-token")
	runtimeEnvironment = append(runtimeEnvironment, "GRAPH_CLOSURE_TOKEN="+string(canary))
	output := runPlain(t, doctor, workspace, runtimeEnvironment,
		"test",
		"--base-url", "http://"+address+"/v1",
		"--protocol", "openai-responses",
		"--model", "synthetic-model",
		"--auth-env", "GRAPH_CLOSURE_TOKEN",
		"--allow-plain-http",
		"--format", "terminal",
	)
	runID := assertPassingTerminal(t, "authenticated inline test", output)

	dataRoot := filepath.Join(workspace, ".agentapi")
	runs, err := runstore.Open(filepath.Join(dataRoot, "runs"), runstore.DefaultMaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := runs.Get(runID, false)
	if err != nil {
		t.Fatalf("load persisted run record: %v", err)
	}
	bundle, err := report.Decode(record.Bundle)
	if err != nil {
		t.Fatalf("decode persisted report: %v", err)
	}
	if string(bundle.RunID) != runID {
		t.Fatalf("persisted report run ID = %s, want %s", bundle.RunID, runID)
	}
	evidenceStore, err := cas.Open(filepath.Join(dataRoot, "evidence"), cas.DefaultMaxObjectBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertEvidenceGraphCloses(t, "passing report", bundle, evidenceStore, canary, false)

	stdout, stderr, runErr := runCommand(doctor, workspace, runtimeEnvironment,
		"test",
		"--base-url", "http://"+address+"/synthetic-missing-prefix",
		"--protocol", "openai-responses",
		"--model", "synthetic-model",
		"--auth-env", "GRAPH_CLOSURE_TOKEN",
		"--allow-plain-http",
		"--format", "terminal",
	)
	var exitError *exec.ExitError
	if !errors.As(runErr, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("failing synthetic run exit = %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout, stderr)
	}
	if len(bytes.TrimSpace(stdout)) != 0 {
		t.Fatalf("failing terminal run wrote unexpected stdout:\n%s", stdout)
	}
	failureTerminal := string(stderr)
	for _, expected := range []string{"Profile outcome: INCOMPATIBLE", "FAIL 4"} {
		if !strings.Contains(failureTerminal, expected) {
			t.Fatalf("failing synthetic run omitted %q:\n%s", expected, failureTerminal)
		}
	}
	failureRunID := terminalRunID(t, "failing synthetic run", failureTerminal)
	failureRecord, err := runs.Get(failureRunID, false)
	if err != nil {
		t.Fatalf("load failing persisted run record: %v", err)
	}
	failureBundle, err := report.Decode(failureRecord.Bundle)
	if err != nil {
		t.Fatalf("decode failing persisted report: %v", err)
	}
	if string(failureBundle.RunID) != failureRunID || failureBundle.Outcome != schema.ProfileIncompatible || failureBundle.PrimaryExitCode != 1 {
		t.Fatalf("failing persisted report identity/outcome = %#v", failureBundle)
	}
	assertEvidenceGraphCloses(t, "failing report", failureBundle, evidenceStore, canary, true)

	if err := filepath.WalkDir(dataRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(raw, canary) {
			t.Fatalf("credential canary reached persisted run data at %q", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func terminalRunID(t *testing.T, label, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if runID, found := strings.CutPrefix(line, "Run: "); found && runID != "" {
			return runID
		}
	}
	t.Fatalf("%s omitted its run ID:\n%s", label, output)
	return ""
}

func assertEvidenceGraphCloses(t *testing.T, label string, bundle report.Bundle, store *cas.Store, canary []byte, requireFinding bool) {
	t.Helper()
	reportRefs := make([]schema.ObjectRef, 0)
	findingCount := 0
	appendEvidenceRef := func(source string, ref schema.ObjectRef) {
		if ref.Kind != "Evidence" {
			t.Fatalf("%s %s referenced non-Evidence object: %#v", label, source, ref)
		}
		reportRefs = append(reportRefs, ref)
	}
	for _, result := range bundle.Cases {
		for _, ref := range result.EvidenceRefs {
			appendEvidenceRef("case", ref)
		}
		for _, assertion := range result.AssertionResults {
			for _, ref := range assertion.EvidenceRefs {
				appendEvidenceRef("assertion", ref)
			}
		}
		for _, finding := range result.Findings {
			findingCount++
			for _, ref := range finding.MinimalEvidenceRefs {
				appendEvidenceRef("finding minimal evidence", ref)
			}
			for _, ref := range finding.ReproRefs {
				if ref.Kind == "Evidence" {
					appendEvidenceRef("finding reproduction", ref)
				}
			}
		}
	}
	if len(reportRefs) == 0 {
		t.Fatalf("%s contained no Evidence references to verify", label)
	}
	if requireFinding && findingCount == 0 {
		t.Fatalf("%s did not exercise a persisted failure finding", label)
	}

	visitedEvidence := make(map[schema.ObjectRef]struct{}, len(reportRefs))
	visitedPayloads := make(map[schema.Digest]struct{})
	verifyPayload := func(source string, ref schema.ObjectRef, expected schema.Digest) {
		if ref.Kind != "Payload" || ref.InstanceID != "" || ref.ContentDigest != expected {
			t.Fatalf("%s %s has an invalid payload edge: %#v", label, source, ref)
		}
		if _, exists := visitedPayloads[ref.ContentDigest]; exists {
			return
		}
		payload, err := store.Get(context.Background(), ref.ContentDigest)
		if err != nil {
			t.Fatalf("%s %s payload ref is dangling (%#v): %v", label, source, ref, err)
		}
		if schema.NewDigest(payload) != expected {
			t.Fatalf("%s %s payload bytes do not match their digest", label, source)
		}
		if bytes.Contains(payload, canary) {
			t.Fatalf("%s credential canary reached a persisted payload", label)
		}
		visitedPayloads[ref.ContentDigest] = struct{}{}
	}

	var verifyEvidence func(schema.ObjectRef)
	verifyEvidence = func(ref schema.ObjectRef) {
		if ref.Kind != "Evidence" || ref.InstanceID != "" {
			t.Fatalf("%s has an invalid Evidence edge: %#v", label, ref)
		}
		if _, exists := visitedEvidence[ref]; exists {
			return
		}
		// Mark before descending so a valid relation cycle cannot recurse forever.
		visitedEvidence[ref] = struct{}{}
		evidence, err := store.GetEvidence(context.Background(), ref)
		if err != nil {
			t.Fatalf("%s Evidence ref is dangling (%#v): %v", label, ref, err)
		}
		if evidence.ObjectRef != ref {
			t.Fatalf("%s resolved Evidence identity changed: %#v != %#v", label, evidence.ObjectRef, ref)
		}
		if err := evidence.Validate(); err != nil {
			t.Fatalf("%s resolved Evidence does not validate: %v", label, err)
		}
		if evidence.RunID != bundle.RunID {
			t.Fatalf("%s Evidence %s belongs to run %s, want report run %s", label, ref.ContentDigest, evidence.RunID, bundle.RunID)
		}
		if evidence.PayloadRef == nil || evidence.PayloadDigest == nil {
			t.Fatalf("%s resolved Evidence has no payload edge: %#v", label, evidence)
		}
		verifyPayload("Evidence", *evidence.PayloadRef, *evidence.PayloadDigest)
		for _, relation := range evidence.Relations {
			switch relation.Target.Kind {
			case "Evidence":
				verifyEvidence(relation.Target)
			case "Payload":
				verifyPayload("Evidence relation "+relation.Relation, relation.Target, relation.Target.ContentDigest)
			default:
				t.Fatalf("%s Evidence relation %q has no persisted graph resolver for target %#v", label, relation.Relation, relation.Target)
			}
		}
	}
	for _, ref := range reportRefs {
		verifyEvidence(ref)
	}
	if len(visitedEvidence) == 0 || len(visitedPayloads) == 0 {
		t.Fatalf("%s did not close over any unique Evidence/payload objects", label)
	}
}
