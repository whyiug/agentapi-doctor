package report

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func baselineWith(states map[string]CaseState) Baseline {
	if states == nil {
		states = map[string]CaseState{}
	}
	return Baseline{SchemaVersion: BaselineSchemaVersion, Name: "main", ProfileDigest: testDigest("profile"), PackDigest: testDigest("pack"), SupportLockDigest: testDigest("support"), DenominatorDigest: testDigest("denominator"), Cases: states}
}

func baselineDocument(t *testing.T, cases map[string]any) []byte {
	return baselineDocumentWithVersion(t, BaselineSchemaVersion, cases)
}

func baselineDocumentWithVersion(t *testing.T, version any, cases map[string]any) []byte {
	t.Helper()
	raw, err := schema.CanonicalMarshal(map[string]any{
		"schema_version":      version,
		"name":                "main",
		"profile_digest":      testDigest("profile"),
		"pack_digest":         testDigest("pack"),
		"support_lock_digest": testDigest("support"),
		"denominator_digest":  testDigest("denominator"),
		"cases":               cases,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBaselineJSONWritesVersionAndReadsLegacyRCBaseline(t *testing.T) {
	current := baselineWith(nil)
	encoded, err := BaselineJSON(current)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBaseline(encoded)
	if err != nil || decoded.SchemaVersion != BaselineSchemaVersion {
		t.Fatalf("current baseline round trip: decoded=%#v err=%v", decoded, err)
	}

	legacy, err := os.ReadFile("testdata/baseline-v0.1.0-rc3.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeBaseline(bytes.TrimSuffix(legacy, []byte("\n")))
	if err != nil {
		t.Fatalf("read legacy rc baseline: %v", err)
	}
	if decoded.SchemaVersion != BaselineSchemaVersion || decoded.Name != "main" {
		t.Fatalf("legacy baseline was not migrated in memory: %#v", decoded)
	}
}

func TestDecodeBaselineRejectsUnknownOrFutureSchema(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schema_version":"urn:agentapi-doctor:baseline:v2","name":"main","profile_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","pack_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","support_lock_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","denominator_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","cases":{}}`),
		[]byte(`{"schema_version":"urn:agentapi-doctor:baseline:v1","name":"main","profile_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","pack_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","support_lock_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","denominator_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","cases":{},"unexpected":true}`),
	} {
		if _, err := DecodeBaseline(raw); err == nil {
			t.Fatalf("accepted baseline mutant: %s", raw)
		}
	}
	for _, version := range []any{"", nil} {
		raw := baselineDocumentWithVersion(t, version, map[string]any{})
		if _, err := DecodeBaseline(raw); err == nil {
			t.Fatalf("accepted explicit empty baseline schema: %s", raw)
		}
	}
}

func TestBaselineValidationRejectsSchemaEnumMutants(t *testing.T) {
	bogusVerdict := schema.Verdict("bogus")
	mutants := []Baseline{
		baselineWith(map[string]CaseState{"   ": {Disposition: schema.DispositionSkip}}),
		baselineWith(map[string]CaseState{"case.one": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionStatus("bogus")}}),
		baselineWith(map[string]CaseState{"case.one": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &bogusVerdict}}),
	}
	for _, mutant := range mutants {
		if err := mutant.Validate(); err == nil {
			t.Fatalf("accepted baseline mutant: %#v", mutant)
		}
	}
}

func TestDecodeBaselineRejectsExplicitEmptyOrNullOptionalEnums(t *testing.T) {
	mutants := []map[string]any{
		{"plan_disposition": "execute", "execution_status": ""},
		{"plan_disposition": "execute", "execution_status": nil},
		{"plan_disposition": "execute", "verdict": nil},
	}
	for _, state := range mutants {
		raw := baselineDocument(t, map[string]any{"case.one": state})
		if _, err := DecodeBaseline(raw); err == nil {
			t.Fatalf("accepted baseline mutant: %s", raw)
		}
	}
}

func TestCompareClassifiesRegressionAndFixed(t *testing.T) {
	pass, fail := schema.VerdictPass, schema.VerdictFail
	before := baselineWith(map[string]CaseState{"regress": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &pass}, "fixed": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &fail}})
	after := baselineWith(map[string]CaseState{"regress": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &fail}, "fixed": {Disposition: schema.DispositionExecute, Execution: schema.ExecutionCompleted, Verdict: &pass}})
	diffs, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, diff := range diffs {
		got[diff.ScenarioID] = diff.Change
	}
	if got["regress"] != Regression || got["fixed"] != Fixed {
		t.Fatalf("unexpected diffs: %#v", diffs)
	}
}

func TestCompareRejectsChangedDenominator(t *testing.T) {
	before, after := baselineWith(nil), baselineWith(nil)
	after.DenominatorDigest = testDigest("other")
	if _, err := Compare(before, after); !errors.Is(err, ErrIncomparable) {
		t.Fatalf("expected ErrIncomparable, got %v", err)
	}
}
