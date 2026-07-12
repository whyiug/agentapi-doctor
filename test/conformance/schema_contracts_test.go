package conformance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/whyiug/agentapi-doctor/internal/planner"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/pkg/driverprotocol"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
	registryapi "github.com/whyiug/agentapi-doctor/registry/api"
	"gopkg.in/yaml.v3"
)

const (
	commonSchemaID       = "urn:agentapi-doctor:schema:common:envelope:v1alpha1"
	intentSchemaID       = "urn:agentapi-doctor:schema:intent-plan:v1alpha1"
	capabilitySchemaID   = "urn:agentapi-doctor:schema:capability-observation:v1alpha1"
	resolvedSchemaID     = "urn:agentapi-doctor:schema:resolved-run-plan:v1alpha1"
	evidenceSchemaID     = "urn:agentapi-doctor:schema:evidence:v1alpha2"
	resultSchemaID       = "urn:agentapi-doctor:schema:result:v1alpha2"
	reportSchemaID       = "urn:agentapi-doctor:schema:report-bundle:v1alpha2"
	driverFrameSchemaID  = "urn:agentapi-doctor:schema:driver-control-frame:v1alpha1"
	driverHeaderSchemaID = "urn:agentapi-doctor:schema:driver-data-frame-header:v1alpha1"
	observationSchemaID  = "urn:agentapi-doctor:schema:observation:v1"
)

func TestVersionedPublicSchemasAcceptGoContracts(t *testing.T) {
	compiled := compileRepositorySchemas(t)
	intent, resolved := planFixtures(t)
	evidence, assertion, finding, caseResult, profile := resultFixtures(t)
	bundle := reportFixture(t, caseResult)
	capability := capabilityFixture(t, intent)
	observation := observationFixture(t)

	contracts := []struct {
		name     string
		schemaID string
		value    any
	}{
		{name: "IntentPlan", schemaID: intentSchemaID, value: intent},
		{name: "CapabilityObservation", schemaID: capabilitySchemaID, value: capability},
		{name: "ResolvedRunPlan", schemaID: resolvedSchemaID, value: resolved},
		{name: "Evidence", schemaID: evidenceSchemaID, value: evidence},
		{name: "AssertionResult", schemaID: resultSchemaID, value: assertion},
		{name: "Finding", schemaID: resultSchemaID, value: finding},
		{name: "CaseResult", schemaID: resultSchemaID, value: caseResult},
		{name: "ProfileResult", schemaID: resultSchemaID, value: profile},
		{name: "report.Bundle", schemaID: reportSchemaID, value: bundle},
		{name: "Registry Observation", schemaID: observationSchemaID, value: observation},
	}
	for _, contract := range contracts {
		t.Run(contract.name, func(t *testing.T) {
			validateTypedContract(t, compiled[contract.schemaID], contract.value)
		})
	}

	control := driverprotocol.Message{
		JSONRPC: driverprotocol.JSONRPCVersion,
		ID:      json.RawMessage(`"reset-1"`),
		Method:  driverprotocol.MethodReset,
		Params:  json.RawMessage(`{}`),
	}
	encoded, err := driverprotocol.EncodeControlFrame(control)
	if err != nil {
		t.Fatal(err)
	}
	validateRawContract(t, compiled[driverFrameSchemaID], bytes.TrimSuffix(encoded, []byte{'\n'}))
	header := driverprotocol.DataFrameHeader{InvocationID: fixtureID('3'), AttemptID: fixtureID('4'), StreamID: "stream-1", Sequence: 0, Length: 12, Final: true}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	validateTypedContract(t, compiled[driverHeaderSchemaID], header)
}

func TestPublicSchemaAndGoValidationRejectInvalidContracts(t *testing.T) {
	compiled := compileRepositorySchemas(t)
	intent, _ := planFixtures(t)
	bundle := reportFixture(t, resultFixturesCase(t))

	intentRaw := marshalObject(t, intent)
	intentRaw["unexpected"] = true
	assertSchemaRejects(t, compiled[intentSchemaID], intentRaw)

	bundleRaw := marshalObject(t, bundle)
	bundleRaw["support_lock_digest"] = "sha256:ABC"
	assertSchemaRejects(t, compiled[reportSchemaID], bundleRaw)

	skippedWithEvidence := publicschema.CaseResult{
		ScenarioID: "skipped-with-evidence", PlanDisposition: publicschema.DispositionSkip,
		ReasonCode: publicschema.ReasonBudgetExhausted, EvidenceRefs: []publicschema.ObjectRef{bundle.IntentPlanRef},
		CandidateMember: true, ApplicableMember: true, AttemptAggregation: "none",
	}
	if err := skippedWithEvidence.Validate(); err == nil {
		t.Fatal("Go validator accepted evidence on a skipped CaseResult")
	}
	assertSchemaRejects(t, compiled[resultSchemaID], marshalObject(t, skippedWithEvidence))

	identityRaw := marshalObject(t, intent)
	identityRaw["object_ref"].(map[string]any)["kind"] = "Evidence"
	assertSchemaRejects(t, compiled[intentSchemaID], identityRaw)

	mismatched := intent
	mismatched.IntentPlanID = fixtureID('9')
	if err := mismatched.Validate(); err == nil {
		t.Fatal("Go validator accepted an IntentPlan whose identity differs from its envelope")
	}

	observation := observationFixture(t)
	observationRaw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	observationObject := marshalObject(t, json.RawMessage(observationRaw))
	observationObject["observation_id"] = string(fixtureDigest('f'))
	mutatedObservation, err := json.Marshal(observationObject)
	if err != nil {
		t.Fatal(err)
	}
	var decoded registryapi.Observation
	if err := json.Unmarshal(mutatedObservation, &decoded); err == nil {
		t.Fatal("Registry Go contract accepted an observation_id projection mismatch")
	}

	unknownParams := []byte(`{"jsonrpc":"2.0","id":1,"method":"driver.reset","params":{"unknown":true}}`)
	assertRawSchemaRejects(t, compiled[driverFrameSchemaID], unknownParams)
	if _, err := driverprotocol.DecodeControlFrame(unknownParams); err == nil {
		t.Fatal("Driver codec accepted an unknown method parameter")
	}
}

func TestNewSchemasCloseObjectsExceptDocumentedMaps(t *testing.T) {
	root := repositoryRoot(t)
	paths := []string{
		"schemas/plan/intent-plan.schema.json",
		"schemas/plan/capability-observation.schema.json",
		"schemas/plan/resolved-run-plan.schema.json",
		"schemas/evidence/evidence.schema.json",
		"schemas/result/result.schema.json",
		"schemas/report/report-bundle.schema.json",
		"schemas/driver/control-frame.schema.json",
		"schemas/driver/data-frame-header.schema.json",
		"schemas/registry/observation.schema.json",
	}
	allowedOpen := map[string]bool{
		"$.$defs.canonicalSection":                            true,
		"$.properties.extensions":                             true,
		"$.$defs.extensions":                                  true,
		"$.$defs.profileResult.properties.extensions":         true,
		"$.$defs.profileResult.properties.dimension_outcomes": true,
		"$.$defs.profileResult.properties.sample_metadata":    true,
		"$.properties.dimension_outcomes":                     true,
	}
	for _, relative := range paths {
		t.Run(relative, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			checkClosedObjects(t, value, "$", allowedOpen)
		})
	}
}

func TestRegistryOpenAPITracksImplementedRoutesAndUnavailableHostedVerifier(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "schemas", "registry", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != "3.1.0" || document["jsonSchemaDialect"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected OpenAPI dialect: %#v", document)
	}
	if _, inventedServer := document["servers"]; inventedServer {
		t.Fatal("provisional OpenAPI must not invent a deployed server")
	}
	info := document["info"].(map[string]any)
	if info["x-hosted-verifier-available"] != false || info["x-ownership-verifier-available"] != false {
		t.Fatal("OpenAPI falsely claims a hosted verifier capability")
	}
	paths := document["paths"].(map[string]any)
	want := []string{
		"/v1/badges/{owner}/{project}/{profile}.svg", "/v1/disputes", "/v1/disputes/{dispute_id}",
		"/v1/observations", "/v1/observations/{digest}", "/v1/observations:commit", "/v1/observations:prepare",
		"/v1/ownership/challenges", "/v1/packs/{name}/{version}", "/v1/profiles/{name}/{version}",
		"/v1/subjects/{owner}/{project}", "/v1/uploads/{session_id}",
	}
	got := make([]string, 0, len(paths))
	for route := range paths {
		got = append(got, route)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("OpenAPI routes drifted\nwant: %v\n got: %v", want, got)
	}
	commit := paths["/v1/observations:commit"].(map[string]any)["post"].(map[string]any)
	responses := commit["responses"].(map[string]any)
	if _, documented := responses["501"]; !documented {
		t.Fatal("commit does not document hosted_verifier_unavailable")
	}
}

func compileRepositorySchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	root := filepath.Join(repositoryRoot(t), "schemas")
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	ids := []string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var header struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return err
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		if err := compiler.AddResource(header.ID, document); err != nil {
			return err
		}
		ids = append(ids, header.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled := make(map[string]*jsonschema.Schema, len(ids))
	for _, id := range ids {
		value, err := compiler.Compile(id)
		if err != nil {
			t.Fatalf("compile %s: %v", id, err)
		}
		compiled[id] = value
	}
	for _, id := range []string{commonSchemaID, intentSchemaID, capabilitySchemaID, resolvedSchemaID, evidenceSchemaID, resultSchemaID, reportSchemaID, driverFrameSchemaID, driverHeaderSchemaID, observationSchemaID} {
		if compiled[id] == nil {
			t.Fatalf("required schema %s is not indexed", id)
		}
	}
	return compiled
}

func validateTypedContract(t *testing.T, compiled *jsonschema.Schema, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	validateRawContract(t, compiled, raw)
}

func validateRawContract(t *testing.T, compiled *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(value); err != nil {
		t.Fatalf("schema rejected valid contract %s: %v", raw, err)
	}
}

func assertRawSchemaRejects(t *testing.T, compiled *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return
	}
	if err := compiled.Validate(value); err == nil {
		t.Fatalf("schema accepted invalid contract: %s", raw)
	}
}

func assertSchemaRejects(t *testing.T, compiled *jsonschema.Schema, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	assertRawSchemaRejects(t, compiled, raw)
}

func marshalObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func planFixtures(t *testing.T) (publicschema.IntentPlan, publicschema.ResolvedRunPlan) {
	t.Helper()
	request := planner.IntentRequest{
		ID: fixtureID('1'), CreatedAt: publicschema.NewUTCTime(time.Unix(0, 0)), Producer: fixtureProducer(),
		ConfigDigest:          fixtureDigest('1'),
		Target:                publicschema.TargetIntent{LogicalRef: "local", ProtocolFamily: "openai-responses", IdentityExpectation: "version-pinned", AllowedOrigin: "http://127.0.0.1:8000"},
		Selectors:             []publicschema.ArtifactSelector{{Kind: "ProtocolPack", Name: "openai-responses", Constraint: "2026.07.0", Allowed: []publicschema.Digest{fixtureDigest('2')}}},
		SupportManifestDigest: fixtureDigest('3'),
		Probe:                 publicschema.ProbePolicy{Operations: []string{"models.list"}, Budget: hardBudget(), Network: publicschema.NetworkTargetOnly},
		Scenarios:             []planner.ScenarioCandidate{{ID: "scenario.one", Capabilities: []string{"streaming"}, Driver: fixtureDriver()}},
		Budget:                budgetPolicy(),
		Evidence:              publicschema.EvidencePolicy{Capture: publicschema.CaptureStandard, Redaction: "strict", Publication: "local"},
		Safety:                publicschema.SafetyPolicy{Network: publicschema.NetworkTargetOnly, Redirects: "same-origin", ToolSideEffects: publicschema.SideEffectsNone, DriverPermissions: []string{}},
		Author:                "contract-test", ApprovalRequirements: []string{"local-only"},
	}
	intent, err := planner.BuildIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := planner.Resolve(intent, planner.ResolutionRequest{
		ID: fixtureID('2'), CreatedAt: publicschema.NewUTCTime(time.Unix(1, 0)), Producer: fixtureProducer(),
		Resolver:          publicschema.ArtifactPin{Kind: "Resolver", Name: "core", Version: "0.1.0", Digest: fixtureDigest('4')},
		SupportLockDigest: fixtureDigest('5'), Artifacts: []publicschema.ArtifactPin{fixtureDriver()},
		Target:    publicschema.TargetResolution{IdentityLevel: "version-pinned", ObservedFingerprint: fixtureDigest('6'), Version: "0.1.0"},
		Scenarios: []planner.ScenarioCandidate{{ID: "scenario.one", Capabilities: []string{"streaming"}, Driver: fixtureDriver()}},
		Runtime:   publicschema.RuntimePolicy{Concurrency: 1, Retries: 0, Timeout: publicschema.NewDuration(time.Minute), Capture: publicschema.CaptureStandard, Sandbox: "process", Network: publicschema.NetworkTargetOnly},
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent, resolved
}

func capabilityFixture(t *testing.T, intent publicschema.IntentPlan) publicschema.CapabilityObservation {
	t.Helper()
	id := fixtureID('5')
	projection := struct {
		SchemaVersion string                  `json:"schema_version"`
		Kind          string                  `json:"kind"`
		ID            publicschema.InstanceID `json:"capability_observation_id"`
	}{"urn:agentapi-doctor:capability-observation:v1alpha1", "CapabilityObservation", id}
	meta, err := publicschema.SealMeta(projection.SchemaVersion, projection.Kind, id, fixtureProducer(), publicschema.NewUTCTime(time.Unix(2, 0)), projection)
	if err != nil {
		t.Fatal(err)
	}
	return publicschema.CapabilityObservation{
		EnvelopeMeta: meta, ObservationID: id, IntentPlanRef: intent.ObjectRef,
		ProbePolicyHash: fixtureDigest('7'),
		Facts:           []publicschema.CapabilityFact{{Capability: "streaming", Status: publicschema.CapabilitySupported, Evidence: []publicschema.ObjectRef{{Kind: "Evidence", ContentDigest: fixtureDigest('8')}}}},
		ConsumedBudget:  hardBudget(),
	}
}

func resultFixtures(t *testing.T) (publicschema.Evidence, publicschema.AssertionResult, publicschema.Finding, publicschema.CaseResult, publicschema.ProfileResult) {
	t.Helper()
	evidenceID := fixtureID('6')
	meta, err := publicschema.SealMeta("urn:agentapi-doctor:evidence:v1alpha2", "Evidence", evidenceID, fixtureProducer(), publicschema.NewUTCTime(time.Unix(3, 0)), struct {
		Value string `json:"value"`
	}{"synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	evidence := publicschema.Evidence{
		EnvelopeMeta: meta, EvidenceID: meta.ContentDigest, RunID: fixtureID('7'), InvocationID: fixtureID('8'), AttemptID: fixtureID('9'),
		Sequence: 1, CaptureLayer: publicschema.LayerSanitizedPersisted, InstrumentationMode: publicschema.InstrumentationFixture,
		Direction: publicschema.DirectionTargetToCore, EvidenceKind: "synthetic.event", MonotonicOffsetNS: 1,
		UnavailableReason: "source_bytes_not_retained", Redactions: []publicschema.RedactionRecord{},
	}
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
	assertion := publicschema.AssertionResult{
		AssertionResultID: fixtureID('a'), AssertionID: "assertion.one", RequirementID: "REQ-1", Role: publicschema.AssertionNormative,
		Oracle:  publicschema.ArtifactPin{Kind: "Oracle", Name: "schema", Version: "0.1.0", Digest: fixtureDigest('9')},
		Verdict: publicschema.VerdictPass, EvidenceRefs: []publicschema.ObjectRef{evidence.ObjectRef}, Deterministic: true, EvaluatorDigest: fixtureDigest('a'),
	}
	if err := assertion.Validate(); err != nil {
		t.Fatal(err)
	}
	finding := publicschema.Finding{
		FindingID: fixtureID('b'), AssertionResultID: assertion.AssertionResultID, FaultDomain: "PROTOCOL_SERIALIZER", FaultFamily: publicschema.FaultProtocol,
		Category: "fixture", Severity: "medium", Confidence: 0.9, CalibrationVersion: "rules-v1",
		MinimalEvidenceRefs: []publicschema.ObjectRef{evidence.ObjectRef}, RemediationHint: "preserve the boundary",
		FingerprintVersion: "failure-fingerprint-v1", Fingerprint: fixtureDigest('b'),
	}
	verdict := publicschema.VerdictPass
	caseResult := publicschema.CaseResult{
		ScenarioID: "scenario.one", PlanDisposition: publicschema.DispositionExecute, AttemptIDs: []publicschema.InstanceID{fixtureID('c')},
		ExecutionStatus: publicschema.ExecutionCompleted, Verdict: &verdict, AssertionResults: []publicschema.AssertionResult{assertion}, Findings: []publicschema.Finding{},
		CandidateMember: true, ApplicableMember: true, ExecutedMember: true, AttemptAggregation: "last_completed",
	}
	if err := caseResult.Validate(); err != nil {
		t.Fatal(err)
	}
	profileID := fixtureID('d')
	profileMeta, err := publicschema.SealMeta("urn:agentapi-doctor:profile-result:v1alpha1", "ProfileResult", profileID, fixtureProducer(), publicschema.NewUTCTime(time.Unix(4, 0)), struct {
		Value string `json:"value"`
	}{"profile"})
	if err != nil {
		t.Fatal(err)
	}
	profile := publicschema.ProfileResult{
		EnvelopeMeta: profileMeta, ProfileResultID: profileID,
		Profile:           publicschema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "fixture.profile", Version: "0.1.0", Digest: fixtureDigest('c')},
		SupportLockDigest: fixtureDigest('d'), Denominators: denominator(), Outcome: publicschema.ProfileCompatible,
		Dimensions: map[string]publicschema.DimensionOutcome{"protocol": publicschema.DimensionPass}, Cases: []publicschema.CaseResult{caseResult},
		HardGates: []publicschema.AssertionResult{assertion},
	}
	return evidence, assertion, finding, caseResult, profile
}

func resultFixturesCase(t *testing.T) publicschema.CaseResult {
	t.Helper()
	_, _, _, value, _ := resultFixtures(t)
	return value
}

func reportFixture(t *testing.T, caseResult publicschema.CaseResult) report.Bundle {
	t.Helper()
	bundle := report.Bundle{
		SchemaVersion: report.SchemaVersion, RunID: fixtureID('e'),
		IntentPlanRef:   publicschema.ObjectRef{Kind: "IntentPlan", InstanceID: fixtureID('1'), ContentDigest: fixtureDigest('e')},
		ResolvedPlanRef: publicschema.ObjectRef{Kind: "ResolvedRunPlan", InstanceID: fixtureID('2'), ContentDigest: fixtureDigest('f')},
		Profile:         publicschema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "fixture.profile", Version: "0.1.0", Digest: fixtureDigest('c')},
		Artifacts:       []publicschema.ArtifactPin{fixtureDriver()}, SupportLock: fixtureDigest('d'), Denominators: denominator(),
		Outcome: publicschema.ProfileCompatible, Dimensions: map[string]publicschema.DimensionOutcome{"protocol": publicschema.DimensionPass},
		Cases: []publicschema.CaseResult{caseResult}, Conditions: []report.Condition{}, PrimaryExitCode: 0,
	}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func observationFixture(t *testing.T) registryapi.Observation {
	t.Helper()
	object := func(raw string) registryapi.CanonicalObject {
		value, err := registryapi.ParseCanonicalObject([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	observation, err := registryapi.NewObservation(registryapi.ObservationProjection{
		SchemaVersion: registryapi.ObservationSchemaV1,
		Subject:       object(`{"project":"owner/project","version":"0.1.0"}`), Test: object(`{"pack":"fixture","profile":"fixture.profile"}`),
		Environment: object(`{"arch":"amd64","os":"linux"}`), Result: object(`{"profile_outcome":"compatible"}`),
		ManifestDigest: fixtureDigest('1'),
	}, fixtureDigest('2'), []registryapi.AttestationReference{}, registryapi.RegistryDerived{})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func fixtureDigest(character byte) publicschema.Digest {
	return publicschema.Digest("sha256:" + strings.Repeat(string(character), 64))
}

func fixtureID(last byte) publicschema.InstanceID {
	return publicschema.InstanceID("00000000-0000-7000-8000-00000000000" + string(last))
}

func fixtureProducer() publicschema.Producer {
	return publicschema.Producer{Name: "doctor", Version: "0.1.0", ArtifactDigest: fixtureDigest('a')}
}

func fixtureDriver() publicschema.ArtifactPin {
	return publicschema.ArtifactPin{Kind: "Driver", Name: "raw-http", Version: "0.1.0", Digest: fixtureDigest('b')}
}

func hardBudget() publicschema.HardBudget {
	return publicschema.HardBudget{MaxRequests: 1, MaxRequestBytes: 1024, MaxResponseBytes: 2048, MaxArtifactBytes: 4096, MaxProcesses: 1, MaxDuration: publicschema.NewDuration(time.Minute)}
}

func budgetPolicy() publicschema.BudgetPolicy {
	return publicschema.BudgetPolicy{Hard: hardBudget(), Reservation: publicschema.TokenBudget{MaxInputTokens: 10, MaxOutputTokens: 10}, Cleanup: hardBudget()}
}

func denominator() publicschema.DenominatorSummary {
	return publicschema.DenominatorSummary{CandidateDigest: fixtureDigest('3'), CandidateCount: 1, ApplicableDigest: fixtureDigest('4'), ApplicableCount: 1, ExecutedDigest: fixtureDigest('5'), ExecutedCount: 1}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate schema contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func checkClosedObjects(t *testing.T, value any, path string, allowedOpen map[string]bool) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if objectType, ok := typed["type"].(string); ok && objectType == "object" {
			additional, present := typed["additionalProperties"]
			if !present {
				t.Errorf("%s: object schema has no additionalProperties policy", path)
			} else if open, ok := additional.(bool); ok && open && !allowedOpen[path] {
				t.Errorf("%s: object schema is unexpectedly open", path)
			}
		}
		for key, child := range typed {
			checkClosedObjects(t, child, path+"."+key, allowedOpen)
		}
	case []any:
		for _, child := range typed {
			checkClosedObjects(t, child, path+"[]", allowedOpen)
		}
	}
}
