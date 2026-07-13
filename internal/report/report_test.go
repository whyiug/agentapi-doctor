package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/redaction"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const testID schema.InstanceID = "018f22e2-79b0-7cc3-98c4-dc0c0c07398f"

func testDigest(label string) schema.Digest { return schema.NewDigest([]byte(label)) }

func verdict(value schema.Verdict) *schema.Verdict { return &value }

func validBundle() Bundle {
	digest := testDigest("object")
	passID := testID
	return Bundle{
		SchemaVersion:   SchemaVersion,
		RunID:           testID,
		IntentPlanRef:   schema.ObjectRef{Kind: "IntentPlan", InstanceID: testID, ContentDigest: digest},
		ResolvedPlanRef: schema.ObjectRef{Kind: "ResolvedRunPlan", InstanceID: testID, ContentDigest: digest},
		Profile:         schema.ArtifactPin{Kind: "ConsumerCompatibilityProfile", Name: "sdk.test", Version: "1.0.0", Digest: testDigest("profile")},
		Artifacts:       []schema.ArtifactPin{{Kind: "ProtocolPack", Name: "test-pack", Version: "2026.07.0", Digest: testDigest("pack")}},
		SupportLock:     testDigest("support"),
		Denominators:    schema.DenominatorSummary{CandidateDigest: testDigest("candidate"), CandidateCount: 1, ApplicableDigest: testDigest("applicable"), ApplicableCount: 1, ExecutedDigest: testDigest("executed"), ExecutedCount: 1},
		Outcome:         schema.ProfileCompatible,
		Dimensions:      map[string]schema.DimensionOutcome{"protocol": schema.DimensionPass},
		Cases:           []schema.CaseResult{{ScenarioID: "safe.case", PlanDisposition: schema.DispositionExecute, AttemptIDs: []schema.InstanceID{passID}, ExecutionStatus: schema.ExecutionCompleted, Verdict: verdict(schema.VerdictPass), CandidateMember: true, ApplicableMember: true, ExecutedMember: true, AttemptAggregation: "all"}},
		Conditions:      []Condition{}, PrimaryExitCode: 0,
	}
}

func TestEveryRendererAcceptsOneTruthModel(t *testing.T) {
	bundle := validBundle()
	renderers := map[string]func(Bundle) ([]byte, error){"json": JSON, "terminal": Terminal, "junit": JUnit, "sarif": SARIF, "markdown": Markdown, "html": HTML}
	for name, renderer := range renderers {
		t.Run(name, func(t *testing.T) {
			data, err := renderer(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				t.Fatal("empty output")
			}
		})
	}
}

func TestTerminalExplainsInconclusiveCase(t *testing.T) {
	bundle := validBundle()
	inconclusive := schema.VerdictInconclusive
	bundle.Outcome = schema.ProfileInconclusive
	bundle.Dimensions["protocol"] = schema.DimensionInconclusive
	bundle.Cases[0].Verdict = &inconclusive
	bundle.Cases[0].ReasonCode = schema.ReasonUnsupportedCapability
	bundle.PrimaryExitCode = 4
	data, err := Terminal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("INCONCLUSIVE")) || !bytes.Contains(data, []byte(schema.ReasonUnsupportedCapability)) {
		t.Fatalf("terminal output hid the inconclusive reason:\n%s", data)
	}
}

func TestHumanRenderersUseCheckResultsInsteadOfCompatibilityClaims(t *testing.T) {
	tests := []struct {
		outcome schema.ProfileOutcome
		want    string
	}{
		{outcome: schema.ProfileCompatible, want: "checks passed"},
		{outcome: schema.ProfileDegraded, want: "checks passed with warnings"},
		{outcome: schema.ProfileIncompatible, want: "checks failed"},
		{outcome: schema.ProfileInconclusive, want: "checks inconclusive"},
	}
	renderers := map[string]func(Bundle) ([]byte, error){"terminal": Terminal, "markdown": Markdown, "html": HTML}
	for _, test := range tests {
		for name, renderer := range renderers {
			t.Run(name+"/"+string(test.outcome), func(t *testing.T) {
				bundle := validBundle()
				bundle.Outcome = test.outcome
				data, err := renderer(bundle)
				if err != nil {
					t.Fatal(err)
				}
				text := strings.ToLower(string(data))
				if !strings.Contains(text, test.want) {
					t.Fatalf("%s output omitted %q:\n%s", name, test.want, data)
				}
				if strings.Contains(text, "compatible") || strings.Contains(text, "incompatible") {
					t.Fatalf("%s output retained a compatibility claim:\n%s", name, data)
				}
			})
		}
	}
}

func TestHumanRenderersProminentlyAndSafelyRenderEveryCondition(t *testing.T) {
	bundle := validBundle()
	bundle.Conditions = []Condition{
		{Code: "provider_usage_unknown", Message: "Usage unavailable <script>alert(1)</script> & verify\nforged\x1b[31m"},
		{Code: "run_budget_exhausted", Message: "The bounded run exhausted its budget."},
	}
	renderers := map[string]func(Bundle) ([]byte, error){"terminal": Terminal, "markdown": Markdown, "html": HTML}
	for name, renderer := range renderers {
		t.Run(name, func(t *testing.T) {
			data, err := renderer(bundle)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			normalized := strings.ReplaceAll(text, `\_`, "_")
			for _, required := range []string{"Important conditions", "provider_usage_unknown", "run_budget_exhausted", "Usage unavailable", "exhausted its budget"} {
				if !strings.Contains(normalized, required) {
					t.Fatalf("%s output omitted condition content %q:\n%s", name, required, text)
				}
			}
			if strings.Contains(text, "\x1b") || strings.Contains(text, "\nforged") {
				t.Fatalf("%s output retained condition control text:\n%s", name, text)
			}
			if name != "terminal" && strings.Contains(strings.ToLower(text), "<script>") {
				t.Fatalf("%s output retained active condition markup:\n%s", name, text)
			}
			if name == "html" && !strings.Contains(text, "&lt;script&gt;") {
				t.Fatalf("HTML did not safely escape condition markup:\n%s", text)
			}
		})
	}
}

func TestHumanRenderersExplainNonPassingCasesAndKeepPassCompact(t *testing.T) {
	bundle := diagnosticBundle()
	renderers := map[string]func(Bundle) ([]byte, error){
		"terminal": Terminal,
		"markdown": Markdown,
		"html":     HTML,
	}
	for name, renderer := range renderers {
		t.Run(name, func(t *testing.T) {
			data, err := renderer(bundle)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			normalized := strings.ReplaceAll(text, `\_`, "_")
			for _, required := range []string{
				"Terminal Exactly Once",
				"missing_terminal_event forged",
				"stream_state_machine forged",
				"exactly one terminal event forged",
				"zero",
				"Emit one terminal event; preserve",
				"verify",
				"WARN",
				"INCONCLUSIVE",
				"no fault domain was attributed",
			} {
				if !strings.Contains(normalized, required) {
					t.Fatalf("%s report omitted %q:\n%s", name, required, text)
				}
			}
			if strings.Contains(text, "\x1b") || strings.Contains(text, "\u202e") || strings.Contains(text, "\nforged") {
				t.Fatalf("%s report retained unsafe control text:\n%s", name, text)
			}
			if name != "terminal" && strings.Contains(text, "<script>") {
				t.Fatalf("%s report retained active markup:\n%s", name, text)
			}
		})
	}

	terminal, err := Terminal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(terminal), "PASS           safe.case") {
		t.Fatalf("PASS row stopped being compact:\n%s", terminal)
	}
	if !strings.Contains(string(terminal), "doctor report markdown "+string(bundle.RunID)+" --output doctor-report.md") {
		t.Fatalf("terminal report omitted the export next step:\n%s", terminal)
	}
}

func diagnosticBundle() Bundle {
	bundle := validBundle()
	bundle.Outcome = schema.ProfileIncompatible
	bundle.Dimensions["protocol"] = schema.DimensionFail
	bundle.PrimaryExitCode = 1
	bundle.Denominators.CandidateCount = 4
	bundle.Denominators.ApplicableCount = 4
	bundle.Denominators.ExecutedCount = 4

	reference := schema.ObjectRef{Kind: "Evidence", InstanceID: testID, ContentDigest: testDigest("evidence")}
	oracle := schema.ArtifactPin{Kind: "Oracle", Name: "fixture-oracle", Version: "1.0.0", Digest: testDigest("oracle")}
	assertion := func(id string, value schema.Verdict, reason schema.ReasonCode, expected, observed any) schema.AssertionResult {
		return schema.AssertionResult{
			AssertionResultID: testID,
			AssertionID:       id,
			Role:              schema.AssertionBehavioral,
			Oracle:            oracle,
			Verdict:           value,
			ReasonCode:        reason,
			Expected:          expected,
			Observed:          observed,
			EvidenceRefs:      []schema.ObjectRef{reference},
			Deterministic:     true,
			EvaluatorDigest:   testDigest("evaluator"),
		}
	}
	caseResult := func(id string, value schema.Verdict, reason schema.ReasonCode, result schema.AssertionResult) schema.CaseResult {
		return schema.CaseResult{
			ScenarioID: id, PlanDisposition: schema.DispositionExecute,
			AttemptIDs: []schema.InstanceID{testID}, ExecutionStatus: schema.ExecutionCompleted,
			Verdict: verdict(value), ReasonCode: reason, AssertionResults: []schema.AssertionResult{result},
			CandidateMember: true, ApplicableMember: true, ExecutedMember: true, AttemptAggregation: "all",
		}
	}

	failedAssertion := assertion(
		"terminal-event", schema.VerdictFail, "",
		"exactly one terminal event\nforged", "zero\x1b[31m\u202eexe.txt",
	)
	failed := caseResult("openai-responses-http-030-terminal-exactly-once", schema.VerdictFail, "", failedAssertion)
	failed.Findings = []schema.Finding{{
		FindingID: testID, AssertionResultID: testID,
		Category: "missing_terminal_event\nforged", FaultDomain: "stream_state_machine\x1b[1m forged", FaultFamily: schema.FaultProtocol,
		Severity: "medium", Confidence: 0.9, CalibrationVersion: "fixture-v1",
		MinimalEvidenceRefs: []schema.ObjectRef{reference},
		RemediationHint:     "Emit one terminal event; preserve & verify <script>\nforged",
		FingerprintVersion:  "fixture-v1", Fingerprint: testDigest("finding"),
	}}
	warned := caseResult(
		"openai-responses-http-039-terminal-status", schema.VerdictWarn, schema.ReasonFlakyDetected,
		assertion("terminal-status", schema.VerdictWarn, schema.ReasonFlakyDetected, "stable terminal status", "varied across attempts"),
	)
	inconclusive := caseResult(
		"openai-responses-http-014-required-response-envelope", schema.VerdictInconclusive, schema.ReasonUnsupportedCapability,
		assertion("response-envelope", schema.VerdictInconclusive, schema.ReasonUnsupportedCapability, "documented response envelope", nil),
	)
	bundle.Cases = append(bundle.Cases, failed, warned, inconclusive)
	return bundle
}

func TestHTMLAndJUnitEscapeProviderControlledText(t *testing.T) {
	bundle := validBundle()
	bundle.Cases[0].ScenarioID = `evil<script>alert(1)</script>&"`
	html, err := HTML(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(html, []byte("<script>alert")) || !bytes.Contains(html, []byte("&lt;script&gt;")) {
		t.Fatalf("unsafe HTML: %s", html)
	}
	xmlData, err := JUnit(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(xmlData, []byte("<script>alert")) || !bytes.Contains(xmlData, []byte("&lt;script&gt;")) {
		t.Fatalf("unsafe XML: %s", xmlData)
	}
}

func TestHTMLHasStrictOfflineCSPAndNoScript(t *testing.T) {
	data, err := HTML(validBundle())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "default-src &#39;none&#39;") && !strings.Contains(text, "default-src 'none'") {
		t.Fatalf("missing CSP: %s", text)
	}
	if strings.Contains(strings.ToLower(text), "<script") {
		t.Fatal("offline report must not contain scripts")
	}
}

func TestJSONIsCanonical(t *testing.T) {
	data, err := JSON(validBundle())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := schema.CanonicalizeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, canonical) {
		t.Fatalf("not canonical\n%s\n%s", data, canonical)
	}
}

func TestDecodeRetainsReadOnlyLegacyBundleSupport(t *testing.T) {
	bundle := validBundle()
	bundle.SchemaVersion = legacySchemaVersion
	raw, err := schema.CanonicalMarshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != legacySchemaVersion || decoded.RunID != bundle.RunID {
		t.Fatalf("legacy bundle changed during decode: %#v", decoded)
	}
}

func TestHARAcceptsOnlySanitizedPayloadType(t *testing.T) {
	redactor, err := redaction.New(nil, [][]byte{[]byte("super-secret-canary")})
	if err != nil {
		t.Fatal(err)
	}
	request, err := redactor.SanitizeJSON([]byte(`{"authorization":"super-secret-canary","message":"ok"}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := redactor.SanitizeJSON([]byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := NewHTTPExchange(time.Unix(1, 0), 50*time.Millisecond, "POST", 200, request, response)
	if err != nil {
		t.Fatal(err)
	}
	data, err := HAR([]HTTPExchange{exchange})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("super-secret-canary")) || bytes.Contains(data, []byte("https://")) {
		t.Fatalf("sensitive HAR: %s", data)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestDenominatorInvariant(t *testing.T) {
	bundle := validBundle()
	bundle.Denominators.ExecutedCount = 2
	if _, err := JSON(bundle); err == nil {
		t.Fatal("expected denominator validation error")
	}
}
