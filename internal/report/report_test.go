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
