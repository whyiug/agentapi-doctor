// Package attribution maps bounded differential evidence to versioned fault
// domains. It deliberately returns UNKNOWN when the evidence does not isolate
// a layer; it never uses majority behavior as protocol truth.
package attribution

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	TaxonomyVersion    = "fault-taxonomy-v1"
	CalibrationVersion = "rules-v1"
)

type Domain string

const (
	DomainTransport          Domain = "TRANSPORT"
	DomainAuth               Domain = "AUTH"
	DomainRequestMapping     Domain = "REQUEST_MAPPING"
	DomainProtocolSerializer Domain = "PROTOCOL_SERIALIZER"
	DomainStreamStateMachine Domain = "STREAM_STATE_MACHINE"
	DomainToolParser         Domain = "TOOL_PARSER"
	DomainReasoningParser    Domain = "REASONING_PARSER"
	DomainChatTemplate       Domain = "CHAT_TEMPLATE"
	DomainModelBehavior      Domain = "MODEL_BEHAVIOR"
	DomainSDKParser          Domain = "SDK_PARSER"
	DomainAgentOrchestration Domain = "AGENT_ORCHESTRATION"
	DomainGatewayTranslation Domain = "GATEWAY_TRANSLATION"
	DomainRateLimitTransient Domain = "RATE_LIMIT_OR_TRANSIENT"
	DomainHarness            Domain = "HARNESS"
	DomainSpecAmbiguity      Domain = "SPEC_AMBIGUITY"
	DomainUnknown            Domain = "UNKNOWN_FAULT_DOMAIN"
)

var families = map[Domain]schema.FaultFamily{
	DomainTransport: schema.FaultTransport, DomainAuth: schema.FaultTransport, DomainRateLimitTransient: schema.FaultTransport,
	DomainRequestMapping: schema.FaultWire, DomainProtocolSerializer: schema.FaultWire, DomainStreamStateMachine: schema.FaultWire, DomainGatewayTranslation: schema.FaultWire,
	DomainToolParser: schema.FaultProtocol, DomainReasoningParser: schema.FaultProtocol,
	DomainChatTemplate: schema.FaultModel, DomainModelBehavior: schema.FaultModel,
	DomainSDKParser: schema.FaultClient, DomainAgentOrchestration: schema.FaultClient,
	DomainHarness:       schema.FaultHarness,
	DomainSpecAmbiguity: schema.FaultUnknown, DomainUnknown: schema.FaultUnknown,
}

func Family(domain Domain) (schema.FaultFamily, error) {
	family, ok := families[domain]
	if !ok {
		return "", fmt.Errorf("unknown fault domain %q", domain)
	}
	return family, nil
}

func ValidatePair(domain Domain, family schema.FaultFamily) error {
	expected, err := Family(domain)
	if err != nil {
		return err
	}
	if expected != family {
		return fmt.Errorf("fault domain %s belongs to family %s, not %s", domain, expected, family)
	}
	return nil
}

// Evidence is the result of explicitly bounded control experiments. Unknown
// booleans stay nil; treating missing evidence as false would over-attribute.
type Evidence struct {
	TransportReached       *bool
	AuthenticationAccepted *bool
	RawWireValid           *bool
	ReferenceAccepts       *bool
	SDKAccepts             *bool
	DirectAccepts          *bool
	GatewayAccepts         *bool
	StreamAccepts          *bool
	NonStreamAccepts       *bool
	ToolSyntaxValid        *bool
	ReasoningSyntaxValid   *bool
	HarnessHealthy         *bool
	TransientStatus        *bool
	SpecUnambiguous        *bool
}

type Result struct {
	Domain       Domain             `json:"fault_domain"`
	Family       schema.FaultFamily `json:"fault_family"`
	Confidence   float64            `json:"confidence"`
	Alternatives []Domain           `json:"alternative_domains,omitempty"`
	Evidence     []string           `json:"evidence"`
	Taxonomy     string             `json:"taxonomy_version"`
	Calibration  string             `json:"calibration_version"`
}

// Classify applies conservative rules ordered from harness/precondition
// failures to increasingly specific differential evidence.
func Classify(input Evidence) Result {
	domain := DomainUnknown
	confidence := 0.25
	reasons := []string{"available evidence does not isolate a product layer"}
	alternatives := []Domain{}
	switch {
	case isFalse(input.HarnessHealthy):
		domain, confidence, reasons = DomainHarness, 1, []string{"harness health precondition failed"}
	case isFalse(input.SpecUnambiguous):
		domain, confidence, reasons = DomainSpecAmbiguity, 0.99, []string{"normative source has unresolved ambiguity"}
	case isFalse(input.TransportReached):
		domain, confidence, reasons = DomainTransport, 0.95, []string{"target transport was not reached"}
	case isTrue(input.TransportReached) && isFalse(input.AuthenticationAccepted):
		domain, confidence, reasons = DomainAuth, 0.95, []string{"transport succeeded and authentication was rejected"}
	case isTrue(input.TransientStatus):
		domain, confidence, reasons = DomainRateLimitTransient, 0.9, []string{"bounded observation reported a rate-limit or transient service status"}
	case isTrue(input.RawWireValid) && isFalse(input.SDKAccepts):
		domain, confidence, reasons = DomainSDKParser, 0.9, []string{"the same captured wire is valid to the raw decoder and rejected by the SDK"}
	case isTrue(input.DirectAccepts) && isFalse(input.GatewayAccepts):
		domain, confidence, reasons = DomainGatewayTranslation, 0.9, []string{"direct path accepts the same semantic exchange while the gateway path rejects it"}
	case isTrue(input.NonStreamAccepts) && isFalse(input.StreamAccepts):
		domain, confidence, reasons = DomainStreamStateMachine, 0.88, []string{"non-stream control passes while stream state-machine control fails"}
	case isFalse(input.RawWireValid) && isTrue(input.ReferenceAccepts):
		domain, confidence, reasons = DomainProtocolSerializer, 0.85, []string{"reference control accepts the scenario while captured target wire violates the checked structure"}
	case isFalse(input.ToolSyntaxValid):
		domain, confidence, reasons = DomainToolParser, 0.8, []string{"tool syntax is invalid at the protocol semantic layer"}
		alternatives = append(alternatives, DomainProtocolSerializer)
	case isFalse(input.ReasoningSyntaxValid):
		domain, confidence, reasons = DomainReasoningParser, 0.8, []string{"reasoning syntax is invalid at the protocol semantic layer"}
		alternatives = append(alternatives, DomainProtocolSerializer)
	}
	family, _ := Family(domain)
	return Result{Domain: domain, Family: family, Confidence: confidence, Alternatives: alternatives, Evidence: reasons, Taxonomy: TaxonomyVersion, Calibration: CalibrationVersion}
}

func isTrue(value *bool) bool  { return value != nil && *value }
func isFalse(value *bool) bool { return value != nil && !*value }

// Fingerprint intentionally excludes timestamps, request IDs, and ordering of
// map keys. expected and observed must already be redacted typed summaries.
func Fingerprint(scenarioID, assertionID, category string, expected, observed any) (schema.Digest, error) {
	if strings.TrimSpace(scenarioID) == "" || strings.TrimSpace(assertionID) == "" || strings.TrimSpace(category) == "" {
		return "", errors.New("scenario, assertion, and category are required")
	}
	return schema.CanonicalDigest(struct {
		Version     string `json:"fingerprint_version"`
		ScenarioID  string `json:"scenario_id"`
		AssertionID string `json:"assertion_id"`
		Category    string `json:"failure_category"`
		Expected    any    `json:"expected"`
		Observed    any    `json:"observed"`
	}{"failure-fingerprint-v1", scenarioID, assertionID, category, expected, observed})
}

// Domains returns a stable list for schema/docs generation.
func Domains() []Domain {
	result := make([]Domain, 0, len(families))
	for domain := range families {
		result = append(result, domain)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
