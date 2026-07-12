// Package rawdriver executes registry-bound raw HTTP scenarios through the
// origin-restricted transport and the evidence-first evaluation pipeline.
package rawdriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/whyiug/agentapi-doctor/internal/budget"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

// Protocol identifies the provider wire shape interpreted by the built-in
// normalizer. It is deliberately closed; unknown protocols require a new,
// reviewed decoder rather than falling through to a permissive guess.
type Protocol string

const (
	ProtocolOpenAIChat      Protocol = "openai-chat"
	ProtocolOpenAIResponses Protocol = "openai-responses"
	ProtocolAnthropic       Protocol = "anthropic-messages"
)

// CheckKind selects one bounded assertion over the normalized exchange. Core
// JSON, relationship, and stream-state checks always run in addition to this
// scenario-specific assertion.
type CheckKind string

const (
	CheckArgumentsString   CheckKind = "arguments_string"
	CheckOutputIndexes     CheckKind = "output_indexes"
	CheckStreamingToolCall CheckKind = "streaming_tool_call"
	CheckFinishReason      CheckKind = "finish_reason"
	CheckTerminalEvent     CheckKind = "terminal_event"
	CheckStableToolCallID  CheckKind = "stable_tool_call_id"
	CheckNoUnknownEvent    CheckKind = "no_unknown_event"
	CheckClosedReasoning   CheckKind = "closed_reasoning"
	CheckUsageConsistent   CheckKind = "usage_consistent"
	CheckValidUTF8         CheckKind = "valid_utf8"
	CheckRequiredEnvelope  CheckKind = "required_response_envelope"
	CheckStreamMediaType   CheckKind = "stream_media_type"
	CheckNoPostTerminal    CheckKind = "no_post_terminal_data"
)

// TokenUsage is an exact synthetic expectation. It is only used by a scenario
// whose catalog assertion explicitly checks deterministic fixture usage.
type TokenUsage struct {
	Input  int64
	Output int64
	Total  *int64
}

// AssertionSpec binds an executable check to its catalog requirement, oracle,
// and protected evaluator digest.
type AssertionSpec struct {
	AssertionID     string
	RequirementID   string
	Role            schema.AssertionRole
	Oracle          schema.ArtifactPin
	EvaluatorDigest schema.Digest
	Check           CheckKind
	AllowedValues   []string
	ExpectedUsage   *TokenUsage
}

// BodyBudget is an enforced per-scenario body boundary. RequestBytes applies
// to the canonical JSON body; ResponseBytes applies before parsing or CAS
// persistence.
type BodyBudget struct {
	RequestBytes  int64
	ResponseBytes int64
}

const (
	maxScenarioRequestBytes  int64 = 16 << 20
	maxScenarioResponseBytes int64 = 64 << 20
)

// Scenario is the immutable request and oracle material returned by the
// registry. No origin is present here: the only origin comes from transport's
// separately authorized exact-origin client.
type Scenario struct {
	PlanDigest     schema.Digest
	ID             string
	Driver         schema.ArtifactPin
	Protocol       Protocol
	Method         string
	Path           string
	Headers        http.Header
	Body           json.RawMessage
	Streaming      bool
	ExpectedStatus int
	Budget         BodyBudget
	Assertion      AssertionSpec
}

// Registry performs both the pre-reservation estimate lookup and the exact
// plan-bound execution lookup required by executor.Runner.
type Registry interface {
	Estimate(schema.ScenarioDecision) (budget.Usage, error)
	Lookup(schema.Digest, schema.ScenarioDecision) (Scenario, error)
}

type registryKey struct {
	plan     schema.Digest
	scenario string
}

type decisionKey struct {
	scenario string
	driver   schema.ArtifactPin
}

// MemoryRegistry is a concurrency-safe synthetic registry suitable for local
// execution and tests. Register clones all mutable input.
type MemoryRegistry struct {
	mu         sync.RWMutex
	byPlan     map[registryKey]Scenario
	byDecision map[decisionKey][]registryKey
}

func NewMemoryRegistry(scenarios ...Scenario) (*MemoryRegistry, error) {
	registry := &MemoryRegistry{
		byPlan:     make(map[registryKey]Scenario, len(scenarios)),
		byDecision: make(map[decisionKey][]registryKey, len(scenarios)),
	}
	for _, scenario := range scenarios {
		if err := registry.Register(scenario); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (registry *MemoryRegistry) Register(input Scenario) error {
	if registry == nil {
		return errors.New("registry is nil")
	}
	scenario, err := validateAndCloneScenario(input)
	if err != nil {
		return err
	}
	key := registryKey{plan: scenario.PlanDigest, scenario: scenario.ID}
	decision := decisionKey{scenario: scenario.ID, driver: scenario.Driver}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.byPlan[key]; exists {
		return fmt.Errorf("scenario %q is already registered for plan %s", scenario.ID, scenario.PlanDigest)
	}
	registry.byPlan[key] = scenario
	registry.byDecision[decision] = append(registry.byDecision[decision], key)
	return nil
}

func (registry *MemoryRegistry) Estimate(decision schema.ScenarioDecision) (budget.Usage, error) {
	if registry == nil {
		return budget.Usage{}, errors.New("registry is nil")
	}
	if err := validateDecision(decision); err != nil {
		return budget.Usage{}, err
	}
	key := decisionKey{scenario: decision.ScenarioID, driver: decision.Driver}
	registry.mu.RLock()
	keys := slices.Clone(registry.byDecision[key])
	if len(keys) != 1 {
		registry.mu.RUnlock()
		if len(keys) == 0 {
			return budget.Usage{}, errors.New("scenario decision is absent from the registry")
		}
		return budget.Usage{}, errors.New("scenario decision is ambiguous across plan digests")
	}
	scenario := cloneScenario(registry.byPlan[keys[0]])
	registry.mu.RUnlock()
	return estimateFor(scenario), nil
}

func (registry *MemoryRegistry) Lookup(planDigest schema.Digest, decision schema.ScenarioDecision) (Scenario, error) {
	if registry == nil {
		return Scenario{}, errors.New("registry is nil")
	}
	if err := planDigest.Validate(); err != nil {
		return Scenario{}, fmt.Errorf("plan digest: %w", err)
	}
	if err := validateDecision(decision); err != nil {
		return Scenario{}, err
	}
	key := registryKey{plan: planDigest, scenario: decision.ScenarioID}
	registry.mu.RLock()
	scenario, exists := registry.byPlan[key]
	registry.mu.RUnlock()
	if !exists {
		return Scenario{}, errors.New("scenario is not registered under the approved plan digest")
	}
	if scenario.Driver != decision.Driver {
		return Scenario{}, errors.New("scenario driver pin does not match the registered request")
	}
	return cloneScenario(scenario), nil
}

// Clear releases all registered request material after one local execution.
// Mutable bodies are overwritten before references are dropped. Header values
// are strings and cannot be reliably erased by Go; they remain process-memory
// only and are never accepted by a persistence API before redaction.
func (registry *MemoryRegistry) Clear() {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for key, scenario := range registry.byPlan {
		for index := range scenario.Body {
			scenario.Body[index] = 0
		}
		for name := range scenario.Headers {
			delete(scenario.Headers, name)
		}
		registry.byPlan[key] = scenario
	}
	clear(registry.byPlan)
	clear(registry.byDecision)
}

func validateAndCloneScenario(input Scenario) (Scenario, error) {
	if err := input.PlanDigest.Validate(); err != nil {
		return Scenario{}, fmt.Errorf("plan digest: %w", err)
	}
	if strings.TrimSpace(input.ID) == "" {
		return Scenario{}, errors.New("scenario ID is required")
	}
	if err := input.Driver.Validate(); err != nil {
		return Scenario{}, fmt.Errorf("driver: %w", err)
	}
	if !slices.Contains([]Protocol{ProtocolOpenAIChat, ProtocolOpenAIResponses, ProtocolAnthropic}, input.Protocol) {
		return Scenario{}, fmt.Errorf("unsupported protocol %q", input.Protocol)
	}
	if !validHTTPMethod(input.Method) {
		return Scenario{}, errors.New("HTTP method must be a canonical uppercase token")
	}
	parsed, err := url.ParseRequestURI(input.Path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || !strings.HasPrefix(parsed.Path, "/") {
		return Scenario{}, errors.New("request path must be an origin-free absolute-path reference")
	}
	if strings.Contains(parsed.Path, "\\") || path.Clean(parsed.Path) != parsed.Path {
		return Scenario{}, errors.New("request path must be canonical")
	}
	canonical, err := schema.CanonicalizeJSON(input.Body)
	if err != nil {
		return Scenario{}, fmt.Errorf("request body: %w", err)
	}
	var requestObject map[string]any
	if err := json.Unmarshal(canonical, &requestObject); err != nil || requestObject == nil {
		return Scenario{}, errors.New("request body must be a JSON object")
	}
	wireStreaming := false
	if value, exists := requestObject["stream"]; exists {
		var ok bool
		wireStreaming, ok = value.(bool)
		if !ok {
			return Scenario{}, errors.New("request stream field must be boolean")
		}
	}
	if wireStreaming != input.Streaming {
		return Scenario{}, errors.New("scenario streaming mode does not match its request body")
	}
	if input.Budget.RequestBytes <= 0 || input.Budget.ResponseBytes <= 0 {
		return Scenario{}, errors.New("positive request and response body budgets are required")
	}
	if input.Budget.RequestBytes > maxScenarioRequestBytes || input.Budget.ResponseBytes > maxScenarioResponseBytes {
		return Scenario{}, errors.New("scenario body budget exceeds the built-in raw-driver safety ceiling")
	}
	if int64(len(canonical)) > input.Budget.RequestBytes {
		return Scenario{}, errors.New("canonical request body exceeds the scenario request budget")
	}
	if input.ExpectedStatus < http.StatusContinue || input.ExpectedStatus > 599 {
		return Scenario{}, errors.New("expected HTTP status must be between 100 and 599")
	}
	if err := validateAssertion(input.Assertion); err != nil {
		return Scenario{}, err
	}
	if err := validateAssertionApplicability(input.Protocol, input.Streaming, input.Assertion.Check); err != nil {
		return Scenario{}, err
	}
	if err := validateHeaders(input.Headers); err != nil {
		return Scenario{}, err
	}
	result := input
	result.Body = append(json.RawMessage(nil), canonical...)
	result.Headers = cloneHeaders(input.Headers)
	if result.Headers.Get("Content-Type") == "" {
		result.Headers.Set("Content-Type", "application/json; charset=utf-8")
	}
	return result, nil
}

func validateAssertion(assertion AssertionSpec) error {
	if strings.TrimSpace(assertion.AssertionID) == "" {
		return errors.New("assertion ID is required")
	}
	if assertion.Role != schema.AssertionNormative || strings.TrimSpace(assertion.RequirementID) == "" {
		return errors.New("raw-driver assertions must be normative and cite a requirement ID")
	}
	if err := assertion.Oracle.Validate(); err != nil {
		return fmt.Errorf("oracle pin: %w", err)
	}
	if err := assertion.EvaluatorDigest.Validate(); err != nil {
		return fmt.Errorf("evaluator digest: %w", err)
	}
	if !slices.Contains([]CheckKind{
		CheckArgumentsString, CheckOutputIndexes, CheckStreamingToolCall,
		CheckFinishReason, CheckTerminalEvent, CheckStableToolCallID,
		CheckNoUnknownEvent, CheckClosedReasoning, CheckUsageConsistent,
		CheckValidUTF8, CheckRequiredEnvelope, CheckStreamMediaType,
		CheckNoPostTerminal,
	}, assertion.Check) {
		return fmt.Errorf("unsupported assertion check %q", assertion.Check)
	}
	if assertion.Check == CheckFinishReason && len(assertion.AllowedValues) == 0 {
		return errors.New("finish-reason assertion requires allowed values")
	}
	seenAllowed := make(map[string]struct{}, len(assertion.AllowedValues))
	for _, value := range assertion.AllowedValues {
		if strings.TrimSpace(value) == "" {
			return errors.New("allowed finish reasons cannot be empty")
		}
		if _, duplicate := seenAllowed[value]; duplicate {
			return errors.New("allowed finish reasons must be unique")
		}
		seenAllowed[value] = struct{}{}
	}
	if assertion.Check == CheckUsageConsistent {
		if assertion.ExpectedUsage == nil || assertion.ExpectedUsage.Input < 0 || assertion.ExpectedUsage.Output < 0 || assertion.ExpectedUsage.Total != nil && *assertion.ExpectedUsage.Total < 0 {
			return errors.New("usage assertion requires a nonnegative exact expectation")
		}
		if assertion.ExpectedUsage.Total != nil && *assertion.ExpectedUsage.Total != assertion.ExpectedUsage.Input+assertion.ExpectedUsage.Output {
			return errors.New("expected usage total must equal input plus output")
		}
	}
	return nil
}

func validateAssertionApplicability(protocol Protocol, streaming bool, check CheckKind) error {
	streamOnly := slices.Contains([]CheckKind{
		CheckOutputIndexes, CheckStreamingToolCall, CheckTerminalEvent,
		CheckStableToolCallID, CheckNoUnknownEvent, CheckClosedReasoning,
		CheckValidUTF8, CheckStreamMediaType, CheckNoPostTerminal,
	}, check)
	if streamOnly && !streaming {
		return fmt.Errorf("assertion check %q requires a streaming scenario", check)
	}
	if check == CheckOutputIndexes && protocol != ProtocolOpenAIResponses {
		return errors.New("output-index assertion requires the OpenAI Responses protocol")
	}
	if check == CheckClosedReasoning && protocol == ProtocolOpenAIChat {
		return errors.New("closed-reasoning assertion is not defined for OpenAI Chat")
	}
	if check == CheckRequiredEnvelope && streaming {
		return errors.New("required-response-envelope assertion requires a non-streaming scenario")
	}
	return nil
}

func validateDecision(decision schema.ScenarioDecision) error {
	if decision.Disposition != schema.DispositionExecute {
		return errors.New("raw driver only estimates executable scenario decisions")
	}
	if strings.TrimSpace(decision.ScenarioID) == "" {
		return errors.New("scenario decision ID is required")
	}
	if err := decision.Driver.Validate(); err != nil {
		return fmt.Errorf("scenario driver: %w", err)
	}
	return nil
}

func validHTTPMethod(method string) bool {
	if method == "" || method != strings.ToUpper(method) {
		return false
	}
	for _, character := range method {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func validateHeaders(headers http.Header) error {
	for name, values := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid request header name %q", name)
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "upgrade":
			return fmt.Errorf("request header %q is controlled by the origin-bound transport", name)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("request header %q contains a forbidden control character", name)
			}
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func estimateFor(scenario Scenario) budget.Usage {
	// The envelope allowance is derived, not a hand-entered result metric. It
	// covers bounded request/response metadata plus both persisted bodies.
	const envelopeAllowance = int64(64 << 10)
	return budget.Usage{
		Requests:      1,
		RequestBytes:  int64(len(scenario.Body)),
		ResponseBytes: scenario.Budget.ResponseBytes,
		ArtifactBytes: int64(len(scenario.Body)) + 16*scenario.Budget.ResponseBytes + envelopeAllowance,
	}
}

func cloneScenario(source Scenario) Scenario {
	result := source
	result.Headers = cloneHeaders(source.Headers)
	result.Body = bytes.Clone(source.Body)
	result.Assertion.AllowedValues = slices.Clone(source.Assertion.AllowedValues)
	if source.Assertion.ExpectedUsage != nil {
		copyUsage := *source.Assertion.ExpectedUsage
		if source.Assertion.ExpectedUsage.Total != nil {
			total := *source.Assertion.ExpectedUsage.Total
			copyUsage.Total = &total
		}
		result.Assertion.ExpectedUsage = &copyUsage
	}
	return result
}

func cloneHeaders(source http.Header) http.Header {
	result := make(http.Header, len(source))
	for name, values := range source {
		result[name] = slices.Clone(values)
	}
	return result
}
