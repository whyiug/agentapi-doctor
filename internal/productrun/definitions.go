// Package productrun assembles the small, local-first candidate execution
// slice used by the CLI. It deliberately does not claim a support tier: all
// built-in normative interpretations remain candidate/pending_review until
// the independent catalog gates are satisfied.
package productrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/whyiug/agentapi-doctor/internal/rawdriver"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	builtinVersion     = "0.1.0-candidate.1"
	catalogStatus      = "candidate"
	catalogReviewState = "pending_review"
)

// ScenarioDescriptor is the reviewable catalog binding for one built-in
// execution check. Interpretation is copied from the candidate Requirement
// Catalog and is part of the immutable built-in pack digest.
type ScenarioDescriptor struct {
	ID                        string              `json:"scenario_id"`
	RequirementID             string              `json:"requirement_id"`
	RequirementInterpretation string              `json:"requirement_interpretation"`
	CatalogStatus             string              `json:"catalog_status"`
	CatalogReviewStatus       string              `json:"catalog_review_status"`
	Protocol                  rawdriver.Protocol  `json:"protocol"`
	Streaming                 bool                `json:"streaming"`
	Check                     rawdriver.CheckKind `json:"check"`
	AllowedValues             []string            `json:"allowed_values,omitempty"`
}

var descriptors = map[string][]ScenarioDescriptor{
	"openai-chat": {
		{
			ID: "openai-chat-002-terminal-status", RequirementID: "OAI-CHAT-REQ-002",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Chat Completions HTTP/SSE maps documented terminal, truncated, refused, and filtered states distinctly.",
			Protocol:                  rawdriver.ProtocolOpenAIChat, Check: rawdriver.CheckFinishReason, AllowedValues: []string{"stop"},
		},
		{
			ID: "openai-chat-015-post-terminal-data", RequirementID: "OAI-CHAT-REQ-015",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Chat Completions HTTP/SSE rejects semantic data emitted after the terminal marker.",
			Protocol:                  rawdriver.ProtocolOpenAIChat, Streaming: true, Check: rawdriver.CheckNoPostTerminal,
		},
		{
			ID: "openai-chat-024-stream-media-type", RequirementID: "OAI-CHAT-REQ-024",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Chat Completions HTTP/SSE validates the documented streaming media type before event parsing.",
			Protocol:                  rawdriver.ProtocolOpenAIChat, Streaming: true, Check: rawdriver.CheckStreamMediaType,
		},
		{
			ID: "openai-chat-030-required-response-envelope", RequirementID: "OAI-CHAT-REQ-030",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Chat Completions HTTP/SSE requires the documented response envelope before evaluating model content.",
			Protocol:                  rawdriver.ProtocolOpenAIChat, Check: rawdriver.CheckRequiredEnvelope,
		},
	},
	"openai-responses": {
		{
			ID: "openai-responses-http-008-stream-media-type", RequirementID: "OAI-RESP-REQ-008",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Responses HTTP/SSE validates the documented streaming media type before event parsing.",
			Protocol:                  rawdriver.ProtocolOpenAIResponses, Streaming: true, Check: rawdriver.CheckStreamMediaType,
		},
		{
			ID: "openai-responses-http-014-required-response-envelope", RequirementID: "OAI-RESP-REQ-014",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Responses HTTP/SSE requires the documented response envelope before evaluating model content.",
			Protocol:                  rawdriver.ProtocolOpenAIResponses, Check: rawdriver.CheckRequiredEnvelope,
		},
		{
			ID: "openai-responses-http-030-terminal-exactly-once", RequirementID: "OAI-RESP-REQ-030",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Responses HTTP/SSE accepts exactly one documented terminal condition.",
			Protocol:                  rawdriver.ProtocolOpenAIResponses, Streaming: true, Check: rawdriver.CheckTerminalEvent,
		},
		{
			ID: "openai-responses-http-039-terminal-status", RequirementID: "OAI-RESP-REQ-039",
			RequirementInterpretation: "Candidate interpretation pending independent source review: OpenAI Responses HTTP/SSE maps documented terminal, truncated, refused, and filtered states distinctly.",
			Protocol:                  rawdriver.ProtocolOpenAIResponses, Check: rawdriver.CheckFinishReason, AllowedValues: []string{"completed"},
		},
	},
	"anthropic-messages": {
		{
			ID: "anthropic-messages-008-post-terminal-data", RequirementID: "ANTH-MSG-REQ-008",
			RequirementInterpretation: "Candidate interpretation pending independent source review: Anthropic Messages HTTP/SSE rejects semantic data emitted after the terminal marker.",
			Protocol:                  rawdriver.ProtocolAnthropic, Streaming: true, Check: rawdriver.CheckNoPostTerminal,
		},
		{
			ID: "anthropic-messages-017-stream-media-type", RequirementID: "ANTH-MSG-REQ-017",
			RequirementInterpretation: "Candidate interpretation pending independent source review: Anthropic Messages HTTP/SSE validates the documented streaming media type before event parsing.",
			Protocol:                  rawdriver.ProtocolAnthropic, Streaming: true, Check: rawdriver.CheckStreamMediaType,
		},
		{
			ID: "anthropic-messages-023-required-response-envelope", RequirementID: "ANTH-MSG-REQ-023",
			RequirementInterpretation: "Candidate interpretation pending independent source review: Anthropic Messages HTTP/SSE requires the documented response envelope before evaluating model content.",
			Protocol:                  rawdriver.ProtocolAnthropic, Check: rawdriver.CheckRequiredEnvelope,
		},
		{
			ID: "anthropic-messages-039-terminal-exactly-once", RequirementID: "ANTH-MSG-REQ-039",
			RequirementInterpretation: "Candidate interpretation pending independent source review: Anthropic Messages HTTP/SSE accepts exactly one documented terminal condition.",
			Protocol:                  rawdriver.ProtocolAnthropic, Streaming: true, Check: rawdriver.CheckTerminalEvent,
		},
	},
}

func init() {
	for protocol, entries := range descriptors {
		for index := range entries {
			entries[index].CatalogStatus = catalogStatus
			entries[index].CatalogReviewStatus = catalogReviewState
		}
		descriptors[protocol] = entries
	}
}

// BuiltinScenarios returns a detached, stable view of the selected candidate
// scenarios. It never reads a live provider or ambient configuration.
func BuiltinScenarios(protocol string) ([]ScenarioDescriptor, error) {
	entries, ok := descriptors[protocol]
	if !ok {
		return nil, fmt.Errorf("unsupported target protocol %q", protocol)
	}
	result := make([]ScenarioDescriptor, len(entries))
	for index, entry := range entries {
		result[index] = entry
		result[index].AllowedValues = slices.Clone(entry.AllowedValues)
	}
	return result, nil
}

type scenarioMaterial struct {
	Descriptor     ScenarioDescriptor   `json:"descriptor"`
	Method         string               `json:"method"`
	Path           string               `json:"path"`
	Headers        http.Header          `json:"headers"`
	Body           json.RawMessage      `json:"body"`
	ExpectedStatus int                  `json:"expected_status"`
	Budget         rawdriver.BodyBudget `json:"body_budget"`
	Driver         schema.ArtifactPin   `json:"driver"`
	Oracle         schema.ArtifactPin   `json:"oracle"`
	Evaluator      schema.Digest        `json:"evaluator_digest"`
}

type artifacts struct {
	driver    schema.ArtifactPin
	oracle    schema.ArtifactPin
	resolver  schema.ArtifactPin
	pack      schema.ArtifactPin
	profile   schema.ArtifactPin
	evaluator schema.Digest
	support   schema.Digest
	producer  schema.Producer
	materials []scenarioMaterial
}

func deriveArtifacts(protocol, model, endpointPath string) (artifacts, error) {
	entries, err := BuiltinScenarios(protocol)
	if err != nil {
		return artifacts{}, err
	}
	evaluatorManifest := struct {
		SchemaVersion string `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Semantics     string `json:"semantics"`
	}{"urn:agentapi-doctor:builtin-evaluator:v1", "raw-http-candidate-evaluator", builtinVersion, "strict content type, required envelope, terminal lifecycle, and post-terminal checks"}
	evaluator, err := schema.CanonicalDigest(evaluatorManifest)
	if err != nil {
		return artifacts{}, err
	}
	oracle, err := pin("Oracle", "builtin-raw-http-oracle", builtinVersion, evaluatorManifest)
	if err != nil {
		return artifacts{}, err
	}
	driverManifest := struct {
		SchemaVersion string `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Contract      string `json:"contract"`
	}{"urn:agentapi-doctor:builtin-driver:v1", "builtin-raw-http", builtinVersion, "one exact-origin bounded HTTP request per scenario; no subprocess or tool side effect"}
	driver, err := pin("Driver", "builtin-raw-http", builtinVersion, driverManifest)
	if err != nil {
		return artifacts{}, err
	}
	materials := make([]scenarioMaterial, 0, len(entries))
	for _, entry := range entries {
		body, bodyErr := requestBody(protocol, model, entry.Streaming)
		if bodyErr != nil {
			return artifacts{}, bodyErr
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "application/json; charset=utf-8")
		if entry.Streaming {
			headers.Set("Accept", "text/event-stream")
		} else {
			headers.Set("Accept", "application/json")
		}
		if protocol == "anthropic-messages" {
			headers.Set("anthropic-version", "2023-06-01")
		}
		materials = append(materials, scenarioMaterial{
			Descriptor: entry, Method: http.MethodPost, Path: endpointPath,
			Headers: headers, Body: body, ExpectedStatus: http.StatusOK,
			Budget: rawdriver.BodyBudget{RequestBytes: 64 << 10, ResponseBytes: 512 << 10},
			Driver: driver, Oracle: oracle, Evaluator: evaluator,
		})
	}
	packManifest := struct {
		SchemaVersion string             `json:"schema_version"`
		Name          string             `json:"name"`
		Version       string             `json:"version"`
		Status        string             `json:"status"`
		ReviewStatus  string             `json:"review_status"`
		Scenarios     []scenarioMaterial `json:"scenarios"`
	}{"urn:agentapi-doctor:builtin-pack:v1", "builtin-" + protocol + "-candidate-slice", builtinVersion, catalogStatus, catalogReviewState, materials}
	pack, err := pin("ProtocolPack", "builtin-"+protocol+"-candidate-slice", builtinVersion, packManifest)
	if err != nil {
		return artifacts{}, err
	}
	profileManifest := struct {
		SchemaVersion string        `json:"schema_version"`
		Name          string        `json:"name"`
		Version       string        `json:"version"`
		Pack          schema.Digest `json:"pack_digest"`
		Claim         string        `json:"claim"`
	}{"urn:agentapi-doctor:builtin-profile:v1", "builtin-" + protocol + "-raw-candidate", builtinVersion, pack.Digest, "candidate local raw-wire slice; no Tier or vendor compatibility claim"}
	profile, err := pin("ConsumerCompatibilityProfile", "builtin-"+protocol+"-raw-candidate", builtinVersion, profileManifest)
	if err != nil {
		return artifacts{}, err
	}
	resolverManifest := struct {
		SchemaVersion string        `json:"schema_version"`
		Name          string        `json:"name"`
		Version       string        `json:"version"`
		DriverDigest  schema.Digest `json:"driver_digest"`
	}{"urn:agentapi-doctor:builtin-resolver:v1", "builtin-exact-runner-resolver", builtinVersion, driver.Digest}
	resolver, err := pin("Resolver", "builtin-exact-runner-resolver", builtinVersion, resolverManifest)
	if err != nil {
		return artifacts{}, err
	}
	support, err := schema.CanonicalDigest(struct {
		SchemaVersion string `json:"schema_version"`
		Status        string `json:"status"`
		Claim         string `json:"claim"`
	}{"urn:agentapi-doctor:builtin-support-state:v1", "candidate-unresolved", "selected checks do not satisfy or assert a support tier"})
	if err != nil {
		return artifacts{}, err
	}
	producerManifest := struct {
		SchemaVersion string `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
	}{"urn:agentapi-doctor:productrun:v1", "agentapi-doctor-productrun", builtinVersion}
	producerDigest, err := schema.CanonicalDigest(producerManifest)
	if err != nil {
		return artifacts{}, err
	}
	return artifacts{
		driver: driver, oracle: oracle, resolver: resolver, pack: pack,
		profile: profile, evaluator: evaluator, support: support, materials: materials,
		producer: schema.Producer{Name: "agentapi-doctor-productrun", Version: builtinVersion, ArtifactDigest: producerDigest},
	}, nil
}

func pin(kind, name, version string, material any) (schema.ArtifactPin, error) {
	digest, err := schema.CanonicalDigest(material)
	if err != nil {
		return schema.ArtifactPin{}, err
	}
	result := schema.ArtifactPin{Kind: kind, Name: name, Version: version, Digest: digest}
	if err := result.Validate(); err != nil {
		return schema.ArtifactPin{}, err
	}
	return result, nil
}

func requestBody(protocol, model string, streaming bool) (json.RawMessage, error) {
	if model == "" {
		return nil, errors.New("target model is required")
	}
	var value any
	switch protocol {
	case "openai-chat":
		value = map[string]any{
			"model": model, "stream": streaming,
			"messages": []any{map[string]any{"role": "user", "content": "Return a concise synthetic response."}},
		}
	case "openai-responses":
		value = map[string]any{"model": model, "stream": streaming, "store": false, "input": "Return a concise synthetic response."}
	case "anthropic-messages":
		value = map[string]any{
			"model": model, "stream": streaming, "max_tokens": 64,
			"messages": []any{map[string]any{"role": "user", "content": "Return a concise synthetic response."}},
		}
	default:
		return nil, fmt.Errorf("unsupported target protocol %q", protocol)
	}
	return schema.CanonicalMarshal(value)
}
