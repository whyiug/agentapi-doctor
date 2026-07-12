package packapi

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

type CompileStage string

const (
	StageParse       CompileStage = "parse"
	StageSchema      CompileStage = "schema"
	StageSemantic    CompileStage = "semantic"
	StageRequirement CompileStage = "requirement"
	StageFixture     CompileStage = "fixture"
	StageCEL         CompileStage = "cel"
	StageCanonical   CompileStage = "canonical"
)

// CompileError identifies the failed deterministic compiler stage.
type CompileError struct {
	Stage CompileStage
	Path  string
	Err   error
}

func (compileError *CompileError) Error() string {
	if compileError == nil {
		return "<nil>"
	}
	if compileError.Path == "" {
		return fmt.Sprintf("%s: %v", compileError.Stage, compileError.Err)
	}
	return fmt.Sprintf("%s at %s: %v", compileError.Stage, compileError.Path, compileError.Err)
}

func (compileError *CompileError) Unwrap() error {
	if compileError == nil {
		return nil
	}
	return compileError.Err
}

type CompilerIdentity struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Canonicalization string `json:"canonicalization"`
	CELEnvironment   string `json:"cel_environment"`
}

type RequirementLink struct {
	ID           string              `json:"id"`
	Level        RequirementLevel    `json:"level"`
	Category     ScenarioClass       `json:"category"`
	SourceDigest publicschema.Digest `json:"source_digest"`
}

type FixturePin struct {
	Ref    string              `json:"ref"`
	Digest publicschema.Digest `json:"digest"`
}

type CELBinding struct {
	StepID         string      `json:"step_id"`
	AssertionIndex *int        `json:"assertion_index,omitempty"`
	Purpose        string      `json:"purpose"`
	Compiled       CompiledCEL `json:"compiled"`
}

// TemplateBinding is a prevalidated runtime substitution site. Expansion may
// only use the listed variables supplied by the resolved plan; no expression,
// environment, file, or command evaluation is involved.
type TemplateBinding struct {
	Path      string   `json:"path"`
	Variables []string `json:"variables"`
}

// ScenarioIR is the canonical compiler output. It contains no YAML syntax,
// source comments, unresolved fixtures, or executable program objects.
type ScenarioIR struct {
	SchemaVersion    string            `json:"schema_version"`
	Kind             string            `json:"kind"`
	Compiler         CompilerIdentity  `json:"compiler"`
	Scenario         Scenario          `json:"scenario"`
	RequirementLinks []RequirementLink `json:"requirement_links"`
	FixturePins      []FixturePin      `json:"fixture_pins"`
	CELBindings      []CELBinding      `json:"cel_bindings,omitempty"`
	TemplateBindings []TemplateBinding `json:"template_bindings,omitempty"`
}

// CompiledScenario owns a canonical immutable projection and digest.
type CompiledScenario struct {
	Authored      Scenario
	IR            ScenarioIR
	CanonicalJSON []byte
	Digest        publicschema.Digest
}

type ScenarioPin struct {
	Path   string              `json:"path"`
	Digest publicschema.Digest `json:"digest"`
}

type PackSpecIR struct {
	Engine            EngineCompatibility         `json:"engine"`
	ProtocolSnapshot  ProtocolSnapshotRef         `json:"protocol_snapshot"`
	Scenarios         ScenarioSelection           `json:"scenarios"`
	ConformanceSuites map[string]ConformanceSuite `json:"conformance_suites"`
	DefaultBudget     PackBudget                  `json:"default_budget"`
}

type PackIR struct {
	SchemaVersion          string              `json:"schema_version"`
	Kind                   string              `json:"kind"`
	Compiler               CompilerIdentity    `json:"compiler"`
	Metadata               PackMetadata        `json:"metadata"`
	Spec                   PackSpecIR          `json:"spec"`
	ProtocolSnapshotDigest publicschema.Digest `json:"protocol_snapshot_digest"`
	ScenarioPins           []ScenarioPin       `json:"scenario_pins"`
}

type CompiledPack struct {
	Authored      ProtocolPack
	IR            PackIR
	CanonicalJSON []byte
	Digest        publicschema.Digest
}

func compilerIdentity() CompilerIdentity {
	return CompilerIdentity{
		Name:             CompilerName,
		Version:          CompilerSemanticVersion,
		Canonicalization: "RFC8785",
		CELEnvironment:   "restricted-pure-v1",
	}
}

// CompileScenarioYAML compiles one authored Scenario without filesystem,
// network, environment, or credential access. All requirement and fixture
// facts are supplied explicitly in options.
func CompileScenarioYAML(raw []byte, options CompileOptions) (*CompiledScenario, error) {
	scenario, err := decodeScenarioYAML(raw)
	if err != nil {
		return nil, classifyDecodeError(err)
	}
	if scenario.Spec.Repetition.Count == 0 && scenario.Spec.Repetition.Policy == "" {
		scenario.Spec.Repetition = RepetitionPolicy{Count: 1, Policy: "all"}
	}
	validation, err := validateScenario(&scenario, options)
	if err != nil {
		return nil, err
	}
	links := make([]RequirementLink, 0, len(validation.requirements))
	for _, requirement := range validation.requirements {
		links = append(links, RequirementLink{
			ID: requirement.ID, Level: requirement.Level, Category: requirement.Category,
			SourceDigest: requirement.SourceDigest,
		})
	}
	slices.SortFunc(links, func(left, right RequirementLink) int { return bytes.Compare([]byte(left.ID), []byte(right.ID)) })
	pins := make([]FixturePin, 0, len(validation.fixtures))
	for ref, digest := range validation.fixtures {
		pins = append(pins, FixturePin{Ref: ref, Digest: digest})
	}
	slices.SortFunc(pins, func(left, right FixturePin) int { return bytes.Compare([]byte(left.Ref), []byte(right.Ref)) })

	ir := ScenarioIR{
		SchemaVersion:    "urn:agentapi-doctor:compiled-scenario:v1",
		Kind:             "CompiledScenario",
		Compiler:         compilerIdentity(),
		Scenario:         scenario,
		RequirementLinks: links,
		FixturePins:      pins,
		CELBindings:      validation.celBindings,
		TemplateBindings: validation.templateBindings,
	}
	canonical, err := publicschema.CanonicalMarshal(ir)
	if err != nil {
		return nil, &CompileError{Stage: StageCanonical, Path: "$", Err: err}
	}
	return &CompiledScenario{
		Authored:      scenario,
		IR:            ir,
		CanonicalJSON: append([]byte(nil), canonical...),
		Digest:        publicschema.NewDigest(canonical),
	}, nil
}

// CompileProtocolPackYAML resolves a pack snapshot and scenario selection to
// exact digests before producing the immutable Pack IR.
func CompileProtocolPackYAML(raw []byte, options PackCompileOptions) (*CompiledPack, error) {
	pack, err := decodePackYAML(raw)
	if err != nil {
		return nil, classifyDecodeError(err)
	}
	resolution, err := validatePack(&pack, options)
	if err != nil {
		return nil, err
	}
	ir := PackIR{
		SchemaVersion: "urn:agentapi-doctor:compiled-pack:v1",
		Kind:          "CompiledProtocolPack",
		Compiler:      compilerIdentity(),
		Metadata:      pack.Metadata,
		Spec: PackSpecIR{
			Engine:            pack.Spec.Engine,
			ProtocolSnapshot:  pack.Spec.ProtocolSnapshot,
			Scenarios:         pack.Spec.Scenarios,
			ConformanceSuites: pack.Spec.ConformanceSuites,
			DefaultBudget:     pack.Spec.DefaultBudget,
		},
		ProtocolSnapshotDigest: resolution.snapshotDigest,
		ScenarioPins:           resolution.scenarios,
	}
	canonical, err := publicschema.CanonicalMarshal(ir)
	if err != nil {
		return nil, &CompileError{Stage: StageCanonical, Path: "$", Err: err}
	}
	digest := publicschema.NewDigest(canonical)
	if pack.Spec.Signing.Digest != "" && pack.Spec.Signing.Digest != digest {
		return nil, &CompileError{Stage: StageCanonical, Path: "$.spec.signing.digest", Err: fmt.Errorf("declared %s does not match compiled %s", pack.Spec.Signing.Digest, digest)}
	}
	return &CompiledPack{
		Authored:      pack,
		IR:            ir,
		CanonicalJSON: append([]byte(nil), canonical...),
		Digest:        digest,
	}, nil
}

func classifyDecodeError(err error) error {
	if err == nil {
		return nil
	}
	stage := StageParse
	if bytes.Contains([]byte(err.Error()), []byte("JSON Schema validation")) || bytes.Contains([]byte(err.Error()), []byte("decode authored contract")) {
		stage = StageSchema
	}
	return &CompileError{Stage: stage, Path: "$", Err: err}
}

func IsCompileStage(err error, stage CompileStage) bool {
	var compileError *CompileError
	return errors.As(err, &compileError) && compileError.Stage == stage
}
