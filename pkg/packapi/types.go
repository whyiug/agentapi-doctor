package packapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	ScenarioAPIVersion = "urn:agentapi-doctor:scenario:v1beta1"
	ScenarioKind       = "Scenario"
	PackAPIVersion     = "urn:agentapi-doctor:pack:v1"
	PackKind           = "ProtocolPack"

	CompilerName                   = "agentapi-doctor-pack-compiler"
	CompilerSemanticVersion        = "0.1.0"
	DefaultMaxCELCost       uint64 = 1000
	AbsoluteMaxCELCost      uint64 = 10000
)

var (
	resourceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	artifactNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	semverPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	calverPattern       = regexp.MustCompile(`^20[0-9]{2}\.(0[1-9]|1[0-2])\.(0|[1-9][0-9]*)$`)
)

// ByteSize is a positive binary byte count authored as a canonical value such
// as 16MiB. Canonical IR serializes it as an integer.
type ByteSize int64

const (
	KiB ByteSize = 1 << 10
	MiB ByteSize = 1 << 20
	GiB ByteSize = 1 << 30
)

func (size ByteSize) Validate() error {
	if size <= 0 {
		return errors.New("byte size must be positive")
	}
	return nil
}

func (size ByteSize) MarshalJSON() ([]byte, error) {
	if err := size.Validate(); err != nil {
		return nil, err
	}
	return []byte(strconv.FormatInt(int64(size), 10)), nil
}

func (size *ByteSize) UnmarshalJSON(raw []byte) error {
	if size == nil {
		return errors.New("cannot unmarshal byte size into nil receiver")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return errors.New("byte size must be a quoted canonical binary size such as 16MiB")
	}
	parsed, err := parseByteSize(text)
	if err != nil {
		return err
	}
	*size = parsed
	return nil
}

func parseByteSize(text string) (ByteSize, error) {
	units := []struct {
		suffix string
		factor ByteSize
	}{{"GiB", GiB}, {"MiB", MiB}, {"KiB", KiB}, {"B", 1}}
	for _, unit := range units {
		if !strings.HasSuffix(text, unit.suffix) {
			continue
		}
		number := strings.TrimSuffix(text, unit.suffix)
		if number == "" || (len(number) > 1 && number[0] == '0') {
			return 0, fmt.Errorf("byte size %q is not canonical", text)
		}
		value, err := strconv.ParseInt(number, 10, 64)
		if err != nil || value <= 0 || value > int64(^uint64(0)>>1)/int64(unit.factor) {
			return 0, fmt.Errorf("invalid byte size %q", text)
		}
		return ByteSize(value) * unit.factor, nil
	}
	return 0, fmt.Errorf("byte size %q must use B, KiB, MiB, or GiB", text)
}

// Scenario is the strict authored YAML form.
type Scenario struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ScenarioMetadata `json:"metadata"`
	Spec       ScenarioSpec     `json:"spec"`
}

type ScenarioMetadata struct {
	ID      string            `json:"id"`
	Version string            `json:"version"`
	Title   string            `json:"title"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type ScenarioSpec struct {
	Protocol       ProtocolBinding       `json:"protocol"`
	Classification Classification        `json:"classification"`
	Requirements   []RequirementRef      `json:"requirements"`
	Requires       CapabilityRequirement `json:"requires,omitempty"`
	Budgets        ScenarioBudget        `json:"budgets"`
	Steps          []Step                `json:"steps"`
	Resources      []ResourceLease       `json:"resources,omitempty"`
	Finally        []FinalizeStep        `json:"finally,omitempty"`
	Repetition     RepetitionPolicy      `json:"repetition,omitempty"`
	Publication    PublicationPolicy     `json:"publication"`
}

type ProtocolBinding struct {
	Family   string              `json:"family"`
	Snapshot string              `json:"snapshot"`
	Digest   publicschema.Digest `json:"digest"`
}

type ScenarioClass string

const (
	ClassNormative       ScenarioClass = "normative"
	ClassDeFactoClient   ScenarioClass = "de-facto-client"
	ClassConsumerProfile ScenarioClass = "consumer-profile"
	ClassBehavioral      ScenarioClass = "behavioral"
	ClassAdvisory        ScenarioClass = "advisory"
)

type Stability string

const (
	StabilityStable       Stability = "stable"
	StabilityExperimental Stability = "experimental"
	StabilityIncubating   Stability = "incubating"
)

type SideEffectClass string

const (
	SideEffectNone             SideEffectClass = "none"
	SideEffectReversibleLocal  SideEffectClass = "reversible-local"
	SideEffectReversibleRemote SideEffectClass = "reversible-remote"
	SideEffectIrreversible     SideEffectClass = "irreversible"
)

type Classification struct {
	Type        ScenarioClass   `json:"type"`
	Stability   Stability       `json:"stability"`
	SideEffects SideEffectClass `json:"sideEffects"`
	Idempotent  *bool           `json:"idempotent"`
}

type RequirementLevel string

const (
	LevelMust   RequirementLevel = "MUST"
	LevelShould RequirementLevel = "SHOULD"
	LevelMay    RequirementLevel = "MAY"
)

type RequirementRef struct {
	ID    string           `json:"id"`
	Level RequirementLevel `json:"level"`
}

type CapabilityRequirement struct {
	All  []string `json:"all,omitempty"`
	Any  []string `json:"any,omitempty"`
	None []string `json:"none,omitempty"`
}

type ScenarioBudget struct {
	Timeout          publicschema.Duration `json:"timeout"`
	MaxRequests      int64                 `json:"maxRequests"`
	MaxInputTokens   int64                 `json:"maxInputTokens"`
	MaxOutputTokens  int64                 `json:"maxOutputTokens"`
	MaxResponseBytes ByteSize              `json:"maxResponseBytes,omitempty"`
	MaxArtifactBytes ByteSize              `json:"maxArtifactBytes"`
}

// Step is a tagged union. Exactly one of the nine operation fields is legal.
type Step struct {
	ID                string                 `json:"id"`
	Invoke            *InvokeStep            `json:"invoke,omitempty"`
	Capture           *CaptureStep           `json:"capture,omitempty"`
	RegisterResource  *RegisterResourceStep  `json:"register_resource,omitempty"`
	ProvideToolResult *ProvideToolResultStep `json:"provide_tool_result,omitempty"`
	WaitFor           *WaitForStep           `json:"wait_for,omitempty"`
	Assert            *AssertStep            `json:"assert,omitempty"`
	Cancel            *CancelStep            `json:"cancel,omitempty"`
	Replay            *ReplayStep            `json:"replay,omitempty"`
	Finalize          *FinalizeStep          `json:"finalize,omitempty"`
}

type ControlledBackend struct {
	Fixture string `json:"fixture"`
}

type InvokeStep struct {
	Operation         string             `json:"operation"`
	Driver            string             `json:"driver"`
	ControlledBackend *ControlledBackend `json:"controlledBackend,omitempty"`
	Request           map[string]any     `json:"request"`
}

type CaptureStep struct {
	Stream string `json:"stream"`
	As     string `json:"as"`
}

type RegisterResourceStep struct {
	Resource    string `json:"resource"`
	AcquireFrom string `json:"acquireFrom"`
}

type ProvideToolResultStep struct {
	CallIDFrom string `json:"callIdFrom"`
	Result     any    `json:"result"`
}

type WaitForStep struct {
	Source    string                `json:"source"`
	Condition string                `json:"condition"`
	Timeout   publicschema.Duration `json:"timeout"`
}

type AssertStep []Assertion

type AssertionRole string

const (
	RolePrecondition    AssertionRole = "precondition"
	RoleNormative       AssertionRole = "normative"
	RoleConsumerProfile AssertionRole = "consumer_profile"
	RoleBehavioral      AssertionRole = "behavioral"
	RoleAdvisory        AssertionRole = "advisory"
)

type Assertion struct {
	Use           string          `json:"use,omitempty"`
	Expression    string          `json:"expression,omitempty"`
	Equals        json.RawMessage `json:"equals,omitempty"`
	AssertionRole AssertionRole   `json:"assertionRole"`
	ObservedAt    string          `json:"observedAt,omitempty"`
	Requirement   string          `json:"requirement,omitempty"`
}

type CancelStep struct {
	Invocation string `json:"invocation"`
	Reason     string `json:"reason"`
}

type ReplayStep struct {
	Fixture string `json:"fixture"`
	As      string `json:"as"`
}

type FinalizeStep struct {
	Finalize string `json:"finalize"`
}

type ResourceLease struct {
	ID              string            `json:"id"`
	AcquireFrom     string            `json:"acquireFrom"`
	SideEffectClass SideEffectClass   `json:"sideEffectClass"`
	Finalizer       ResourceFinalizer `json:"finalizer"`
	CleanupBudget   CleanupBudget     `json:"cleanupBudget"`
}

type ResourceFinalizer struct {
	Operation  string      `json:"operation"`
	Idempotent *bool       `json:"idempotent"`
	Retry      RetryPolicy `json:"retry"`
}

type RetryPolicy struct {
	MaxAttempts int64 `json:"maxAttempts"`
}

type CleanupBudget struct {
	Requests int64                 `json:"requests"`
	Duration publicschema.Duration `json:"duration"`
}

type RepetitionPolicy struct {
	Count  int64  `json:"count,omitempty"`
	Policy string `json:"policy,omitempty"`
}

type PublicationPolicy struct {
	DataClass string `json:"dataClass"`
}

// ProtocolPack is the strict authored pack manifest.
type ProtocolPack struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   PackMetadata `json:"metadata"`
	Spec       PackSpec     `json:"spec"`
}

type PackMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PackSpec struct {
	Engine            EngineCompatibility         `json:"engine"`
	ProtocolSnapshot  ProtocolSnapshotRef         `json:"protocolSnapshot"`
	Scenarios         ScenarioSelection           `json:"scenarios"`
	ConformanceSuites map[string]ConformanceSuite `json:"conformanceSuites"`
	DefaultBudget     PackBudget                  `json:"defaultBudget"`
	Signing           SigningExpectation          `json:"signing,omitempty"`
}

type EngineCompatibility struct {
	MinVersion string `json:"minVersion"`
	MaxMajor   int64  `json:"maxMajor"`
}

type ProtocolSnapshotRef struct {
	Ref string `json:"ref"`
}

type ScenarioSelection struct {
	Include []string `json:"include"`
}

type ConformanceSuite struct {
	Requirements []string `json:"requirements"`
}

type PackBudget struct {
	MaxRequests int64                 `json:"maxRequests"`
	MaxDuration publicschema.Duration `json:"maxDuration"`
}

type SigningExpectation struct {
	Digest publicschema.Digest `json:"digest,omitempty"`
}

// RequirementRecord is the immutable catalog fact supplied to the compiler.
// The compiler does not fetch sources or infer requirements.
type RequirementRecord struct {
	ID           string
	Level        RequirementLevel
	SourceDigest publicschema.Digest
	Category     ScenarioClass
}

type CompileOptions struct {
	Requirements     map[string]RequirementRecord
	Fixtures         map[string]publicschema.Digest
	AllowedVariables map[string]struct{}
	MaxCELCost       uint64
}

type PackCompileOptions struct {
	ProtocolSnapshots map[string]publicschema.Digest
	ScenarioFiles     map[string]publicschema.Digest
}
