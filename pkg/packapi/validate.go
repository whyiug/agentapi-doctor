package packapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

var templatePattern = regexp.MustCompile(`\{\{[ \t]*([A-Za-z][A-Za-z0-9_.-]*)[ \t]*\}\}`)

type scenarioValidation struct {
	requirements     map[string]RequirementRecord
	fixtures         map[string]publicschema.Digest
	celBindings      []CELBinding
	templateBindings []TemplateBinding
	options          CompileOptions
	stepIndexes      map[string]int
	resources        map[string]ResourceLease
}

func validateScenario(scenario *Scenario, options CompileOptions) (*scenarioValidation, error) {
	if scenario.APIVersion != ScenarioAPIVersion || scenario.Kind != ScenarioKind {
		return nil, semanticError("$", "scenario apiVersion/kind mismatch")
	}
	if !resourceNamePattern.MatchString(scenario.Metadata.ID) {
		return nil, semanticError("$.metadata.id", "invalid scenario ID")
	}
	if !semverPattern.MatchString(scenario.Metadata.Version) {
		return nil, semanticError("$.metadata.version", "scenario version must be SemVer")
	}
	if strings.TrimSpace(scenario.Metadata.Title) == "" {
		return nil, semanticError("$.metadata.title", "title is required")
	}
	labelKeys := make([]string, 0, len(scenario.Metadata.Labels))
	for key := range scenario.Metadata.Labels {
		labelKeys = append(labelKeys, key)
	}
	slices.Sort(labelKeys)
	for _, key := range labelKeys {
		if !resourceNamePattern.MatchString(key) {
			return nil, semanticError("$.metadata.labels", fmt.Sprintf("invalid label key %q", key))
		}
	}
	if !artifactNamePattern.MatchString(scenario.Spec.Protocol.Family) {
		return nil, semanticError("$.spec.protocol.family", "invalid protocol family")
	}
	if strings.TrimSpace(scenario.Spec.Protocol.Snapshot) == "" {
		return nil, semanticError("$.spec.protocol.snapshot", "protocol snapshot is required")
	}
	if err := scenario.Spec.Protocol.Digest.Validate(); err != nil {
		return nil, semanticError("$.spec.protocol.digest", err.Error())
	}
	if err := validateClassification(scenario.Spec.Classification); err != nil {
		return nil, semanticError("$.spec.classification", err.Error())
	}
	if err := validateScenarioBudget(scenario.Spec.Budgets); err != nil {
		return nil, semanticError("$.spec.budgets", err.Error())
	}
	if err := validateRepetition(scenario.Spec.Repetition); err != nil {
		return nil, semanticError("$.spec.repetition", err.Error())
	}
	if !slices.Contains([]string{"synthetic-only", "metadata-only", "local-private"}, scenario.Spec.Publication.DataClass) {
		return nil, semanticError("$.spec.publication.dataClass", "invalid publication data class")
	}

	validation := &scenarioValidation{
		requirements: make(map[string]RequirementRecord),
		fixtures:     make(map[string]publicschema.Digest),
		options:      options,
		stepIndexes:  make(map[string]int),
		resources:    make(map[string]ResourceLease),
	}
	if validation.options.MaxCELCost == 0 {
		validation.options.MaxCELCost = DefaultMaxCELCost
	}
	if validation.options.MaxCELCost > AbsoluteMaxCELCost {
		return nil, &CompileError{Stage: StageCEL, Path: "$", Err: fmt.Errorf("CEL cost limit exceeds %d", AbsoluteMaxCELCost)}
	}
	if validation.options.AllowedVariables == nil {
		validation.options.AllowedVariables = map[string]struct{}{"target.model": {}}
	}
	if err := validation.validateRequirements(scenario.Spec.Requirements); err != nil {
		return nil, err
	}
	if err := validateCapabilities(scenario.Spec.Requires); err != nil {
		return nil, semanticError("$.spec.requires", err.Error())
	}
	if err := validation.indexResources(scenario.Spec.Resources, scenario.Spec.Classification); err != nil {
		return nil, err
	}
	if err := validation.validateSteps(scenario); err != nil {
		return nil, err
	}
	if err := validation.validateResourceReferencesAndFinally(scenario); err != nil {
		return nil, err
	}
	slices.SortFunc(validation.templateBindings, func(left, right TemplateBinding) int {
		return strings.Compare(left.Path, right.Path)
	})
	return validation, nil
}

func validateClassification(classification Classification) error {
	if !slices.Contains([]ScenarioClass{ClassNormative, ClassDeFactoClient, ClassConsumerProfile, ClassBehavioral, ClassAdvisory}, classification.Type) {
		return fmt.Errorf("invalid scenario class %q", classification.Type)
	}
	if !slices.Contains([]Stability{StabilityStable, StabilityExperimental, StabilityIncubating}, classification.Stability) {
		return fmt.Errorf("invalid stability %q", classification.Stability)
	}
	if !slices.Contains([]SideEffectClass{SideEffectNone, SideEffectReversibleLocal, SideEffectReversibleRemote, SideEffectIrreversible}, classification.SideEffects) {
		return fmt.Errorf("invalid side effect class %q", classification.SideEffects)
	}
	if classification.Idempotent == nil {
		return errors.New("idempotent must be explicitly true or false")
	}
	if classification.Stability == StabilityStable && classification.SideEffects == SideEffectIrreversible {
		return errors.New("stable scenarios cannot declare irreversible side effects")
	}
	return nil
}

func validateScenarioBudget(budget ScenarioBudget) error {
	if err := budget.Timeout.Validate(); err != nil {
		return err
	}
	if budget.MaxRequests <= 0 {
		return errors.New("maxRequests must be positive")
	}
	if budget.MaxInputTokens < 0 || budget.MaxOutputTokens < 0 {
		return errors.New("token budgets cannot be negative")
	}
	if budget.MaxResponseBytes != 0 {
		if err := budget.MaxResponseBytes.Validate(); err != nil {
			return fmt.Errorf("maxResponseBytes: %w", err)
		}
	}
	return budget.MaxArtifactBytes.Validate()
}

func validateRepetition(repetition RepetitionPolicy) error {
	if repetition.Count <= 0 || repetition.Count > 1000 {
		return errors.New("repetition count must be between 1 and 1000")
	}
	if repetition.Policy != "all" && repetition.Policy != "any" {
		return errors.New("repetition policy must be all or any")
	}
	return nil
}

func validateCapabilities(requirement CapabilityRequirement) error {
	seen := make(map[string]string)
	for group, values := range map[string][]string{"all": requirement.All, "any": requirement.Any, "none": requirement.None} {
		for _, value := range values {
			if !resourceNamePattern.MatchString(value) {
				return fmt.Errorf("invalid %s capability %q", group, value)
			}
			if previous, duplicate := seen[value]; duplicate {
				return fmt.Errorf("capability %q appears in both %s and %s", value, previous, group)
			}
			seen[value] = group
		}
	}
	return nil
}

func (validation *scenarioValidation) validateRequirements(refs []RequirementRef) error {
	if len(refs) == 0 {
		return &CompileError{Stage: StageRequirement, Path: "$.spec.requirements", Err: errors.New("at least one requirement is required")}
	}
	declared := make(map[string]struct{}, len(refs))
	for index, ref := range refs {
		path := fmt.Sprintf("$.spec.requirements[%d]", index)
		if _, duplicate := declared[ref.ID]; duplicate {
			return &CompileError{Stage: StageRequirement, Path: path, Err: fmt.Errorf("duplicate requirement %q", ref.ID)}
		}
		declared[ref.ID] = struct{}{}
		record, err := validation.requirementRecord(ref.ID)
		if err != nil {
			return &CompileError{Stage: StageRequirement, Path: path, Err: err}
		}
		if record.Level != ref.Level {
			return &CompileError{Stage: StageRequirement, Path: path, Err: fmt.Errorf("level %s does not match catalog %s", ref.Level, record.Level)}
		}
		validation.requirements[record.ID] = record
	}
	return nil
}

func (validation *scenarioValidation) requirementRecord(id string) (RequirementRecord, error) {
	record, exists := validation.options.Requirements[id]
	if !exists {
		return RequirementRecord{}, fmt.Errorf("requirement %q is absent from the supplied catalog", id)
	}
	if record.ID != id {
		return RequirementRecord{}, fmt.Errorf("catalog key %q is bound to record %q", id, record.ID)
	}
	if !slices.Contains([]RequirementLevel{LevelMust, LevelShould, LevelMay}, record.Level) {
		return RequirementRecord{}, fmt.Errorf("requirement %q has invalid level %q", id, record.Level)
	}
	if !slices.Contains([]ScenarioClass{ClassNormative, ClassDeFactoClient, ClassConsumerProfile, ClassBehavioral, ClassAdvisory}, record.Category) {
		return RequirementRecord{}, fmt.Errorf("requirement %q has invalid category %q", id, record.Category)
	}
	if err := record.SourceDigest.Validate(); err != nil {
		return RequirementRecord{}, fmt.Errorf("requirement %q source digest: %w", id, err)
	}
	return record, nil
}

func (validation *scenarioValidation) indexResources(resources []ResourceLease, classification Classification) error {
	for index, resource := range resources {
		path := fmt.Sprintf("$.spec.resources[%d]", index)
		if !resourceNamePattern.MatchString(resource.ID) {
			return semanticError(path+".id", "invalid resource ID")
		}
		if _, duplicate := validation.resources[resource.ID]; duplicate {
			return semanticError(path+".id", fmt.Sprintf("duplicate resource %q", resource.ID))
		}
		if !slices.Contains([]SideEffectClass{SideEffectNone, SideEffectReversibleLocal, SideEffectReversibleRemote, SideEffectIrreversible}, resource.SideEffectClass) {
			return semanticError(path+".sideEffectClass", "invalid side effect class")
		}
		if classification.Stability == StabilityStable && resource.SideEffectClass == SideEffectIrreversible {
			return semanticError(path+".sideEffectClass", "stable scenarios cannot lease irreversible resources")
		}
		if !artifactNamePattern.MatchString(resource.Finalizer.Operation) {
			return semanticError(path+".finalizer.operation", "invalid finalizer operation")
		}
		if resource.Finalizer.Idempotent == nil || !*resource.Finalizer.Idempotent {
			return semanticError(path+".finalizer.idempotent", "finalizer must explicitly be idempotent")
		}
		if resource.Finalizer.Retry.MaxAttempts <= 0 || resource.Finalizer.Retry.MaxAttempts > 10 {
			return semanticError(path+".finalizer.retry.maxAttempts", "retry count must be between 1 and 10")
		}
		if resource.CleanupBudget.Requests <= 0 {
			return semanticError(path+".cleanupBudget.requests", "cleanup request budget must be positive")
		}
		if err := resource.CleanupBudget.Duration.Validate(); err != nil {
			return semanticError(path+".cleanupBudget.duration", err.Error())
		}
		validation.resources[resource.ID] = resource
	}
	if classification.SideEffects == SideEffectNone {
		for _, resource := range resources {
			if resource.SideEffectClass != SideEffectNone {
				return semanticError("$.spec.classification.sideEffects", "none conflicts with a side-effecting resource")
			}
		}
	} else if len(resources) == 0 {
		return semanticError("$.spec.resources", "side-effecting scenarios must declare ResourceLease cleanup")
	}
	return nil
}

func (validation *scenarioValidation) validateSteps(scenario *Scenario) error {
	if len(scenario.Spec.Steps) == 0 {
		return semanticError("$.spec.steps", "at least one step is required")
	}
	for index := range scenario.Spec.Steps {
		step := &scenario.Spec.Steps[index]
		stepPath := fmt.Sprintf("$.spec.steps[%d]", index)
		if !resourceNamePattern.MatchString(step.ID) {
			return semanticError(stepPath+".id", "invalid step ID")
		}
		if _, duplicate := validation.stepIndexes[step.ID]; duplicate {
			return semanticError(stepPath+".id", fmt.Sprintf("duplicate step %q", step.ID))
		}
		if countStepVariants(*step) != 1 {
			return semanticError(stepPath, "step must contain exactly one of the nine supported operations")
		}
		validation.stepIndexes[step.ID] = index
		if err := validation.validateStep(step, index, stepPath, scenario); err != nil {
			return err
		}
	}
	return nil
}

func countStepVariants(step Step) int {
	count := 0
	for _, present := range []bool{
		step.Invoke != nil, step.Capture != nil, step.RegisterResource != nil,
		step.ProvideToolResult != nil, step.WaitFor != nil, step.Assert != nil,
		step.Cancel != nil, step.Replay != nil, step.Finalize != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func (validation *scenarioValidation) validateStep(step *Step, index int, stepPath string, scenario *Scenario) error {
	switch {
	case step.Invoke != nil:
		if !artifactNamePattern.MatchString(step.Invoke.Operation) || !artifactNamePattern.MatchString(step.Invoke.Driver) {
			return semanticError(stepPath+".invoke", "invoke operation and driver must be safe artifact names")
		}
		if step.Invoke.Request == nil {
			return semanticError(stepPath+".invoke.request", "request object is required")
		}
		if step.Invoke.ControlledBackend != nil {
			if err := validation.resolveFixture(step.Invoke.ControlledBackend.Fixture, stepPath+".invoke.controlledBackend.fixture"); err != nil {
				return err
			}
		}
		if err := validation.validateDynamicValue(step.Invoke.Request, stepPath+".invoke.request"); err != nil {
			return err
		}
	case step.Capture != nil:
		if err := validation.requirePreviousReference(step.Capture.Stream, index, stepPath+".capture.stream"); err != nil {
			return err
		}
		if !resourceNamePattern.MatchString(step.Capture.As) {
			return semanticError(stepPath+".capture.as", "invalid capture name")
		}
	case step.RegisterResource != nil:
		if _, exists := validation.resources[step.RegisterResource.Resource]; !exists {
			return semanticError(stepPath+".register_resource.resource", "resource is not declared")
		}
		if err := validation.requirePreviousReference(step.RegisterResource.AcquireFrom, index, stepPath+".register_resource.acquireFrom"); err != nil {
			return err
		}
	case step.ProvideToolResult != nil:
		if err := validation.requirePreviousReference(step.ProvideToolResult.CallIDFrom, index, stepPath+".provide_tool_result.callIdFrom"); err != nil {
			return err
		}
		if err := validation.validateDynamicValue(step.ProvideToolResult.Result, stepPath+".provide_tool_result.result"); err != nil {
			return err
		}
	case step.WaitFor != nil:
		if err := validation.requirePreviousReference(step.WaitFor.Source, index, stepPath+".wait_for.source"); err != nil {
			return err
		}
		if err := step.WaitFor.Timeout.Validate(); err != nil {
			return semanticError(stepPath+".wait_for.timeout", err.Error())
		}
		if step.WaitFor.Timeout.Duration() > scenario.Spec.Budgets.Timeout.Duration() {
			return semanticError(stepPath+".wait_for.timeout", "wait timeout exceeds scenario timeout")
		}
		compiled, err := compileCEL(step.WaitFor.Condition, validation.options.MaxCELCost)
		if err != nil {
			return &CompileError{Stage: StageCEL, Path: stepPath + ".wait_for.condition", Err: err}
		}
		validation.celBindings = append(validation.celBindings, CELBinding{StepID: step.ID, Purpose: "wait_for", Compiled: compiled})
	case step.Assert != nil:
		if len(*step.Assert) == 0 {
			return semanticError(stepPath+".assert", "assert step must contain at least one assertion")
		}
		for assertionIndex := range *step.Assert {
			if err := validation.validateAssertion(step.ID, assertionIndex, &(*step.Assert)[assertionIndex], scenario); err != nil {
				return err
			}
		}
	case step.Cancel != nil:
		if err := validation.requirePreviousReference(step.Cancel.Invocation, index, stepPath+".cancel.invocation"); err != nil {
			return err
		}
		if strings.TrimSpace(step.Cancel.Reason) == "" {
			return semanticError(stepPath+".cancel.reason", "cancel reason is required")
		}
	case step.Replay != nil:
		if err := validation.resolveFixture(step.Replay.Fixture, stepPath+".replay.fixture"); err != nil {
			return err
		}
		if !resourceNamePattern.MatchString(step.Replay.As) {
			return semanticError(stepPath+".replay.as", "invalid replay binding")
		}
	case step.Finalize != nil:
		if _, exists := validation.resources[step.Finalize.Finalize]; !exists {
			return semanticError(stepPath+".finalize.finalize", "resource is not declared")
		}
	}
	return nil
}

func (validation *scenarioValidation) validateAssertion(stepID string, index int, assertion *Assertion, scenario *Scenario) error {
	assertionPath := fmt.Sprintf("$.spec.steps[%d].assert[%d]", validation.stepIndexes[stepID], index)
	if (assertion.Use == "") == (assertion.Expression == "") {
		return semanticError(assertionPath, "assertion requires exactly one of use or expression")
	}
	if assertion.Use != "" && !artifactNamePattern.MatchString(assertion.Use) {
		return semanticError(assertionPath+".use", "invalid oracle assertion name")
	}
	if !slices.Contains([]AssertionRole{RolePrecondition, RoleNormative, RoleConsumerProfile, RoleBehavioral, RoleAdvisory}, assertion.AssertionRole) {
		return semanticError(assertionPath+".assertionRole", "invalid assertion role")
	}
	if assertion.AssertionRole == RolePrecondition {
		if assertion.ObservedAt == "" {
			return semanticError(assertionPath+".observedAt", "precondition requires an explicit observation source")
		}
		if assertion.Requirement != "" {
			return semanticError(assertionPath+".requirement", "precondition cannot claim a target requirement")
		}
	}
	if assertion.AssertionRole == RoleBehavioral && scenario.Spec.Repetition.Count < 2 {
		return semanticError(assertionPath, "behavioral assertion requires repeated samples")
	}
	if err := validation.linkAssertionRequirement(assertion, scenario); err != nil {
		return &CompileError{Stage: StageRequirement, Path: assertionPath + ".requirement", Err: err}
	}
	if len(assertion.Equals) != 0 {
		canonical, err := publicschema.CanonicalizeJSON(assertion.Equals)
		if err != nil {
			return semanticError(assertionPath+".equals", err.Error())
		}
		assertion.Equals = canonical
	}
	if assertion.Expression != "" {
		compiled, err := compileCEL(assertion.Expression, validation.options.MaxCELCost)
		if err != nil {
			return &CompileError{Stage: StageCEL, Path: assertionPath + ".expression", Err: err}
		}
		assertion.Expression = compiled.Source
		assertionIndex := index
		validation.celBindings = append(validation.celBindings, CELBinding{
			StepID: stepID, AssertionIndex: &assertionIndex, Purpose: "assertion", Compiled: compiled,
		})
	}
	return nil
}

func (validation *scenarioValidation) linkAssertionRequirement(assertion *Assertion, scenario *Scenario) error {
	if assertion.AssertionRole == RoleNormative {
		if assertion.Requirement == "" {
			candidates := make([]string, 0)
			for _, ref := range scenario.Spec.Requirements {
				if validation.requirements[ref.ID].Category == ClassNormative {
					candidates = append(candidates, ref.ID)
				}
			}
			if len(candidates) != 1 {
				return errors.New("normative assertion must name a requirement unless exactly one normative requirement is declared")
			}
			assertion.Requirement = candidates[0]
		}
		declared := false
		for _, ref := range scenario.Spec.Requirements {
			if ref.ID == assertion.Requirement {
				declared = true
				break
			}
		}
		if !declared {
			return fmt.Errorf("normative requirement %q is not declared by the scenario", assertion.Requirement)
		}
	}
	if assertion.AssertionRole == RoleConsumerProfile && assertion.Requirement == "" {
		return errors.New("consumer_profile assertion requires an explicit consumer requirement")
	}
	if assertion.Requirement == "" {
		return nil
	}
	record, err := validation.requirementRecord(assertion.Requirement)
	if err != nil {
		return err
	}
	if assertion.AssertionRole == RoleNormative && record.Category != ClassNormative {
		return fmt.Errorf("requirement %q is %s, not normative", record.ID, record.Category)
	}
	if assertion.AssertionRole == RoleConsumerProfile && record.Category != ClassConsumerProfile && record.Category != ClassDeFactoClient {
		return fmt.Errorf("requirement %q is not a consumer/client requirement", record.ID)
	}
	validation.requirements[record.ID] = record
	return nil
}

func (validation *scenarioValidation) validateResourceReferencesAndFinally(scenario *Scenario) error {
	for index, resource := range scenario.Spec.Resources {
		if err := validation.requireAnyStepReference(resource.AcquireFrom, fmt.Sprintf("$.spec.resources[%d].acquireFrom", index)); err != nil {
			return err
		}
	}
	if len(scenario.Spec.Finally) != len(scenario.Spec.Resources) {
		return semanticError("$.spec.finally", "finally must contain every declared resource exactly once in LIFO order")
	}
	for index, finalizer := range scenario.Spec.Finally {
		expected := scenario.Spec.Resources[len(scenario.Spec.Resources)-1-index].ID
		if finalizer.Finalize != expected {
			return semanticError(fmt.Sprintf("$.spec.finally[%d].finalize", index), fmt.Sprintf("expected %q for LIFO cleanup", expected))
		}
	}
	return nil
}

func (validation *scenarioValidation) requirePreviousReference(reference string, currentIndex int, fieldPath string) error {
	name := referenceRoot(reference)
	index, exists := validation.stepIndexes[name]
	if !exists || index >= currentIndex {
		return semanticError(fieldPath, fmt.Sprintf("reference %q must point to an earlier step", reference))
	}
	return nil
}

func (validation *scenarioValidation) requireAnyStepReference(reference, fieldPath string) error {
	if _, exists := validation.stepIndexes[referenceRoot(reference)]; !exists {
		return semanticError(fieldPath, fmt.Sprintf("reference %q does not name a step", reference))
	}
	return nil
}

func referenceRoot(reference string) string {
	root, _, _ := strings.Cut(reference, ".")
	return root
}

func (validation *scenarioValidation) validateDynamicValue(value any, fieldPath string) error {
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return nil
	case string:
		return validation.validateTemplates(typed, fieldPath)
	case []any:
		for index, child := range typed {
			if err := validation.validateDynamicValue(child, fmt.Sprintf("%s[%d]", fieldPath, index)); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			child := typed[key]
			childPath := fieldPath + "." + key
			if key == "fixture" {
				ref, ok := child.(string)
				if !ok {
					return &CompileError{Stage: StageFixture, Path: childPath, Err: errors.New("fixture reference must be a string")}
				}
				if err := validation.resolveFixture(ref, childPath); err != nil {
					return err
				}
			}
			if err := validation.validateDynamicValue(child, childPath); err != nil {
				return err
			}
		}
	default:
		return semanticError(fieldPath, fmt.Sprintf("unsupported dynamic value type %T", value))
	}
	return nil
}

func (validation *scenarioValidation) validateTemplates(value, fieldPath string) error {
	matches := templatePattern.FindAllStringSubmatchIndex(value, -1)
	remainder := templatePattern.ReplaceAllString(value, "")
	if strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
		return semanticError(fieldPath, "malformed template expression")
	}
	variables := make([]string, 0, len(matches))
	for _, match := range matches {
		variable := value[match[2]:match[3]]
		if _, allowed := validation.options.AllowedVariables[variable]; !allowed {
			return semanticError(fieldPath, fmt.Sprintf("template variable %q is not declared", variable))
		}
		variables = append(variables, variable)
	}
	if len(variables) != 0 {
		validation.templateBindings = append(validation.templateBindings, TemplateBinding{Path: fieldPath, Variables: variables})
	}
	return nil
}

func (validation *scenarioValidation) resolveFixture(ref, fieldPath string) error {
	if err := validateSafeRelativePath(ref, false); err != nil {
		return &CompileError{Stage: StageFixture, Path: fieldPath, Err: err}
	}
	digest, exists := validation.options.Fixtures[ref]
	if !exists {
		return &CompileError{Stage: StageFixture, Path: fieldPath, Err: fmt.Errorf("fixture %q is not supplied", ref)}
	}
	if err := digest.Validate(); err != nil {
		return &CompileError{Stage: StageFixture, Path: fieldPath, Err: fmt.Errorf("fixture %q digest: %w", ref, err)}
	}
	validation.fixtures[ref] = digest
	return nil
}

type packValidation struct {
	snapshotDigest publicschema.Digest
	scenarios      []ScenarioPin
}

func validatePack(pack *ProtocolPack, options PackCompileOptions) (*packValidation, error) {
	if pack.APIVersion != PackAPIVersion || pack.Kind != PackKind {
		return nil, semanticError("$", "pack apiVersion/kind mismatch")
	}
	if !artifactNamePattern.MatchString(pack.Metadata.Name) {
		return nil, semanticError("$.metadata.name", "invalid pack name")
	}
	if !calverPattern.MatchString(pack.Metadata.Version) {
		return nil, semanticError("$.metadata.version", "pack version must be YYYY.MM.patch CalVer")
	}
	if !semverPattern.MatchString(pack.Spec.Engine.MinVersion) || pack.Spec.Engine.MaxMajor <= 0 {
		return nil, semanticError("$.spec.engine", "invalid engine version range")
	}
	minimumMajor, _ := strconv.ParseInt(strings.SplitN(pack.Spec.Engine.MinVersion, ".", 2)[0], 10, 64)
	if minimumMajor > pack.Spec.Engine.MaxMajor {
		return nil, semanticError("$.spec.engine.maxMajor", "maxMajor is below minVersion major")
	}
	if err := validateSafeRelativePath(pack.Spec.ProtocolSnapshot.Ref, false); err != nil {
		return nil, &CompileError{Stage: StageFixture, Path: "$.spec.protocolSnapshot.ref", Err: err}
	}
	snapshotDigest, exists := options.ProtocolSnapshots[pack.Spec.ProtocolSnapshot.Ref]
	if !exists {
		return nil, &CompileError{Stage: StageFixture, Path: "$.spec.protocolSnapshot.ref", Err: errors.New("protocol snapshot is not supplied")}
	}
	if err := snapshotDigest.Validate(); err != nil {
		return nil, &CompileError{Stage: StageFixture, Path: "$.spec.protocolSnapshot.ref", Err: err}
	}
	if len(pack.Spec.Scenarios.Include) == 0 {
		return nil, semanticError("$.spec.scenarios.include", "at least one scenario include is required")
	}
	selected := make(map[string]publicschema.Digest)
	seenPatterns := make(map[string]struct{})
	for index, pattern := range pack.Spec.Scenarios.Include {
		fieldPath := fmt.Sprintf("$.spec.scenarios.include[%d]", index)
		if err := validateSafeRelativePath(pattern, true); err != nil {
			return nil, &CompileError{Stage: StageFixture, Path: fieldPath, Err: err}
		}
		if _, duplicate := seenPatterns[pattern]; duplicate {
			return nil, semanticError(fieldPath, fmt.Sprintf("duplicate include pattern %q", pattern))
		}
		seenPatterns[pattern] = struct{}{}
		matched := false
		candidatePaths := make([]string, 0, len(options.ScenarioFiles))
		for scenarioPath := range options.ScenarioFiles {
			candidatePaths = append(candidatePaths, scenarioPath)
		}
		slices.Sort(candidatePaths)
		for _, scenarioPath := range candidatePaths {
			digest := options.ScenarioFiles[scenarioPath]
			if err := validateSafeRelativePath(scenarioPath, false); err != nil {
				return nil, &CompileError{Stage: StageFixture, Path: fieldPath, Err: fmt.Errorf("candidate scenario path %q: %w", scenarioPath, err)}
			}
			if globMatches(pattern, scenarioPath) {
				if err := digest.Validate(); err != nil {
					return nil, &CompileError{Stage: StageFixture, Path: fieldPath, Err: fmt.Errorf("scenario %q digest: %w", scenarioPath, err)}
				}
				selected[scenarioPath] = digest
				matched = true
			}
		}
		if !matched {
			return nil, &CompileError{Stage: StageFixture, Path: fieldPath, Err: fmt.Errorf("pattern %q matched no supplied scenario", pattern)}
		}
	}
	if len(pack.Spec.ConformanceSuites) == 0 {
		return nil, semanticError("$.spec.conformanceSuites", "at least one suite is required")
	}
	suiteNames := make([]string, 0, len(pack.Spec.ConformanceSuites))
	for name := range pack.Spec.ConformanceSuites {
		suiteNames = append(suiteNames, name)
	}
	slices.Sort(suiteNames)
	for _, name := range suiteNames {
		suite := pack.Spec.ConformanceSuites[name]
		if !resourceNamePattern.MatchString(name) || len(suite.Requirements) == 0 {
			return nil, semanticError("$.spec.conformanceSuites", fmt.Sprintf("invalid suite %q", name))
		}
		seen := make(map[string]struct{})
		for _, requirement := range suite.Requirements {
			if !resourceNamePattern.MatchString(requirement) {
				return nil, semanticError("$.spec.conformanceSuites."+name, fmt.Sprintf("invalid requirement selector %q", requirement))
			}
			if _, duplicate := seen[requirement]; duplicate {
				return nil, semanticError("$.spec.conformanceSuites."+name, fmt.Sprintf("duplicate requirement selector %q", requirement))
			}
			seen[requirement] = struct{}{}
		}
	}
	if pack.Spec.DefaultBudget.MaxRequests <= 0 {
		return nil, semanticError("$.spec.defaultBudget.maxRequests", "must be positive")
	}
	if err := pack.Spec.DefaultBudget.MaxDuration.Validate(); err != nil {
		return nil, semanticError("$.spec.defaultBudget.maxDuration", err.Error())
	}
	if pack.Spec.Signing.Digest != "" {
		if err := pack.Spec.Signing.Digest.Validate(); err != nil {
			return nil, semanticError("$.spec.signing.digest", err.Error())
		}
	}
	pins := make([]ScenarioPin, 0, len(selected))
	for scenarioPath, digest := range selected {
		pins = append(pins, ScenarioPin{Path: scenarioPath, Digest: digest})
	}
	slices.SortFunc(pins, func(left, right ScenarioPin) int { return bytes.Compare([]byte(left.Path), []byte(right.Path)) })
	return &packValidation{snapshotDigest: snapshotDigest, scenarios: pins}, nil
}

func validateSafeRelativePath(value string, allowGlob bool) error {
	if value == "" || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return fmt.Errorf("unsafe relative path %q", value)
	}
	if strings.Contains(value, "://") || strings.Contains(value, "{{") || strings.Contains(value, "}}") {
		return fmt.Errorf("path %q cannot be a URL or template", value)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("unsafe path segment in %q", value)
		}
		if !allowGlob && strings.ContainsAny(segment, "*?[]") {
			return fmt.Errorf("fixture path %q cannot contain glob syntax", value)
		}
	}
	if path.Clean(value) != value {
		return fmt.Errorf("path %q is not canonical", value)
	}
	return nil
}

func globMatches(pattern, value string) bool {
	var expression strings.Builder
	expression.WriteByte('^')
	for index := 0; index < len(pattern); {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				index += 2
				if index < len(pattern) && pattern[index] == '/' {
					expression.WriteString("(?:.*/)?")
					index++
				} else {
					expression.WriteString(".*")
				}
			} else {
				expression.WriteString("[^/]*")
				index++
			}
		case '?':
			expression.WriteString("[^/]")
			index++
		default:
			expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
			index++
		}
	}
	expression.WriteByte('$')
	matched, err := regexp.MatchString(expression.String(), value)
	return err == nil && matched
}

func semanticError(fieldPath, message string) *CompileError {
	return &CompileError{Stage: StageSemantic, Path: fieldPath, Err: errors.New(message)}
}
