package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const maxManifestBytes = 4 << 20

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	xVersionSegment = regexp.MustCompile(`(?i)(^|\.)x($|\.)`)
	zeroDigest      = "sha256:" + strings.Repeat("0", 64)
)

type Summary struct {
	Cells            int `json:"cells"`
	Profiles         int `json:"profiles"`
	Drivers          int `json:"drivers"`
	RuntimeAdapters  int `json:"runtime_adapters"`
	ExternalAdapters int `json:"external_adapters"`
	PassedClaims     int `json:"passed_claims"`
}

type validationErrors struct{ messages []string }

func (validation *validationErrors) add(format string, args ...any) {
	validation.messages = append(validation.messages, fmt.Sprintf(format, args...))
}

func (validation *validationErrors) err() error {
	if len(validation.messages) == 0 {
		return nil
	}
	sort.Strings(validation.messages)
	return errors.New(strings.Join(validation.messages, "\n"))
}

type validator struct {
	root    string
	errors  validationErrors
	schemas map[string]*jsonschema.Schema
	summary Summary
}

type expectedCell struct {
	kind string
	path string
	tier string
}

var expectedCells = map[string]expectedCell{
	"t1.protocol.openai-chat":             {"ProtocolPack", "packs/openai-chat/pack.yaml", "tier1"},
	"t1.protocol.openai-responses-http":   {"ProtocolPack", "packs/openai-responses-http/pack.yaml", "tier1"},
	"t1.protocol.anthropic-messages":      {"ProtocolPack", "packs/anthropic-messages/pack.yaml", "tier1"},
	"t1.profile.openai-python":            {"ConsumerCompatibilityProfile", "profiles/sdk/openai-python/profile.yaml", "tier1"},
	"t1.profile.openai-node":              {"ConsumerCompatibilityProfile", "profiles/sdk/openai-node/profile.yaml", "tier1"},
	"t1.profile.anthropic-python":         {"ConsumerCompatibilityProfile", "profiles/sdk/anthropic-python/profile.yaml", "tier1"},
	"t1.profile.anthropic-node":           {"ConsumerCompatibilityProfile", "profiles/sdk/anthropic-node/profile.yaml", "tier1"},
	"t1.profile.vercel-ai-sdk":            {"ConsumerCompatibilityProfile", "profiles/clients/vercel-ai-sdk/profile.yaml", "tier1"},
	"t1.profile.codex":                    {"ConsumerCompatibilityProfile", "profiles/clients/codex/profile.yaml", "tier1"},
	"t1.profile.openclaw":                 {"ConsumerCompatibilityProfile", "profiles/clients/openclaw/profile.yaml", "tier1"},
	"t1.runtime.vllm":                     {"RuntimeMetadataAdapter", "adapters/runtime-metadata/vllm/adapter.yaml", "tier1"},
	"t1.runtime.llama-cpp":                {"RuntimeMetadataAdapter", "adapters/runtime-metadata/llama-cpp/adapter.yaml", "tier1"},
	"t1.runtime.ollama":                   {"RuntimeMetadataAdapter", "adapters/runtime-metadata/ollama/adapter.yaml", "tier1"},
	"t1.runtime.sglang":                   {"RuntimeMetadataAdapter", "adapters/runtime-metadata/sglang/adapter.yaml", "tier1"},
	"t1.runtime.litellm":                  {"RuntimeMetadataAdapter", "adapters/runtime-metadata/litellm/adapter.yaml", "tier1"},
	"t2.external.open-responses":          {"ExternalSuiteAdapter", "adapters/external-suites/open-responses/adapter.yaml", "tier2"},
	"t2.protocol.google-generate-content": {"ProtocolPack", "packs/extensions/google-generate-content/pack.yaml", "tier2"},
	"t2.protocol.google-interactions":     {"ProtocolPack", "packs/extensions/google-interactions/pack.yaml", "tier2"},
	"t2.protocol.mcp-2025-11-25":          {"ProtocolPack", "packs/extensions/mcp-2025-11-25/pack.yaml", "tier2"},
	"t2.protocol.ollama-native":           {"ProtocolPack", "packs/extensions/ollama-native/pack.yaml", "tier2"},
	"t2.profile.openclaw-ollama-native":   {"ConsumerCompatibilityProfile", "profiles/clients/openclaw/ollama-native.profile.yaml", "tier2"},
}

var expectedProfiles = map[string]string{
	"profiles/sdk/openai-python/profile.yaml":              "openai-python",
	"profiles/sdk/openai-node/profile.yaml":                "openai-node",
	"profiles/sdk/anthropic-python/profile.yaml":           "anthropic-python",
	"profiles/sdk/anthropic-node/profile.yaml":             "anthropic-node",
	"profiles/clients/vercel-ai-sdk/profile.yaml":          "vercel-ai-sdk",
	"profiles/clients/codex/profile.yaml":                  "codex",
	"profiles/clients/openclaw/profile.yaml":               "openclaw",
	"profiles/clients/openclaw/ollama-native.profile.yaml": "openclaw.ollama-native",
}

var expectedDrivers = map[string]string{
	"runners/raw/driver.yaml":    "raw-go",
	"runners/python/driver.yaml": "python-sdk",
	"runners/node/driver.yaml":   "node-sdk",
	"runners/agent/driver.yaml":  "agent-cli",
}

var expectedRuntimeAdapters = map[string]string{
	"adapters/runtime-metadata/vllm/adapter.yaml":      "vllm",
	"adapters/runtime-metadata/llama-cpp/adapter.yaml": "llama-cpp",
	"adapters/runtime-metadata/ollama/adapter.yaml":    "ollama",
	"adapters/runtime-metadata/sglang/adapter.yaml":    "sglang",
	"adapters/runtime-metadata/litellm/adapter.yaml":   "litellm",
}

type expectedReleaseComponent struct {
	kind     string
	maturity string
}

var expectedReleaseComponents = map[string]expectedReleaseComponent{
	"core-cli":                {"CoreCLI", "stable"},
	"tier1-protocol-packs":    {"ProtocolPackSet", "stable"},
	"tier1-consumer-profiles": {"ConsumerProfileSet", "stable"},
	"tier1-runtime-adapters":  {"RuntimeMetadataAdapterSet", "stable"},
	"required-tier2-set":      {"ExperimentalExtensionSet", "experimental"},
	"self-hosted-registry":    {"RegistryDistribution", "stable"},
	"hosted-registry":         {"HostedRegistry", "stable"},
	"hosted-matrix":           {"HostedMatrix", "stable"},
}

var expectedTierGates = map[string][]string{
	"ProtocolPack:tier1": {
		"requirements", "assertionQuality", "taxonomy", "ci", "ownership", "knownGaps", "publicLabel",
	},
	"ProtocolPack:tier2": {
		"requirements", "assertionQuality", "declaredScope", "ci", "ownership", "knownGaps", "publicLabel",
	},
	"ConsumerCompatibilityProfile:tier1": {
		"requirements", "controlledBackend", "clientVersions", "ci", "ownership", "knownGaps", "publicLabel",
	},
	"ConsumerCompatibilityProfile:tier2": {
		"requirements", "controlledBackend", "clientVersions", "ci", "ownership", "knownGaps", "publicLabel",
	},
	"RuntimeMetadataAdapter:tier1": {
		"contract", "fixtures", "ci", "ownership", "knownGaps", "protocolLabelForbidden",
	},
	"ExternalSuiteAdapter:tier2": {
		"upstreamIdentity", "mappingFidelity", "adapterMutants", "ci", "ownership", "knownGaps", "publicLabel",
	},
}

// ValidateRepository verifies policy, path, schema, lock, and synthetic
// contract invariants. It never resolves upstream versions or changes files.
func ValidateRepository(root string) (Summary, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Summary{}, err
	}
	validation := &validator{root: absolute, schemas: make(map[string]*jsonschema.Schema)}
	validation.validate()
	return validation.summary, validation.errors.err()
}

func (validation *validator) validate() {
	validation.validateArtifactInventory()
	var manifest SupportManifest
	manifestOK := validation.decode("support/support-manifest.yaml", "schemas/support/support-manifest.schema.json", &manifest)
	var lock SupportLock
	lockOK := validation.decode("support/support-lock.yaml", "schemas/support/support-lock.schema.json", &lock)
	var release ReleaseComponents
	releaseOK := validation.decode("support/release-components.yaml", "schemas/support/release-components.schema.json", &release)
	if manifestOK {
		validation.validateManifest(&manifest)
	}
	if lockOK && manifestOK {
		validation.validateLock(&lock, &manifest)
	}
	if releaseOK && manifestOK {
		validation.validateRelease(&release, &manifest)
	}
	if manifestOK {
		var validatedLock *SupportLock
		if lockOK {
			validatedLock = &lock
		}
		validation.validateProfiles(&manifest, validatedLock)
		validation.validateDrivers()
		validation.validateRuntimeAdapters()
		validation.validateExternalAdapter()
	}
}

func (validation *validator) decode(relativePath, schemaPath string, destination any) bool {
	raw, err := os.ReadFile(filepath.Join(validation.root, filepath.FromSlash(relativePath)))
	if err != nil {
		validation.errors.add("%s: %v", relativePath, err)
		return false
	}
	if len(raw) > maxManifestBytes {
		validation.errors.add("%s: exceeds %d bytes", relativePath, maxManifestBytes)
		return false
	}
	canonical, err := publicschema.CanonicalizeJSON(raw)
	if err != nil {
		validation.errors.add("%s: strict JSON: %v", relativePath, err)
		return false
	}
	schema, err := validation.loadSchema(schemaPath)
	if err != nil {
		validation.errors.add("%s: schema: %v", relativePath, err)
		return false
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
	if err != nil {
		validation.errors.add("%s: schema projection: %v", relativePath, err)
		return false
	}
	if err := schema.Validate(instance); err != nil {
		validation.errors.add("%s: schema validation: %v", relativePath, err)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		validation.errors.add("%s: strict decode: %v", relativePath, err)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		validation.errors.add("%s: trailing JSON value", relativePath)
		return false
	}
	return true
}

func (validation *validator) loadSchema(relativePath string) (*jsonschema.Schema, error) {
	if compiled := validation.schemas[relativePath]; compiled != nil {
		return compiled, nil
	}
	raw, err := os.ReadFile(filepath.Join(validation.root, filepath.FromSlash(relativePath)))
	if err != nil {
		return nil, err
	}
	if _, err := publicschema.CanonicalizeJSON(raw); err != nil {
		return nil, fmt.Errorf("strict schema JSON: %w", err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	uri := "urn:agentapi-doctor:local-schema:" + strings.ReplaceAll(relativePath, "/", ":")
	if err := compiler.AddResource(uri, document); err != nil {
		return nil, err
	}
	compiled, err := compiler.Compile(uri)
	if err != nil {
		return nil, err
	}
	validation.schemas[relativePath] = compiled
	return compiled, nil
}

func (validation *validator) validateManifest(manifest *SupportManifest) {
	validation.summary.Cells = len(manifest.Cells)
	seenCells := make(map[string]SupportCell)
	seenArtifacts := make(map[string]string)
	for index, cell := range manifest.Cells {
		prefix := fmt.Sprintf("support/support-manifest.yaml cells[%d]", index)
		if _, duplicate := seenCells[cell.ID]; duplicate {
			validation.errors.add("%s: duplicate cell ID %q", prefix, cell.ID)
		}
		seenCells[cell.ID] = cell
		expected, exists := expectedCells[cell.ID]
		if !exists {
			validation.errors.add("%s: undeclared v1.0 cell %q", prefix, cell.ID)
		} else if cell.Artifact.Kind != expected.kind || cell.Artifact.Path != expected.path || cell.Tier != expected.tier {
			validation.errors.add("%s: kind/path/tier mismatch for %s", prefix, cell.ID)
		}
		identity := cell.Artifact.Kind + ":" + cell.Artifact.Name
		if previous, duplicate := seenArtifacts[identity]; duplicate {
			validation.errors.add("%s: artifact identity %s already used by %s", prefix, identity, previous)
		}
		seenArtifacts[identity] = cell.ID
		validation.validateCell(prefix, &cell, manifest.D30Catalog)
	}
	for id := range expectedCells {
		if _, exists := seenCells[id]; !exists {
			validation.errors.add("support/support-manifest.yaml: missing required cell %s", id)
		}
	}
}

func (validation *validator) validateCell(prefix string, cell *SupportCell, d30 map[string]string) {
	if !cell.ReleaseBlocking {
		validation.errors.add("%s: v1.0 required cell must be releaseBlocking", prefix)
	}
	if cell.Ownership.Primary.Role == cell.Ownership.Backup.Role || cell.Ownership.Primary.Role == "" || cell.Ownership.Backup.Role == "" {
		validation.errors.add("%s: primary and backup ownership roles must be nonempty and distinct", prefix)
	}
	if len(cell.Platforms.OS) == 0 || len(cell.Platforms.Arch) == 0 || len(cell.CICadence) == 0 {
		validation.errors.add("%s: OS, arch, and CI cadence are required", prefix)
	}
	if cell.Tier == "tier1" {
		if cell.MaturityTarget != "stable" || cell.KnownGapPolicy != "tier1-no-unresolved-required" || cell.UpdateSLA.Days != 14 {
			validation.errors.add("%s: Tier 1 maturity/gap/SLA policy mismatch", prefix)
		}
		for _, cadence := range []string{"pull_request", "nightly", "release"} {
			if !slices.Contains(cell.CICadence, cadence) {
				validation.errors.add("%s: Tier 1 cell missing %s cadence", prefix, cadence)
			}
		}
	} else if cell.Tier == "tier2" {
		if cell.MaturityTarget != "experimental" || cell.KnownGapPolicy != "tier2-publish-all-gaps" || cell.UpdateSLA.Days != 30 {
			validation.errors.add("%s: Tier 2 maturity/gap/SLA policy mismatch", prefix)
		}
		for _, cadence := range []string{"nightly", "release"} {
			if !slices.Contains(cell.CICadence, cadence) {
				validation.errors.add("%s: Tier 2 cell missing %s cadence", prefix, cadence)
			}
		}
	}
	if !cell.VersionPolicy.ExactResolutionRequired {
		validation.errors.add("%s: exact support-lock resolution must be required", prefix)
	}
	gatePolicy := cell.Artifact.Kind + ":" + cell.Tier
	wantGates, exists := expectedTierGates[gatePolicy]
	if !exists {
		validation.errors.add("%s: no tier applicability policy for %s", prefix, gatePolicy)
	} else if !sameStrings(mapKeys(cell.TierGates), wantGates) {
		validation.errors.add("%s: tier gates do not match applicability policy for %s", prefix, gatePolicy)
	}
	switch cell.Artifact.Kind {
	case "ConsumerCompatibilityProfile":
		if cell.VersionPolicy.Applicability != "required" {
			validation.errors.add("%s: consumer version applicability must be required", prefix)
		}
		want := []string{"current", "previous", "candidate"}
		if cell.Tier == "tier2" {
			want = []string{"exact-experimental"}
		}
		if !sameStrings(cell.VersionPolicy.Selectors, want) {
			validation.errors.add("%s: wrong version selectors", prefix)
		}
	case "ProtocolPack", "ExternalSuiteAdapter", "RuntimeMetadataAdapter":
		if cell.VersionPolicy.Applicability != "not_applicable" || len(cell.VersionPolicy.Selectors) != 0 {
			validation.errors.add("%s: client version row must be not_applicable with no selectors", prefix)
		}
	}
	if err := validateKindPath(cell.Artifact.Kind, cell.Artifact.Path); err != nil {
		validation.errors.add("%s: %v", prefix, err)
	}
	for _, criterion := range cell.D30Criteria {
		if _, exists := d30[criterion]; !exists {
			validation.errors.add("%s: unknown D30 criterion %s", prefix, criterion)
		}
	}
	for gate, status := range cell.TierGates {
		if status == "passed" {
			validation.summary.PassedClaims++
		}
		if status != "pending" && status != "passed" {
			validation.errors.add("%s: gate %s has invalid status %s", prefix, gate, status)
		}
	}
	if cell.Ownership.Primary.Status != "assigned" || cell.Ownership.Backup.Status != "assigned" {
		if cell.TierGates["ownership"] != "pending" {
			validation.errors.add("%s: ownership gate cannot pass while role assignments are pending", prefix)
		}
	}
}

func (validation *validator) validateArtifactInventory() {
	validation.validateInventory("profiles", expectedProfiles, func(relative string) bool {
		return strings.HasSuffix(relative, "/profile.yaml") || strings.HasSuffix(relative, ".profile.yaml")
	})
	validation.validateInventory("runners", expectedDrivers, func(relative string) bool {
		return strings.HasSuffix(relative, "/driver.yaml")
	})
	validation.validateInventory("adapters/runtime-metadata", expectedRuntimeAdapters, func(relative string) bool {
		return strings.HasSuffix(relative, "/adapter.yaml")
	})
	validation.validateInventory("adapters/external-suites", map[string]string{
		"adapters/external-suites/open-responses/adapter.yaml": "open-responses",
	}, func(relative string) bool {
		return strings.HasSuffix(relative, "/adapter.yaml")
	})
}

func (validation *validator) validateInventory(directory string, expected map[string]string, isManifest func(string) bool) {
	root := filepath.Join(validation.root, filepath.FromSlash(directory))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(validation.root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !isManifest(relative) {
			return nil
		}
		if _, exists := expected[relative]; !exists {
			validation.errors.add("%s: manifest is not declared in the v1.0 artifact inventory", relative)
		}
		return nil
	})
	if err != nil {
		validation.errors.add("%s: inventory scan: %v", directory, err)
	}
}

func (validation *validator) validateLock(lock *SupportLock, manifest *SupportManifest) {
	manifestCells := make(map[string]SupportCell, len(manifest.Cells))
	for _, cell := range manifest.Cells {
		manifestCells[cell.ID] = cell
	}
	seen := make(map[string]struct{})
	lockByID := make(map[string]LockCell)
	for index, cell := range lock.Cells {
		prefix := fmt.Sprintf("support/support-lock.yaml cells[%d]", index)
		if _, duplicate := seen[cell.CellID]; duplicate {
			validation.errors.add("%s: duplicate lock cell %s", prefix, cell.CellID)
		}
		seen[cell.CellID] = struct{}{}
		manifestCell, exists := manifestCells[cell.CellID]
		if !exists {
			validation.errors.add("%s: cell is absent from support manifest", prefix)
			continue
		}
		lockByID[cell.CellID] = cell
		validation.validateLockCell(prefix, &cell, &manifestCell)
	}
	for id := range manifestCells {
		if _, exists := seen[id]; !exists {
			validation.errors.add("support/support-lock.yaml: missing cell %s", id)
		}
	}
	manifestRaw, err := os.ReadFile(filepath.Join(validation.root, "support", "support-manifest.yaml"))
	if err == nil {
		canonical, canonicalErr := publicschema.CanonicalizeJSON(manifestRaw)
		if canonicalErr == nil {
			actual := string(publicschema.NewDigest(canonical))
			if lock.SupportManifestDigest != nil && *lock.SupportManifestDigest != actual {
				validation.errors.add("support/support-lock.yaml: supportManifestDigest mismatch")
			}
			if lock.LockStatus == "resolved" && lock.SupportManifestDigest == nil {
				validation.errors.add("support/support-lock.yaml: resolved lock requires supportManifestDigest %s", actual)
			}
		}
	}
	for _, manifestCell := range manifest.Cells {
		locked := lockByID[manifestCell.ID]
		if hasPassedGate(manifestCell.TierGates) && (locked.Status != "resolved" || locked.GateStatus != "passed" || len(locked.EvidenceRefs) == 0) {
			validation.errors.add("support/support-manifest.yaml: %s has passed gate without resolved evidenced lock", manifestCell.ID)
		}
	}
}

func (validation *validator) validateLockCell(prefix string, lock *LockCell, manifest *SupportCell) {
	if !sameStrings(slotNames(lock.VersionSlots), manifest.VersionPolicy.Selectors) {
		validation.errors.add("%s: version slots do not match manifest selectors", prefix)
	}
	if lock.Status == "unresolved" {
		if lock.ArtifactVersion != nil || lock.ArtifactDigest != nil || lock.DenominatorDigest != nil || len(lock.EvidenceRefs) != 0 || lock.GateStatus != "pending" {
			validation.errors.add("%s: unresolved cell must not contain exact identity, evidence, or passed gate", prefix)
		}
		for _, slot := range lock.VersionSlots {
			validation.validateUnresolvedSlot(prefix, &slot)
		}
		return
	}
	if lock.Status != "resolved" {
		validation.errors.add("%s: invalid lock status %s", prefix, lock.Status)
		return
	}
	if lock.ArtifactVersion == nil || isFloating(*lock.ArtifactVersion) || !validDigestPointer(lock.ArtifactDigest) || len(lock.EvidenceRefs) == 0 || lock.GateStatus != "passed" {
		validation.errors.add("%s: resolved cell requires exact non-floating artifact identity, evidence, and passed gate", prefix)
	}
	if manifest.Artifact.Kind == "ProtocolPack" || manifest.Artifact.Kind == "ConsumerCompatibilityProfile" {
		if !validDigestPointer(lock.DenominatorDigest) {
			validation.errors.add("%s: resolved pack/profile requires denominator digest", prefix)
		}
	}
	for _, slot := range lock.VersionSlots {
		if slot.Slot == "candidate" && slot.Status == "unresolved" {
			validation.validateUnresolvedSlot(prefix, &slot)
			continue
		}
		if slot.Status != "resolved" || slot.ExactVersion == nil || isFloating(*slot.ExactVersion) || slot.RuntimeVersion == nil || isFloating(*slot.RuntimeVersion) || !validDigestPointer(slot.LockfileDigest) || (!validDigestPointer(slot.PackageDigest) && !validDigestPointer(slot.ImageDigest)) || len(slot.EvidenceRefs) == 0 {
			validation.errors.add("%s: resolved version slot %s lacks exact version/runtime/digests/evidence", prefix, slot.Slot)
		}
	}
}

func (validation *validator) validateUnresolvedSlot(prefix string, slot *VersionSlot) {
	if slot.Status != "unresolved" || slot.ExactVersion != nil || slot.PackageDigest != nil || slot.RuntimeVersion != nil || slot.ImageDigest != nil || slot.LockfileDigest != nil || len(slot.EvidenceRefs) != 0 {
		validation.errors.add("%s: unresolved slot %s must contain no claimed exact facts", prefix, slot.Slot)
	}
}

func (validation *validator) validateRelease(release *ReleaseComponents, manifest *SupportManifest) {
	seen := make(map[string]struct{})
	for index, component := range release.Components {
		prefix := fmt.Sprintf("support/release-components.yaml components[%d]", index)
		if _, duplicate := seen[component.ID]; duplicate {
			validation.errors.add("%s: duplicate component %s", prefix, component.ID)
		}
		seen[component.ID] = struct{}{}
		expected, exists := expectedReleaseComponents[component.ID]
		if !exists {
			validation.errors.add("%s: unexpected component %s", prefix, component.ID)
		} else if component.Kind != expected.kind || component.TargetMaturity != expected.maturity {
			validation.errors.add("%s: kind or target maturity does not match release scope", prefix)
		}
		if !component.Required {
			validation.errors.add("%s: v1.0 component must remain required", prefix)
		}
		if component.Status == "passed" {
			validation.summary.PassedClaims++
			validation.errors.add("%s: passed release claim has no evidence field in this candidate contract", prefix)
		}
		for _, criterion := range component.D30Criteria {
			if _, exists := manifest.D30Catalog[criterion]; !exists && criterion != "D30-PHASE-STATUS" && criterion != "D30-GA-VOTE" {
				validation.errors.add("%s: unknown D30 criterion %s", prefix, criterion)
			}
		}
	}
	for id := range expectedReleaseComponents {
		if _, exists := seen[id]; !exists {
			validation.errors.add("support/release-components.yaml: missing component %s", id)
		}
	}
}

func (validation *validator) validateProfiles(manifest *SupportManifest, lock *SupportLock) {
	supportProfiles := make(map[string]SupportCell)
	for _, cell := range manifest.Cells {
		if cell.Artifact.Kind == "ConsumerCompatibilityProfile" {
			supportProfiles[cell.Artifact.Path] = cell
		}
	}
	lockCells := make(map[string]LockCell)
	if lock != nil {
		for _, cell := range lock.Cells {
			lockCells[cell.CellID] = cell
		}
	}
	for profilePath, expectedID := range expectedProfiles {
		var profile ConsumerProfile
		if !validation.decode(profilePath, "schemas/profile/consumer-compatibility-profile.schema.json", &profile) {
			continue
		}
		validation.summary.Profiles++
		if profile.Metadata.ID != expectedID {
			validation.errors.add("%s: metadata ID %s does not match path identity %s", profilePath, profile.Metadata.ID, expectedID)
		}
		cell, exists := supportProfiles[profilePath]
		if !exists || cell.Artifact.Name != profile.Metadata.ID {
			validation.errors.add("%s: no matching support-manifest profile cell", profilePath)
		}
		if profile.Spec.Consumer.UpstreamVersionResolution == "unresolved" {
			if len(profile.Spec.Consumer.ExactVersions) != 0 {
				validation.errors.add("%s: unresolved consumer cannot claim exact versions", profilePath)
			}
		} else if profile.Spec.Consumer.UpstreamVersionResolution == "resolved" && len(profile.Spec.Consumer.ExactVersions) == 0 {
			validation.errors.add("%s: resolved consumer requires exact versions", profilePath)
		}
		for _, version := range profile.Spec.Consumer.ExactVersions {
			if isFloating(version) {
				validation.errors.add("%s: floating consumer version %q", profilePath, version)
			}
		}
		if profile.Spec.SupportGate.Status == "passed" {
			validation.summary.PassedClaims++
			if len(profile.Spec.SupportGate.EvidenceRefs) == 0 {
				validation.errors.add("%s: passed profile gate lacks evidence", profilePath)
			}
			locked := lockCells[cell.ID]
			if !allGatesPassed(cell.TierGates) || locked.Status != "resolved" || locked.GateStatus != "passed" || len(locked.EvidenceRefs) == 0 {
				validation.errors.add("%s: passed profile gate requires all manifest gates and its support-lock cell to be resolved with evidence", profilePath)
			}
		}
		if profile.Spec.SupportGate.Status == "pending" && len(profile.Spec.SupportGate.EvidenceRefs) != 0 {
			validation.errors.add("%s: pending profile gate must not imply verification evidence", profilePath)
		}
		if !safeRelative(profile.Spec.DriverRef) {
			validation.errors.add("%s: unsafe driverRef %q", profilePath, profile.Spec.DriverRef)
		} else if _, err := os.Stat(filepath.Join(validation.root, filepath.FromSlash(profile.Spec.DriverRef))); err != nil {
			validation.errors.add("%s: driverRef %q does not exist", profilePath, profile.Spec.DriverRef)
		}
		if profile.Metadata.ID == "codex" {
			if !sameStrings(profile.Spec.ProtocolPacks, []string{"openai-responses-http"}) || slices.Contains(profile.Spec.APITypes, "openai-chat") || !slices.Contains(profile.Spec.ForbiddenFallbacks, "openai-chat") {
				validation.errors.add("%s: Codex must remain Responses-only with Chat fallback forbidden", profilePath)
			}
		}
		if profile.Metadata.ID == "openclaw" {
			for _, excluded := range []string{"ollama-native", "gemini-native", "plugin-provider"} {
				if slices.Contains(profile.Spec.APITypes, excluded) || !slices.Contains(profile.Spec.ExcludedAPITypes, excluded) {
					validation.errors.add("%s: Tier 1 OpenClaw profile must exclude %s", profilePath, excluded)
				}
			}
		}
		if profile.Metadata.ID == "openclaw.ollama-native" && !sameStrings(profile.Spec.APITypes, []string{"ollama-native"}) {
			validation.errors.add("%s: Tier 2 OpenClaw profile must be Ollama-native only", profilePath)
		}
	}
}

func (validation *validator) validateDrivers() {
	for driverPath, expectedID := range expectedDrivers {
		var driver DriverManifest
		if !validation.decode(driverPath, "schemas/support/driver-manifest.schema.json", &driver) {
			continue
		}
		validation.summary.Drivers++
		if driver.Metadata.ID != expectedID {
			validation.errors.add("%s: driver ID mismatch", driverPath)
		}
		execution := &driver.Spec.Execution
		if execution.ResolutionStatus == "unresolved" {
			if execution.ExactRuntimeVersion != nil || execution.ArtifactDigest != nil || execution.LockfileDigest != nil || execution.ImageDigest != nil {
				validation.errors.add("%s: unresolved driver cannot claim exact runtime or digests", driverPath)
			}
		} else if execution.ResolutionStatus == "resolved" {
			if execution.ExactRuntimeVersion == nil || isFloating(*execution.ExactRuntimeVersion) || !validDigestPointer(execution.ArtifactDigest) || !validDigestPointer(execution.LockfileDigest) || !validDigestPointer(execution.ImageDigest) {
				validation.errors.add("%s: resolved driver requires exact runtime and non-placeholder artifact, lockfile, and image digests", driverPath)
			}
		}
		if driver.Spec.Gate.Status != "pending" || len(driver.Spec.Gate.EvidenceRefs) != 0 {
			validation.errors.add("%s: unverified driver gate must remain pending without evidence", driverPath)
		}
	}
}

func (validation *validator) validateRuntimeAdapters() {
	for adapterPath, expectedID := range expectedRuntimeAdapters {
		var adapter RuntimeAdapter
		if !validation.decode(adapterPath, "schemas/support/runtime-metadata-adapter.schema.json", &adapter) {
			continue
		}
		validation.summary.RuntimeAdapters++
		if adapter.Metadata.ID != expectedID || adapter.Spec.Runtime.Name != expectedID {
			validation.errors.add("%s: adapter/runtime identity mismatch", adapterPath)
		}
		if adapter.Spec.Runtime.VersionResolution == "unresolved" {
			if len(adapter.Spec.Runtime.ExactVersions) != 0 {
				validation.errors.add("%s: unresolved runtime adapter cannot claim exact versions", adapterPath)
			}
		} else if adapter.Spec.Runtime.VersionResolution == "resolved" && len(adapter.Spec.Runtime.ExactVersions) == 0 {
			validation.errors.add("%s: resolved runtime adapter requires exact versions", adapterPath)
		}
		for _, version := range adapter.Spec.Runtime.ExactVersions {
			if isFloating(version) {
				validation.errors.add("%s: floating runtime version %q", adapterPath, version)
			}
		}
		if adapter.Spec.Behavior.SendsClientRequests || adapter.Spec.Behavior.ModifiesNormativeTruth || adapter.Spec.Behavior.ProtocolConformanceLabel {
			validation.errors.add("%s: metadata adapter crossed its non-normative boundary", adapterPath)
		}
		if adapter.Spec.Gate.Status != "pending" || len(adapter.Spec.Gate.EvidenceRefs) != 0 {
			validation.errors.add("%s: unverified adapter gate must remain pending without evidence", adapterPath)
		}
		adapterDirectory := filepath.ToSlash(filepath.Dir(adapterPath))
		if adapter.Spec.FixtureContract.Valid != adapterDirectory+"/fixtures/valid.json" || adapter.Spec.FixtureContract.Invalid != adapterDirectory+"/fixtures/invalid.json" ||
			!sameStrings(adapter.Spec.FixtureContract.RequiredFields, []string{"synthetic", "runtime", "reportedVersion", "configuration"}) ||
			!sameStrings(adapter.Spec.FixtureContract.ForbiddenFields, []string{"authorization", "apiKey", "token", "cookie", "secret"}) {
			validation.errors.add("%s: fixture contract paths or required/forbidden fields were weakened", adapterPath)
		}
		validFixtureOK := validation.runtimeFixturePasses(adapter.Spec.FixtureContract.Valid, &adapter)
		invalidFixtureOK := validation.runtimeFixturePasses(adapter.Spec.FixtureContract.Invalid, &adapter)
		if !validFixtureOK {
			validation.errors.add("%s: declared valid synthetic fixture fails its contract", adapterPath)
		}
		if invalidFixtureOK {
			validation.errors.add("%s: declared invalid synthetic fixture unexpectedly passes", adapterPath)
		}
	}
}

func (validation *validator) runtimeFixturePasses(relativePath string, adapter *RuntimeAdapter) bool {
	if !safeRelative(relativePath) {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(validation.root, filepath.FromSlash(relativePath)))
	if err != nil {
		return false
	}
	canonical, err := publicschema.CanonicalizeJSON(raw)
	if err != nil {
		return false
	}
	var fixture map[string]any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&fixture); err != nil {
		return false
	}
	for _, required := range adapter.Spec.FixtureContract.RequiredFields {
		if _, exists := fixture[required]; !exists {
			return false
		}
	}
	if synthetic, ok := fixture["synthetic"].(bool); !ok || !synthetic {
		return false
	}
	if runtimeName, ok := fixture["runtime"].(string); !ok || runtimeName != adapter.Metadata.ID {
		return false
	}
	if configuration, ok := fixture["configuration"].(map[string]any); !ok || len(configuration) == 0 {
		return false
	}
	forbidden := make(map[string]struct{})
	for _, field := range adapter.Spec.FixtureContract.ForbiddenFields {
		forbidden[strings.ToLower(field)] = struct{}{}
	}
	return !containsForbiddenField(fixture, forbidden)
}

func (validation *validator) validateExternalAdapter() {
	const adapterPath = "adapters/external-suites/open-responses/adapter.yaml"
	var adapter ExternalAdapter
	if !validation.decode(adapterPath, "schemas/support/external-suite-adapter.schema.json", &adapter) {
		return
	}
	validation.summary.ExternalAdapters++
	upstream := &adapter.Spec.Upstream
	if upstream.ResolutionStatus == "unresolved" {
		if upstream.ExactVersion != nil || upstream.SourceDigest != nil || upstream.LicenseStatus != "review-pending" {
			validation.errors.add("%s: unresolved upstream cannot claim exact version/digest/license", adapterPath)
		}
	} else if upstream.ResolutionStatus == "resolved" {
		if upstream.ExactVersion == nil || isFloating(*upstream.ExactVersion) || !validDigestPointer(upstream.SourceDigest) || upstream.LicenseStatus != "verified" {
			validation.errors.add("%s: resolved upstream requires exact non-floating version, source digest, and verified license", adapterPath)
		}
	}
	run := &adapter.Spec.RunEvidence
	if run.Status == "not-run" {
		if run.ResultDigest != nil || len(run.EvidenceRefs) != 0 {
			validation.errors.add("%s: not-run adapter cannot contain result evidence", adapterPath)
		}
	} else if run.Status == "verified" {
		if upstream.ResolutionStatus != "resolved" || !validDigestPointer(run.ResultDigest) || len(run.EvidenceRefs) == 0 {
			validation.errors.add("%s: verified run requires resolved upstream, non-placeholder result digest, and evidence", adapterPath)
		}
	}
	if adapter.Spec.Gate.Status == "pending" {
		if len(adapter.Spec.Gate.EvidenceRefs) != 0 {
			validation.errors.add("%s: pending external adapter gate cannot contain evidence", adapterPath)
		}
	} else if adapter.Spec.Gate.Status == "passed" {
		validation.summary.PassedClaims++
		if run.Status != "verified" || len(adapter.Spec.Gate.EvidenceRefs) == 0 {
			validation.errors.add("%s: passed external adapter gate requires a verified evidenced run", adapterPath)
		}
	}
	if adapter.Spec.Interface.InputSchema != "urn:agentapi-doctor:external-suite-input:v1" || adapter.Spec.Interface.OutputSchema != "urn:agentapi-doctor:external-suite-output:v1" {
		validation.errors.add("%s: external-suite input/output interface identifiers must remain fixed", adapterPath)
	}
	parsed, err := url.Parse(adapter.Spec.Upstream.Repository)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" {
		validation.errors.add("%s: upstream repository must be the declared HTTPS GitHub source", adapterPath)
	}
}

func validateKindPath(kind, artifactPath string) error {
	if !safeRelative(artifactPath) {
		return fmt.Errorf("unsafe artifact path %q", artifactPath)
	}
	switch kind {
	case "ProtocolPack":
		if !strings.HasPrefix(artifactPath, "packs/") || !strings.HasSuffix(artifactPath, "/pack.yaml") {
			return errors.New("ProtocolPack must live only under packs/**/pack.yaml")
		}
	case "ConsumerCompatibilityProfile":
		if !strings.HasPrefix(artifactPath, "profiles/sdk/") && !strings.HasPrefix(artifactPath, "profiles/clients/") {
			return errors.New("ConsumerCompatibilityProfile must live under profiles/sdk or profiles/clients")
		}
	case "ExternalSuiteAdapter":
		if !strings.HasPrefix(artifactPath, "adapters/external-suites/") {
			return errors.New("ExternalSuiteAdapter must live under adapters/external-suites")
		}
	case "RuntimeMetadataAdapter":
		if !strings.HasPrefix(artifactPath, "adapters/runtime-metadata/") {
			return errors.New("RuntimeMetadataAdapter must live under adapters/runtime-metadata")
		}
	default:
		return fmt.Errorf("unknown artifact kind %q", kind)
	}
	return nil
}

func safeRelative(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && !strings.HasPrefix(clean, "../")
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := slices.Clone(left), slices.Clone(right)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func slotNames(slots []VersionSlot) []string {
	values := make([]string, len(slots))
	for index, slot := range slots {
		values[index] = slot.Slot
	}
	return values
}

func isFloating(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || strings.ContainsAny(normalized, "*<>=~^") || xVersionSegment.MatchString(normalized) {
		return true
	}
	for _, floating := range []string{
		"latest", "current", "previous", "candidate", "unresolved", "main", "master", "head",
		"next", "canary", "nightly", "snapshot", "stable", "edge", "tip", "trunk",
	} {
		if normalized == floating {
			return true
		}
	}
	return false
}

func validDigestPointer(value *string) bool {
	return value != nil && digestPattern.MatchString(*value) && *value != zeroDigest && !strings.Contains(*value, "placeholder")
}

func hasPassedGate(gates map[string]string) bool {
	for _, status := range gates {
		if status == "passed" {
			return true
		}
	}
	return false
}

func allGatesPassed(gates map[string]string) bool {
	if len(gates) == 0 {
		return false
	}
	for _, status := range gates {
		if status != "passed" {
			return false
		}
	}
	return true
}

func containsForbiddenField(value any, forbidden map[string]struct{}) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, exists := forbidden[strings.ToLower(key)]; exists || containsForbiddenField(child, forbidden) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsForbiddenField(child, forbidden) {
				return true
			}
		}
	}
	return false
}
