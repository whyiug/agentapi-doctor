package packapi

import (
	"strings"
	"testing"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestStrictYAMLAndSchemaMutantsFailClosed(t *testing.T) {
	mutants := []struct {
		name  string
		yaml  string
		stage CompileStage
	}{
		{
			name:  "duplicate field",
			yaml:  strings.Replace(validScenarioYAML, "  version: 1.2.0\n", "  version: 1.2.0\n  version: 1.2.1\n", 1),
			stage: StageParse,
		},
		{
			name:  "unknown root field",
			yaml:  validScenarioYAML + "unknown: true\n",
			stage: StageSchema,
		},
		{
			name:  "unknown nested field",
			yaml:  strings.Replace(validScenarioYAML, "    idempotent: true\n", "    idempotent: true\n    typo: true\n", 1),
			stage: StageSchema,
		},
		{
			name:  "YAML anchor",
			yaml:  strings.Replace(validScenarioYAML, "metadata:\n", "metadata: &shared\n", 1),
			stage: StageParse,
		},
		{
			name:  "multiple documents",
			yaml:  validScenarioYAML + "---\n{}\n",
			stage: StageParse,
		},
		{
			name:  "implicit timestamp",
			yaml:  strings.Replace(validScenarioYAML, "  title: Two scripted calls preserve their evidence links", "  title: 2026-07-10", 1),
			stage: StageParse,
		},
		{
			name:  "unsupported shell step",
			yaml:  strings.Replace(validScenarioYAML, "      invoke:\n", "      shell:\n", 1),
			stage: StageSchema,
		},
		{
			name: "two step variants",
			yaml: strings.Replace(validScenarioYAML,
				"          stream: true\n          tools:",
				"          stream: true\n      capture:\n        stream: create.stream\n        as: illegal-second-tag\n      invoke_extra:\n        tools:", 1),
			stage: StageSchema,
		},
		{
			name:  "noncanonical duration",
			yaml:  strings.Replace(validScenarioYAML, "    timeout: 45s", "    timeout: 45000ms", 1),
			stage: StageSchema,
		},
		{
			name:  "noncanonical binary size",
			yaml:  strings.Replace(validScenarioYAML, "    maxArtifactBytes: 16MiB", "    maxArtifactBytes: 016MiB", 1),
			stage: StageSchema,
		},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			_, err := CompileScenarioYAML([]byte(mutant.yaml), validCompileOptions())
			if err == nil || !IsCompileStage(err, mutant.stage) {
				t.Fatalf("want %s rejection, got %v", mutant.stage, err)
			}
		})
	}
}

func TestTargetedSemanticMutantsFailClosed(t *testing.T) {
	type mutant struct {
		name    string
		yaml    string
		options CompileOptions
		stage   CompileStage
	}
	base := validCompileOptions()
	missingRequirement := validCompileOptions()
	delete(missingRequirement.Requirements, "OAI-RESP-STREAM-FUNC-004")
	wrongLevel := validCompileOptions()
	record := wrongLevel.Requirements["OAI-RESP-STREAM-FUNC-004"]
	record.Level = LevelShould
	wrongLevel.Requirements[record.ID] = record
	missingFixture := validCompileOptions()
	delete(missingFixture.Fixtures, "tools/weather.yaml")
	lowCost := validCompileOptions()
	lowCost.MaxCELCost = 1

	twoRequirements := validCompileOptions()
	twoRequirements.Requirements["OAI-RESP-STREAM-FUNC-005"] = RequirementRecord{
		ID: "OAI-RESP-STREAM-FUNC-005", Level: LevelMust, Category: ClassNormative,
		SourceDigest: publicschema.NewDigest([]byte("second-source")),
	}
	secondRequirementYAML := strings.Replace(validScenarioYAML,
		"    - id: OAI-RESP-STREAM-FUNC-004\n      level: MUST\n",
		"    - id: OAI-RESP-STREAM-FUNC-004\n      level: MUST\n    - id: OAI-RESP-STREAM-FUNC-005\n      level: MUST\n", 1)

	mutants := []mutant{
		{name: "invalid SemVer", yaml: strings.Replace(validScenarioYAML, "version: 1.2.0", "version: latest", 1), options: base, stage: StageSemantic},
		{name: "missing catalog requirement", yaml: validScenarioYAML, options: missingRequirement, stage: StageRequirement},
		{name: "catalog level mismatch", yaml: validScenarioYAML, options: wrongLevel, stage: StageRequirement},
		{name: "unresolved fixture", yaml: validScenarioYAML, options: missingFixture, stage: StageFixture},
		{name: "fixture traversal", yaml: strings.Replace(validScenarioYAML, "tools/weather.yaml", "../private.yaml", 1), options: base, stage: StageFixture},
		{name: "undeclared template variable", yaml: strings.Replace(validScenarioYAML, "{{ target.model }}", "{{ env.API_KEY }}", 1), options: base, stage: StageSemantic},
		{name: "malformed template", yaml: strings.Replace(validScenarioYAML, "{{ target.model }}", "{{ target.model", 1), options: base, stage: StageSemantic},
		{name: "forward step reference", yaml: strings.Replace(validScenarioYAML, "stream: create.stream", "stream: cleanup.stream", 1), options: base, stage: StageSemantic},
		{name: "duplicate step ID", yaml: strings.Replace(validScenarioYAML, "    - id: collect", "    - id: create", 1), options: base, stage: StageSemantic},
		{name: "behavioral without repetition", yaml: strings.Replace(validScenarioYAML, "count: 3", "count: 1", 1), options: base, stage: StageSemantic},
		{name: "CEL not boolean", yaml: strings.Replace(validScenarioYAML, "actual == expected", "actual", 1), options: base, stage: StageCEL},
		{name: "CEL I/O function", yaml: strings.Replace(validScenarioYAML, "actual == expected", `read_file("/tmp/x") == ""`, 1), options: base, stage: StageCEL},
		{name: "CEL dynamic network function", yaml: strings.Replace(validScenarioYAML, "actual == expected", `target.fetch() == true`, 1), options: base, stage: StageCEL},
		{name: "CEL comprehension macro disabled", yaml: strings.Replace(validScenarioYAML, "actual == expected", `"[1, 2].all(x, x > 0)"`, 1), options: base, stage: StageCEL},
		{name: "CEL ambient env unavailable", yaml: strings.Replace(validScenarioYAML, "actual == expected", `env.API_KEY == "x"`, 1), options: base, stage: StageCEL},
		{name: "CEL over cost", yaml: validScenarioYAML, options: lowCost, stage: StageCEL},
		{name: "stable irreversible", yaml: strings.ReplaceAll(validScenarioYAML, "reversible-remote", "irreversible"), options: base, stage: StageSemantic},
		{name: "non-idempotent finalizer", yaml: strings.Replace(validScenarioYAML, "        idempotent: true", "        idempotent: false", 1), options: base, stage: StageSemantic},
		{name: "missing finally", yaml: strings.Replace(validScenarioYAML, "  finally:\n    - finalize: stored-response\n", "", 1), options: base, stage: StageSemantic},
		{name: "wait exceeds scenario", yaml: strings.Replace(validScenarioYAML, "        timeout: 1s", "        timeout: 1m0s", 1), options: base, stage: StageSemantic},
		{name: "consumer assertion without requirement", yaml: strings.Replace(validScenarioYAML, "          requirement: RUNTIME-CONTROLLED-TRANSFORM-001\n", "", 1), options: base, stage: StageRequirement},
		{name: "ambiguous normative linkage", yaml: secondRequirementYAML, options: twoRequirements, stage: StageRequirement},
		{name: "capability in conflicting groups", yaml: strings.Replace(validScenarioYAML, "    all:\n      - streaming", "    all:\n      - streaming\n    none:\n      - streaming", 1), options: base, stage: StageSemantic},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			_, err := CompileScenarioYAML([]byte(mutant.yaml), mutant.options)
			if err == nil || !IsCompileStage(err, mutant.stage) {
				t.Fatalf("want %s rejection, got %v", mutant.stage, err)
			}
		})
	}
}

func TestResourceFinalizersMustBeCompleteLIFO(t *testing.T) {
	secondResource := `    - id: temporary-file
      acquireFrom: replay.file_id
      sideEffectClass: reversible-local
      finalizer:
        operation: files.delete
        idempotent: true
        retry:
          maxAttempts: 2
      cleanupBudget:
        requests: 2
        duration: 5s
`
	withTwo := strings.Replace(validScenarioYAML, "  steps:\n", secondResource+"  steps:\n", 1)
	wrongOrder := strings.Replace(withTwo,
		"  finally:\n    - finalize: stored-response\n",
		"  finally:\n    - finalize: stored-response\n    - finalize: temporary-file\n", 1)
	_, err := CompileScenarioYAML([]byte(wrongOrder), validCompileOptions())
	if err == nil || !IsCompileStage(err, StageSemantic) {
		t.Fatalf("wrong LIFO order accepted: %v", err)
	}
	correct := strings.Replace(withTwo,
		"  finally:\n    - finalize: stored-response\n",
		"  finally:\n    - finalize: temporary-file\n    - finalize: stored-response\n", 1)
	if _, err := CompileScenarioYAML([]byte(correct), validCompileOptions()); err != nil {
		t.Fatalf("correct LIFO order rejected: %v", err)
	}
}

func TestPackMutantsFailClosed(t *testing.T) {
	missingSnapshot := validPackOptions()
	delete(missingSnapshot.ProtocolSnapshots, "specs/openai-responses/2026-07-10.yaml")
	noScenarios := validPackOptions()
	noScenarios.ScenarioFiles = map[string]publicschema.Digest{"other/x.yaml": publicschema.NewDigest([]byte("x"))}
	unsafeCandidate := validPackOptions()
	unsafeCandidate.ScenarioFiles["../escape.yaml"] = publicschema.NewDigest([]byte("escape"))

	mutants := []struct {
		name    string
		yaml    string
		options PackCompileOptions
		stage   CompileStage
	}{
		{name: "unknown field", yaml: strings.Replace(validPackYAML, "    maxMajor: 1", "    maxMajor: 1\n    typo: true", 1), options: validPackOptions(), stage: StageSchema},
		{name: "invalid CalVer", yaml: strings.Replace(validPackYAML, "version: 2026.07.0", "version: 1.0.0", 1), options: validPackOptions(), stage: StageSchema},
		{name: "unsafe include", yaml: strings.Replace(validPackYAML, "scenarios/**/*.yaml", "../**/*.yaml", 1), options: validPackOptions(), stage: StageFixture},
		{name: "duplicate include", yaml: strings.Replace(validPackYAML, "      - scenarios/**/*.yaml", "      - scenarios/**/*.yaml\n      - scenarios/**/*.yaml", 1), options: validPackOptions(), stage: StageSemantic},
		{name: "missing snapshot", yaml: validPackYAML, options: missingSnapshot, stage: StageFixture},
		{name: "no matched scenario", yaml: validPackYAML, options: noScenarios, stage: StageFixture},
		{name: "unsafe candidate path", yaml: validPackYAML, options: unsafeCandidate, stage: StageFixture},
		{name: "duplicate suite selector", yaml: strings.Replace(validPackYAML, "        - errors", "        - errors\n        - errors", 1), options: validPackOptions(), stage: StageSemantic},
		{name: "noncanonical duration", yaml: strings.Replace(validPackYAML, "15m0s", "15m", 1), options: validPackOptions(), stage: StageSchema},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			_, err := CompileProtocolPackYAML([]byte(mutant.yaml), mutant.options)
			if err == nil || !IsCompileStage(err, mutant.stage) {
				t.Fatalf("want %s rejection, got %v", mutant.stage, err)
			}
		})
	}
}
