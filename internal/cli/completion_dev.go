package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var scaffoldName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

func runCompletion(args []string, dependencies Dependencies) int {
	if len(args) != 1 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor completion <bash|zsh|fish|powershell>")
	}
	script, ok := completionScripts[args[0]]
	if !ok {
		return writeError(dependencies.Stderr, ExitInput, "invalid_shell", fmt.Sprintf("unsupported shell %q", args[0]))
	}
	_, _ = io.WriteString(dependencies.Stdout, script)
	return ExitSuccess
}

var completionScripts = map[string]string{
	"bash": `_doctor_complete(){ local cur="${COMP_WORDS[COMP_CWORD]}"; COMPREPLY=( $(compgen -W 'init self-check target test demo reproduce run compare baseline report dev completion version' -- "$cur") ); }; complete -F _doctor_complete doctor
`,
	"zsh": `#compdef doctor
_arguments '1:command:(init self-check target test demo reproduce run compare baseline report dev completion version)'
`,
	"fish": `complete -c doctor -f -a 'init self-check target test demo reproduce run compare baseline report dev completion version'
`,
	"powershell": `Register-ArgumentCompleter -Native -CommandName doctor -ScriptBlock { param($wordToComplete) 'init','self-check','target','test','demo','reproduce','run','compare','baseline','report','dev','completion','version' | Where-Object { $_ -like "$wordToComplete*" } }
`,
}

func runDev(args []string, dependencies Dependencies) int {
	if len(args) == 0 {
		return writeError(dependencies.Stderr, ExitInput, "missing_dev_command", "usage: doctor dev scaffold <kind> <name> --output <directory>")
	}
	if args[0] != "scaffold" {
		return writeError(dependencies.Stderr, ExitInput, "unknown_dev_command", fmt.Sprintf("unknown dev command %q", args[0]))
	}
	return runScaffold(args[1:], dependencies)
}

func runScaffold(args []string, dependencies Dependencies) int {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor dev scaffold <requirement|scenario|fixture|profile|driver> <name> --output <directory>")
	}
	kind, name := args[0], args[1]
	template, ok := scaffoldTemplates[kind]
	if !ok {
		return writeError(dependencies.Stderr, ExitInput, "invalid_scaffold_kind", fmt.Sprintf("unsupported scaffold kind %q", kind))
	}
	if !scaffoldName.MatchString(name) {
		return writeError(dependencies.Stderr, ExitInput, "invalid_scaffold_name", "scaffold name must use lowercase letters, digits, dot, underscore, or hyphen")
	}
	flags := flag.NewFlagSet("dev scaffold", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "output directory")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || *output == "" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor dev scaffold <kind> <name> --output <directory>")
	}
	directory := absolutePath(dependencies.WorkingDir, *output)
	filename := filepath.Join(directory, name+".yaml")
	content := strings.ReplaceAll(template, "{{NAME}}", name)
	if err := writeNewFile(filename, []byte(content)); err != nil {
		reason := "scaffold_write_failed"
		code := ExitInfrastructure
		if errors.Is(err, os.ErrExist) {
			reason = "scaffold_exists"
			code = ExitInput
		}
		return writeError(dependencies.Stderr, code, reason, err.Error())
	}
	return writeSuccess(dependencies.Stdout, map[string]string{"kind": kind, "name": name, "path": filename})
}

var scaffoldTemplates = map[string]string{
	"requirement": `schemaVersion: urn:agentapi-doctor:requirement:v1alpha1
id: DRAFT-{{NAME}}
status: draft
level: MUST
classification: normative
source:
  id: replace-with-source-id
  locator: replace-with-stable-locator
statement: Replace with a source-faithful, independently reviewable statement.
`,
	"scenario": `apiVersion: urn:agentapi-doctor:scenario:v1beta1
kind: Scenario
metadata:
  id: {{NAME}}
  version: 0.1.0
  title: Draft {{NAME}}
spec:
  protocol:
    family: replace-with-protocol
    snapshot: replace-with-snapshot
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  classification:
    type: normative
    stability: incubating
    sideEffects: none
    idempotent: true
  requirements:
    - {id: DRAFT-{{NAME}}, level: MUST}
  budgets:
    timeout: 30s
    maxRequests: 1
    maxInputTokens: 1000
    maxOutputTokens: 1000
    maxResponseBytes: 1MiB
    maxArtifactBytes: 2MiB
  steps:
    - id: invoke
      invoke:
        operation: replace-with-operation
        driver: raw-http
        request: {synthetic: true}
    - id: verify
      assert:
        - expression: "true"
          assertionRole: normative
          requirement: DRAFT-{{NAME}}
  publication: {dataClass: synthetic}
`,
	"fixture": `schemaVersion: urn:agentapi-doctor:fixture:v1alpha1
kind: SyntheticFixture
metadata: {name: {{NAME}}, status: draft}
provenance: {origin: synthetic, rights: project-authored}
payload: {}
`,
	"profile": `schemaVersion: urn:agentapi-doctor:consumer-profile:v1alpha1
kind: ConsumerCompatibilityProfile
metadata: {name: {{NAME}}, version: 0.1.0, status: draft}
consumer: {name: replace-with-consumer, constraint: replace-with-exact-range}
requiredPacks: []
`,
	"driver": `schemaVersion: urn:agentapi-doctor:driver-manifest:v1alpha1
kind: Driver
metadata: {name: {{NAME}}, version: 0.1.0, status: draft}
rpc: {minimum: 1.0.0, maximum: 1.0.0}
permissions: []
runtime: {name: replace-with-runtime, version: replace-with-exact-version}
`,
}
