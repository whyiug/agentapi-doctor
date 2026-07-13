package cli

import (
	"slices"
	"strings"
	"testing"

	agentapidoctor "github.com/whyiug/agentapi-doctor"
	"gopkg.in/yaml.v3"
)

func TestPublishedCLISpecMatchesImplementedCommands(t *testing.T) {
	raw, err := agentapidoctor.ReadAsset("cli/spec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		ExitPrecedence []int `yaml:"exitPrecedence"`
		Commands       []struct {
			Path  []string `yaml:"path"`
			Flags []struct {
				Name string `yaml:"name"`
			} `yaml:"flags"`
		} `yaml:"commands"`
	}
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	wantExitPrecedence := []int{130, 2, 5, 3, 4, 6, 1, 0}
	if !slices.Equal(contract.ExitPrecedence, wantExitPrecedence) {
		t.Fatalf("published exit precedence drifted: got %v, want %v", contract.ExitPrecedence, wantExitPrecedence)
	}
	got := make([]string, 0, len(contract.Commands))
	runInspectFlags := []string{}
	for _, command := range contract.Commands {
		if len(command.Path) == 0 {
			t.Fatal("CLI spec contains an empty command path")
		}
		path := strings.Join(command.Path, " ")
		got = append(got, path)
		if path == "run inspect" {
			for _, flag := range command.Flags {
				runInspectFlags = append(runInspectFlags, flag.Name)
			}
		}
		helpArgs := append(append([]string(nil), command.Path...), "--help")
		code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: t.TempDir()}, helpArgs...)
		if code != ExitSuccess || stderr != "" || !strings.Contains(strings.ToLower(stdout), "usage:") {
			t.Errorf("%s --help failed: code=%d stdout=%q stderr=%q", path, code, stdout, stderr)
		}
	}
	want := []string{
		"baseline accept", "baseline compare", "baseline inspect", "baseline list",
		"compare", "completion", "demo", "init", "report", "reproduce", "run inspect",
		"self-check", "target add", "target inspect", "target list", "test", "version",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("published CLI commands drifted from dispatch:\n got: %v\nwant: %v", got, want)
	}
	if !slices.Contains(runInspectFlags, "include-plan") {
		t.Fatalf("published run inspect flags omit include-plan: %v", runInspectFlags)
	}
	for shell, script := range completionScripts {
		for _, root := range []string{"init", "self-check", "target", "test", "demo", "reproduce", "run", "compare", "baseline", "report", "completion", "version"} {
			if !strings.Contains(script, root) {
				t.Errorf("%s completion omits %s", shell, root)
			}
		}
		for _, future := range []string{"pack", "profile", "replay", "minimize", "publish", "registry", "matrix", "migrate", "phase"} {
			if strings.Contains(script, future) {
				t.Errorf("%s completion advertises unimplemented command %s", shell, future)
			}
		}
	}
}
