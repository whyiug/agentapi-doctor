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
		Commands []struct {
			Path []string `yaml:"path"`
		} `yaml:"commands"`
	}
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(contract.Commands))
	for _, command := range contract.Commands {
		if len(command.Path) == 0 {
			t.Fatal("CLI spec contains an empty command path")
		}
		got = append(got, strings.Join(command.Path, " "))
	}
	want := []string{
		"baseline accept", "baseline compare", "baseline inspect", "baseline list",
		"compare", "completion", "dev scaffold", "init", "report", "run inspect",
		"self-check", "target add", "target inspect", "target list", "test", "version",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("published CLI commands drifted from dispatch:\n got: %v\nwant: %v", got, want)
	}
	for shell, script := range completionScripts {
		for _, root := range []string{"init", "self-check", "target", "test", "run", "compare", "baseline", "report", "dev", "completion", "version"} {
			if !strings.Contains(script, root) {
				t.Errorf("%s completion omits %s", shell, root)
			}
		}
		for _, future := range []string{"pack", "profile", "replay", "minimize", "repro", "publish", "registry", "matrix", "migrate", "phase"} {
			if strings.Contains(script, future) {
				t.Errorf("%s completion advertises unimplemented command %s", shell, future)
			}
		}
	}
}
