package packapi

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

func TestSafeTemplateExpansionIsLiteralAndBounded(t *testing.T) {
	got, err := ExpandTemplateString("model={{ target.model }}", map[string]string{
		"target.model": "{{ env.API_KEY }};$(ignored)",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "model={{ env.API_KEY }};$(ignored)" {
		t.Fatalf("replacement was reinterpreted: %q", got)
	}
	if _, err := ExpandTemplateString("{{ target.model }}", nil); err == nil {
		t.Fatal("missing variable was accepted")
	}
	if _, err := ExpandTemplateString("{{ target.model", map[string]string{"target.model": "x"}); err == nil {
		t.Fatal("malformed template was accepted")
	}
	if _, err := ExpandTemplateString("{{ target.model }}", map[string]string{
		"target.model": strings.Repeat("x", MaxExpandedTemplateBytes+1),
	}); err == nil {
		t.Fatal("oversized expansion was accepted")
	}
}

func TestCanonicalDigestIndependentOfResolverMapOrder(t *testing.T) {
	baseline, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 128; iteration++ {
		options := CompileOptions{Requirements: make(map[string]RequirementRecord), Fixtures: make(map[string]publicschema.Digest)}
		requirementKeys := []string{"OAI-RESP-STREAM-FUNC-004", "RUNTIME-CONTROLLED-TRANSFORM-001"}
		fixtureKeys := []string{"responses/parallel-two-tools-v1", "tools/weather.yaml", "traces/response.json"}
		if iteration%2 == 1 {
			requirementKeys[0], requirementKeys[1] = requirementKeys[1], requirementKeys[0]
		}
		if iteration%3 == 1 {
			fixtureKeys[0], fixtureKeys[2] = fixtureKeys[2], fixtureKeys[0]
		} else if iteration%3 == 2 {
			fixtureKeys[0], fixtureKeys[1] = fixtureKeys[1], fixtureKeys[0]
		}
		base := validCompileOptions()
		for _, key := range requirementKeys {
			options.Requirements[key] = base.Requirements[key]
		}
		for _, key := range fixtureKeys {
			options.Fixtures[key] = base.Fixtures[key]
		}
		compiled, err := CompileScenarioYAML([]byte(validScenarioYAML), options)
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if compiled.Digest != baseline.Digest || !bytes.Equal(compiled.CanonicalJSON, baseline.CanonicalJSON) {
			t.Fatalf("iteration %d changed deterministic output", iteration)
		}
	}
}

func TestCompilerIsSafeForParallelDeterministicUse(t *testing.T) {
	baseline, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			compiled, err := CompileScenarioYAML([]byte(validScenarioYAML), validCompileOptions())
			if err != nil {
				errorsByWorker <- fmt.Errorf("worker %d: %w", worker, err)
				return
			}
			if compiled.Digest != baseline.Digest || !bytes.Equal(compiled.CanonicalJSON, baseline.CanonicalJSON) {
				errorsByWorker <- fmt.Errorf("worker %d produced divergent output", worker)
			}
		}(worker)
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Error(err)
	}
}

func TestGlobMatcherProperties(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"scenarios/**/*.yaml", "scenarios/core.yaml", true},
		{"scenarios/**/*.yaml", "scenarios/streaming/tools.yaml", true},
		{"scenarios/*.yaml", "scenarios/streaming/tools.yaml", false},
		{"scenarios/?.yaml", "scenarios/a.yaml", true},
		{"scenarios/?.yaml", "scenarios/ab.yaml", false},
		{"*.yaml", "core.yaml", true},
		{"*.yaml", "nested/core.yaml", false},
	}
	for _, test := range tests {
		if got := globMatches(test.pattern, test.path); got != test.want {
			t.Errorf("globMatches(%q, %q)=%v, want %v", test.pattern, test.path, got, test.want)
		}
	}
}

func TestByteSizeCanonicalProperty(t *testing.T) {
	for _, test := range []struct {
		text string
		want ByteSize
	}{
		{"1B", 1},
		{"1KiB", KiB},
		{"16MiB", 16 * MiB},
		{"2GiB", 2 * GiB},
	} {
		got, err := parseByteSize(test.text)
		if err != nil {
			t.Fatalf("%s: %v", test.text, err)
		}
		if got != test.want {
			t.Fatalf("%s: got %d, want %d", test.text, got, test.want)
		}
	}
	for _, invalid := range []string{"0B", "01B", "1KB", "1.5MiB", "-1B", "1mb", "9223372036854775807GiB"} {
		if _, err := parseByteSize(invalid); err == nil {
			t.Fatalf("accepted noncanonical byte size %q", invalid)
		}
	}
}

func FuzzCompileScenarioNeverPanics(fuzz *testing.F) {
	for _, seed := range [][]byte{
		[]byte(validScenarioYAML),
		[]byte("{}"),
		[]byte("a: &x [*x]"),
		{0xff, 0xfe, 0xfd},
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = CompileScenarioYAML(raw, validCompileOptions())
	})
}

func FuzzCompilePackNeverPanics(fuzz *testing.F) {
	for _, seed := range [][]byte{
		[]byte(validPackYAML),
		[]byte("---\nnull\n"),
		[]byte("apiVersion: urn:bad"),
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = CompileProtocolPackYAML(raw, validPackOptions())
	})
}
