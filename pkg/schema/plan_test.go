package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationRejectsNoncanonicalOrNonpositive(t *testing.T) {
	for _, raw := range []string{`"60s"`, `"0s"`, `"-1s"`, `1`} {
		var value Duration
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("accepted invalid duration %s", raw)
		}
	}
	var value Duration
	if err := json.Unmarshal([]byte(`"1m0s"`), &value); err != nil {
		t.Fatal(err)
	}
	if value.Duration() != time.Minute {
		t.Fatalf("got %v", value.Duration())
	}
}

func TestResolvedScenarioDAGRejectsForwardAndUnknownDependencies(t *testing.T) {
	digest := Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	driver := ArtifactPin{Kind: "Driver", Name: "raw-http", Version: "1.0.0", Digest: digest}
	tests := []struct {
		name      string
		decisions []ScenarioDecision
	}{
		{
			name:      "unknown",
			decisions: []ScenarioDecision{{ScenarioID: "case.one", Disposition: DispositionExecute, Driver: driver, DependsOn: []string{"missing"}}},
		},
		{
			name: "forward",
			decisions: []ScenarioDecision{
				{ScenarioID: "case.one", Disposition: DispositionExecute, Driver: driver, DependsOn: []string{"case.two"}},
				{ScenarioID: "case.two", Disposition: DispositionExecute, Driver: driver},
			},
		},
		{
			name:      "skip without reason",
			decisions: []ScenarioDecision{{ScenarioID: "case.one", Disposition: DispositionSkip, Driver: driver}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateScenarioDAG(test.decisions); err == nil {
				t.Fatal("expected DAG rejection")
			}
		})
	}
	valid := []ScenarioDecision{
		{ScenarioID: "case.one", Disposition: DispositionExecute, Driver: driver},
		{ScenarioID: "case.two", Disposition: DispositionNotApplicable, ReasonCode: "unsupported_capability", Driver: driver, DependsOn: []string{"case.one"}},
	}
	if err := validateScenarioDAG(valid); err != nil {
		t.Fatal(err)
	}
}
