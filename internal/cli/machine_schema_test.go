package cli

import (
	"bytes"
	"context"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	agentapidoctor "github.com/whyiug/agentapi-doctor"
)

func TestCLIResultEnvelopesMatchPublishedSchema(t *testing.T) {
	rawSchema, err := agentapidoctor.ReadAsset("schemas/cli/cli-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(rawSchema))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(resultSchema, document); err != nil {
		t.Fatal(err)
	}
	contract, err := compiler.Compile(resultSchema)
	if err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"success": {"version", "--json"},
		"error":   {"unknown-command"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, Dependencies{Stdout: &stdout, Stderr: &stderr, WorkingDir: t.TempDir()})
			raw := stdout.Bytes()
			if code != ExitSuccess {
				raw = stderr.Bytes()
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := contract.Validate(instance); err != nil {
				t.Fatalf("CLI result violates published schema: %v\n%s", err, raw)
			}
		})
	}

	mutant, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"schema_version":"urn:agentapi-doctor:cli-result:v1alpha1","status":"pass","primary_exit_code":0}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := contract.Validate(mutant); err == nil {
		t.Fatal("published CLI schema accepted an envelope without conditions")
	}
}
