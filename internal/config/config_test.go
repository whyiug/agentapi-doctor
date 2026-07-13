package config

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const validConfig = `apiVersion: urn:agentapi-doctor:config:v1beta2
targets:
  local-vllm:
    baseURL: http://127.0.0.1:8000/v1
    protocol: openai-responses
    model: Qwen/Qwen3.5-32B
    auth:
      type: bearer
      token:
        ref: env://LOCAL_LLM_API_KEY
`

func TestDecodeStrictConfig(t *testing.T) {
	config, err := Decode([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if config.Targets["local-vllm"].Protocol != "openai-responses" {
		t.Fatal("target was not decoded")
	}
	for _, mutation := range []string{
		strings.Replace(validConfig, "model:", "modelz:", 1),
		validConfig + "---\n{}\n",
		strings.Replace(validConfig, "env://LOCAL_LLM_API_KEY", "plain-text-key", 1),
		strings.Replace(validConfig, "http://127.0.0.1:8000/v1", "file:///etc/passwd", 1),
	} {
		if _, err := Decode([]byte(mutation)); err == nil {
			t.Fatal("accepted invalid config mutation")
		}
	}
}

func TestV1Beta1GetsActionableMigrationError(t *testing.T) {
	legacy := strings.Replace(validConfig, APIVersion, legacyAPIVersion, 1) + `defaults:
  profile: raw.responses
`
	_, err := Decode([]byte(legacy))
	if err == nil || !strings.Contains(err.Error(), "remove the top-level defaults field") || !strings.Contains(err.Error(), APIVersion) {
		t.Fatalf("legacy migration error = %v", err)
	}
	legacyObject := Default()
	legacyObject.APIVersion = legacyAPIVersion
	if err := legacyObject.Validate(); err == nil || !strings.Contains(err.Error(), "remove the top-level defaults field") {
		t.Fatalf("legacy in-memory config migration error = %v", err)
	}

	mutant := validConfig + `defaults:
  profile: raw.responses
`
	if _, err := Decode([]byte(mutant)); err == nil || !strings.Contains(err.Error(), "field defaults not found") {
		t.Fatalf("v1beta2 accepted removed defaults field: %v", err)
	}
}

func TestTargetNamesMatchPublishedSchemaPattern(t *testing.T) {
	for _, name := range []string{"a", "0", "local-reference", "a.b_c-9", "latest", strings.Repeat("a", 128)} {
		configuration := Default()
		configuration.Targets = map[string]Target{name: configuration.Targets["local-reference"]}
		if err := configuration.Validate(); err != nil {
			t.Fatalf("schema-valid target name %q was rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", "Bad Name", "Upper", "-leading", ".leading", "a/b", "a\nb", "é", strings.Repeat("a", 129)} {
		configuration := Default()
		configuration.Targets = map[string]Target{name: configuration.Targets["local-reference"]}
		if err := configuration.Validate(); err == nil {
			t.Fatalf("accepted target-name mutant %q", name)
		}
	}
}

func TestPublishedSchemaMatchesRuntimeConfigContract(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/config/config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		ID         string   `json:"$id"`
		Required   []string `json:"required"`
		Properties struct {
			APIVersion struct {
				Const string `json:"const"`
			} `json:"apiVersion"`
			Targets struct {
				PropertyNames struct {
					Pattern string `json:"pattern"`
				} `json:"propertyNames"`
			} `json:"targets"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.ID != "urn:agentapi-doctor:schema:config:v1beta2" || document.Properties.APIVersion.Const != APIVersion {
		t.Fatalf("published version drift: %#v", document)
	}
	if document.Properties.Targets.PropertyNames.Pattern != TargetNamePattern {
		t.Fatalf("target-name pattern drift: schema=%q runtime=%q", document.Properties.Targets.PropertyNames.Pattern, TargetNamePattern)
	}
	if slices.Contains(document.Required, "defaults") || strings.Contains(string(raw), `"defaults"`) {
		t.Fatal("published v1beta2 schema retained removed defaults surface")
	}
}

func TestPublishedSchemaAndRuntimeRejectSecurityBoundaryMutants(t *testing.T) {
	rawSchema, err := os.ReadFile("../../schemas/config/config.schema.json")
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
	if err := compiler.AddResource("urn:agentapi-doctor:schema:config:v1beta2", document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:agentapi-doctor:schema:config:v1beta2")
	if err != nil {
		t.Fatal(err)
	}

	configuration := func() Config {
		return Config{
			APIVersion: APIVersion,
			Targets: map[string]Target{
				"local": {
					BaseURL:  "http://127.0.0.1:8000/v1",
					Protocol: "openai-responses",
					Model:    "synthetic-model",
					Auth:     &Auth{Type: "bearer", Token: SecretReference{Ref: "env://TOKEN"}},
				},
			},
		}
	}
	validateSchema := func(value Config) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		return compiled.Validate(instance)
	}

	reference := configuration()
	if err := reference.Validate(); err != nil {
		t.Fatalf("runtime rejected reference config: %v", err)
	}
	if err := validateSchema(reference); err != nil {
		t.Fatalf("schema rejected reference config: %v", err)
	}

	mutants := map[string]func(*Config){
		"environment reference with path": func(value *Config) {
			target := value.Targets["local"]
			target.Auth.Token.Ref = "env://A/B"
			value.Targets["local"] = target
		},
		"header auth without header": func(value *Config) {
			target := value.Targets["local"]
			target.Auth.Type = "header"
			value.Targets["local"] = target
		},
		"URL credentials": func(value *Config) {
			target := value.Targets["local"]
			target.BaseURL = "https://user@example.invalid/v1"
			value.Targets["local"] = target
		},
		"URL without host": func(value *Config) {
			target := value.Targets["local"]
			target.BaseURL = "http:///v1"
			value.Targets["local"] = target
		},
		"URL query": func(value *Config) {
			target := value.Targets["local"]
			target.BaseURL = "https://example.invalid/v1?key=value"
			value.Targets["local"] = target
		},
		"URL fragment": func(value *Config) {
			target := value.Targets["local"]
			target.BaseURL = "https://example.invalid/v1#fragment"
			value.Targets["local"] = target
		},
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			mutant := configuration()
			mutate(&mutant)
			if err := mutant.Validate(); err == nil {
				t.Fatal("runtime accepted config mutant")
			}
			if err := validateSchema(mutant); err == nil {
				t.Fatal("schema accepted config mutant")
			}
		})
	}
}

func TestSecretReferences(t *testing.T) {
	for _, valid := range []string{"env://TOKEN", "keyring://doctor/local", "file:///tmp/token", "exec:///usr/bin/helper"} {
		if _, err := ParseSecretReference(valid); err != nil {
			t.Fatalf("%s: %v", valid, err)
		}
	}
	for _, invalid := range []string{"TOKEN", "https://example.invalid", "env://A/B", "env://TOKEN\nOTHER"} {
		if _, err := ParseSecretReference(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestDefaultTargetMatchesReferenceServer(t *testing.T) {
	configuration := Default()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := configuration.Targets["local-reference"].BaseURL; got != "http://127.0.0.1:8090/v1" {
		t.Fatalf("default target does not match the reference server listener: %s", got)
	}
	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 2 || document["apiVersion"] != APIVersion || document["targets"] == nil {
		t.Fatalf("default config is not the minimal v1beta2 document:\n%s", encoded)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("default config does not round-trip: %v", err)
	}
}
