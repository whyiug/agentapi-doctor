package config

import (
	"strings"
	"testing"
)

const validConfig = `apiVersion: urn:agentapi-doctor:config:v1beta1
targets:
  local-vllm:
    baseURL: http://127.0.0.1:8000/v1
    protocol: openai-responses
    model: Qwen/Qwen3.5-32B
    auth:
      type: bearer
      token:
        ref: env://LOCAL_LLM_API_KEY
defaults:
  profile: codex.responses
  budget:
    maxRequests: 80
    maxDuration: 15m0s
    maxInputTokens: 100000
    maxOutputTokens: 20000
  capture:
    content: standard_fixture_only
  retries:
    transport: 1
    semantic: 0
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
		strings.Replace(validConfig, "maxRequests:", "maxRequestz:", 1),
		validConfig + "---\n{}\n",
		strings.Replace(validConfig, "env://LOCAL_LLM_API_KEY", "plain-text-key", 1),
		strings.Replace(validConfig, "http://127.0.0.1:8000/v1", "file:///etc/passwd", 1),
	} {
		if _, err := Decode([]byte(mutation)); err == nil {
			t.Fatal("accepted invalid config mutation")
		}
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
}
