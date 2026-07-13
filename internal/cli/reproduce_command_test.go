package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const pinnedDependenciesJSON = `[{"name":"annotated-types","version":"0.7.0"},{"name":"anyio","version":"4.14.2"},{"name":"certifi","version":"2026.6.17"},{"name":"distro","version":"1.9.0"},{"name":"h11","version":"0.16.0"},{"name":"httpcore","version":"1.0.9"},{"name":"httpx","version":"0.28.1"},{"name":"idna","version":"3.18"},{"name":"jiter","version":"0.16.0"},{"name":"openai","version":"2.38.0"},{"name":"pydantic","version":"2.13.4"},{"name":"pydantic-core","version":"2.46.4"},{"name":"sniffio","version":"1.3.1"},{"name":"tqdm","version":"4.68.4"},{"name":"typing-extensions","version":"4.16.0"},{"name":"typing-inspection","version":"0.4.2"}]`

const confirmedReferenceObservation = `{"schema_version":"agentapi-doctor.openai-sdk-observation.v1","version":{"python":"3.12.12","openai":"2.38.0"},"environment":{"implementation":"CPython","python_version":"3.12.12","system":"Linux","machine":"x86_64","dependencies":` + pinnedDependenciesJSON + `,"bootstrap_tools":[],"matches_lock":true,"mismatches":[]},"event_types":["response.created","response.completed"],"event_count":2,"final":{"status":"completed","output_count":1},"exception":null}`

const mismatchedEnvironmentObservation = `{"schema_version":"agentapi-doctor.openai-sdk-observation.v1","version":{"python":"3.12.12","openai":null},"environment":{"implementation":"CPython","python_version":"3.12.12","system":"Linux","machine":"x86_64","dependencies":[{"name":"openai","version":"2.38.1"}],"bootstrap_tools":[],"matches_lock":false,"mismatches":[{"kind":"distribution_version_mismatch","name":"openai","expected":"2.38.0","observed":"2.38.1"}]},"event_types":[],"event_count":0,"final":{"status":null,"output_count":null},"exception":{"phase":"environment_attestation","class":"RuntimePinError","sanitized_message":"runtime environment does not match the frozen dependency lock"}}`

func TestReproduceOpenAIPythonResponsesConfirmedTerminal(t *testing.T) {
	requireReproducePlatform(t)
	directory := t.TempDir()
	python := writeReproducePythonFixture(t, directory, confirmedReferenceObservation, true)
	bundle := filepath.Join("output", "reference.zip")

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: directory},
		"reproduce", "openai-python-responses",
		"--python", filepath.Base(python),
		"--fixture", "reference",
		"--bundle", bundle,
		"--format", "terminal",
	)
	if code != ExitSuccess || stderr != "" {
		t.Fatalf("terminal reproduction failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, fragment := range []string{
		"OpenAI Python Responses reproduction: CONFIRMED",
		"Fixture: reference",
		"Raw terminal events: 1",
		"SDK outcome: completed",
		"Fault domain: none",
		"Bundle: " + filepath.Join(directory, bundle),
	} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("terminal output omitted %q:\n%s", fragment, stdout)
		}
	}
	assertRegularNonemptyFile(t, filepath.Join(directory, bundle))
}

func TestReproduceOpenAIPythonResponsesConfirmedJSON(t *testing.T) {
	requireReproducePlatform(t)
	directory := t.TempDir()
	python := writeReproducePythonFixture(t, directory, confirmedReferenceObservation, true)
	bundle := filepath.Join(directory, "reference.json-mode.zip")

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: directory},
		"reproduce", "openai-python-responses",
		"--python", python,
		"--fixture", "reference",
		"--bundle", bundle,
		"--format", "json",
	)
	if code != ExitSuccess || stderr != "" {
		t.Fatalf("JSON reproduction failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var output result
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("decode JSON result: %v\n%s", err, stdout)
	}
	if output.SchemaVersion != resultSchema || output.Status != "pass" || output.PrimaryExitCode != ExitSuccess || len(output.Conditions) != 0 {
		t.Fatalf("unexpected JSON envelope: %#v", output)
	}
	data, ok := output.Data.(map[string]any)
	if !ok || data["bundle"] != bundle {
		t.Fatalf("unexpected JSON data: %#v", output.Data)
	}
	reproduction, ok := data["result"].(map[string]any)
	if !ok || reproduction["status"] != "confirmed" || reproduction["fixture"] != "reference" || reproduction["fault_domain"] != "none" {
		t.Fatalf("unexpected reproduction result: %#v", data["result"])
	}
	assertRegularNonemptyFile(t, bundle)
}

func TestReproduceOpenAIPythonResponsesUnknownWritesBundleAndExitsIncomplete(t *testing.T) {
	requireReproducePlatform(t)
	directory := t.TempDir()
	python := writeReproducePythonFixture(t, directory, mismatchedEnvironmentObservation, false)
	bundle := filepath.Join(directory, "unknown.zip")

	code, stdout, stderr := runRawWithDependencies(t, Dependencies{WorkingDir: directory},
		"reproduce", "openai-python-responses",
		"--python", python,
		"--fixture", "reference",
		"--bundle", bundle,
		"--format", "json",
	)
	if code != ExitIncomplete || stdout != "" {
		t.Fatalf("UNKNOWN result used wrong channel or exit: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var output result
	if err := json.Unmarshal([]byte(stderr), &output); err != nil {
		t.Fatalf("decode UNKNOWN result: %v\n%s", err, stderr)
	}
	if output.Status != "fail" || output.PrimaryExitCode != ExitIncomplete || len(output.Conditions) != 1 || output.Conditions[0].Code != "reproduction_unknown" {
		t.Fatalf("unexpected UNKNOWN envelope: %#v", output)
	}
	data, ok := output.Data.(map[string]any)
	if !ok || data["bundle"] != bundle {
		t.Fatalf("UNKNOWN result omitted bundle identity: %#v", output.Data)
	}
	reproduction, ok := data["result"].(map[string]any)
	if !ok || reproduction["status"] != "unknown" || reproduction["sdk_status"] != "environment_mismatch" {
		t.Fatalf("unexpected UNKNOWN evidence summary: %#v", data["result"])
	}
	assertRegularNonemptyFile(t, bundle)
}

func TestReproduceOpenAIPythonResponsesRejectsInvalidFixtureAndFormat(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name       string
		arguments  []string
		reasonCode string
	}{
		{
			name: "fixture",
			arguments: []string{
				"--fixture", "not-a-fixture",
				"--format", "terminal",
			},
			reasonCode: "unknown_fixture",
		},
		{
			name: "format",
			arguments: []string{
				"--fixture", "reference",
				"--format", "yaml",
			},
			reasonCode: "invalid_format",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := filepath.Join(directory, test.name+".zip")
			arguments := []string{
				"reproduce", "openai-python-responses",
				"--python", os.Args[0],
				"--bundle", bundle,
			}
			arguments = append(arguments, test.arguments...)
			code, output := run(t, directory, arguments...)
			if code != ExitInput || output.Status != "error" || output.PrimaryExitCode != ExitInput || len(output.Conditions) != 1 || output.Conditions[0].Code != test.reasonCode {
				t.Fatalf("invalid %s result: code=%d output=%#v", test.name, code, output)
			}
			if _, err := os.Stat(bundle); !os.IsNotExist(err) {
				t.Fatalf("invalid %s created a bundle: %v", test.name, err)
			}
		})
	}
}

func TestReproduceOpenAIPythonResponsesDoesNotOverwriteBundle(t *testing.T) {
	requireReproducePlatform(t)
	directory := t.TempDir()
	python := writeReproducePythonFixture(t, directory, confirmedReferenceObservation, true)
	bundle := filepath.Join(directory, "existing.zip")
	if err := os.WriteFile(bundle, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, output := run(t, directory,
		"reproduce", "openai-python-responses",
		"--python", python,
		"--fixture", "reference",
		"--bundle", bundle,
	)
	if code != ExitInput || output.Status != "error" || len(output.Conditions) != 1 || output.Conditions[0].Code != "bundle_exists" {
		t.Fatalf("existing bundle result: code=%d output=%#v", code, output)
	}
	if data, err := os.ReadFile(bundle); err != nil || string(data) != "owned" {
		t.Fatalf("existing bundle changed: data=%q err=%v", data, err)
	}
}

func TestReproduceOpenAIPythonResponsesValidatesPaths(t *testing.T) {
	t.Run("Python must be a regular file", func(t *testing.T) {
		directory := t.TempDir()
		for name, python := range map[string]string{
			"missing":   filepath.Join(directory, "missing-python"),
			"directory": directory,
		} {
			t.Run(name, func(t *testing.T) {
				bundle := filepath.Join(directory, name+".zip")
				code, output := run(t, directory,
					"reproduce", "openai-python-responses",
					"--python", python,
					"--fixture", "reference",
					"--bundle", bundle,
				)
				if code != ExitInput || output.Status != "error" || len(output.Conditions) != 1 || output.Conditions[0].Code != "python_not_found" {
					t.Fatalf("invalid Python path result: code=%d output=%#v", code, output)
				}
			})
		}
	})

	t.Run("Python must be executable", func(t *testing.T) {
		directory := t.TempDir()
		python := filepath.Join(directory, "python-not-executable")
		if err := os.WriteFile(python, []byte("not executable"), 0o600); err != nil {
			t.Fatal(err)
		}
		bundle := filepath.Join(directory, "not-executable.zip")
		code, output := run(t, directory,
			"reproduce", "openai-python-responses",
			"--python", python,
			"--fixture", "reference",
			"--bundle", bundle,
		)
		if code != ExitInput || output.Status != "error" || len(output.Conditions) != 1 || output.Conditions[0].Code != "python_not_executable" {
			t.Fatalf("non-executable Python result: code=%d output=%#v", code, output)
		}
		if _, err := os.Stat(bundle); !os.IsNotExist(err) {
			t.Fatalf("non-executable Python created a bundle: %v", err)
		}
	})

	t.Run("bundle symlink ancestor is rejected", func(t *testing.T) {
		requireReproducePlatform(t)
		directory := t.TempDir()
		outside := t.TempDir()
		link := filepath.Join(directory, "linked-output")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		python := writeReproducePythonFixture(t, directory, confirmedReferenceObservation, true)
		code, output := run(t, directory,
			"reproduce", "openai-python-responses",
			"--python", python,
			"--fixture", "reference",
			"--bundle", filepath.Join("linked-output", "escaped.zip"),
		)
		if code != ExitInfrastructure || output.Status != "error" || len(output.Conditions) != 1 || output.Conditions[0].Code != "bundle_write_failed" {
			t.Fatalf("symlink bundle result: code=%d output=%#v", code, output)
		}
		if _, err := os.Stat(filepath.Join(outside, "escaped.zip")); !os.IsNotExist(err) {
			t.Fatalf("bundle escaped through a symlink: %v", err)
		}
	})
}

func writeReproducePythonFixture(t *testing.T, directory, observation string, makeRequest bool) string {
	t.Helper()
	path := filepath.Join(directory, "python-fixture")
	request := ""
	if makeRequest {
		request = `/usr/bin/curl --silent --show-error --fail \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer synthetic-test-token' \
  --data '{"model":"fixture-model","input":"synthetic","stream":true,"max_output_tokens":32}' \
  "$4/responses" >/dev/null
`
	}
	script := "#!/bin/sh\nset -eu\n" + request + "printf '%s\\n' '" + observation + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireReproducePlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the frozen OpenAI SDK reproduction baseline is Linux amd64 only")
	}
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skipf("deterministic loopback fixture requires /usr/bin/curl: %v", err)
	}
}

func assertRegularNonemptyFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("expected non-empty regular file at %s, got mode=%s size=%d", path, info.Mode(), info.Size())
	}
}
