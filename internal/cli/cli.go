// Package cli implements the stable doctor command surface without making a
// specific command-line framework part of the public contract.
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
	"github.com/whyiug/agentapi-doctor/internal/config"
)

const resultSchema = "urn:agentapi-doctor:cli-result:v1alpha1"

type Dependencies struct {
	Stdout     io.Writer
	Stderr     io.Writer
	WorkingDir string
	Executable string
	LookupEnv  func(string) (string, bool)
}

type condition struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type result struct {
	SchemaVersion   string      `json:"schema_version"`
	Status          string      `json:"status"`
	PrimaryExitCode int         `json:"primary_exit_code"`
	Conditions      []condition `json:"conditions"`
	Data            any         `json:"data,omitempty"`
}

func Run(ctx context.Context, args []string, dependencies Dependencies) int {
	if dependencies.Stdout == nil {
		dependencies.Stdout = io.Discard
	}
	if dependencies.Stderr == nil {
		dependencies.Stderr = io.Discard
	}
	if dependencies.WorkingDir == "" {
		dependencies.WorkingDir, _ = os.Getwd()
	}
	if len(args) == 0 {
		return writeError(dependencies.Stderr, ExitInput, "missing_command", usage())
	}
	select {
	case <-ctx.Done():
		return writeError(dependencies.Stderr, ExitInterrupted, "interrupted", "operation cancelled")
	default:
	}
	switch args[0] {
	case "version":
		return runVersion(args[1:], dependencies)
	case "self-check":
		return runSelfCheck(args[1:], dependencies)
	case "init":
		return runInit(args[1:], dependencies)
	case "target":
		return runTarget(args[1:], dependencies)
	case "test":
		return runTest(ctx, args[1:], dependencies)
	case "demo":
		return runDemo(ctx, args[1:], dependencies)
	case "reproduce":
		return runReproduce(ctx, args[1:], dependencies)
	case "run":
		return runRun(args[1:], dependencies)
	case "report":
		return runReport(args[1:], dependencies)
	case "compare":
		return runCompare(args[1:], dependencies)
	case "baseline":
		return runBaseline(args[1:], dependencies)
	case "completion":
		return runCompletion(args[1:], dependencies)
	case "dev":
		return runDev(args[1:], dependencies)
	case "help":
		return runHelp(args[1:], dependencies)
	case "--help", "-h":
		return writeHelp(dependencies.Stdout, usage())
	default:
		return writeError(dependencies.Stderr, ExitInput, "unknown_command", fmt.Sprintf("unknown command %q\n%s", args[0], usage()))
	}
}

func runVersion(args []string, dependencies Dependencies) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "emit stable JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor version [--json]")
	}
	info := buildinfo.Current()
	if *jsonOutput {
		return writeSuccess(dependencies.Stdout, info)
	}
	_, _ = fmt.Fprintf(dependencies.Stdout, "doctor %s (%s, built %s)\n", info.Version, info.Commit, info.BuiltAt)
	return ExitSuccess
}

func runInit(args []string, dependencies Dependencies) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor init [<directory>]")
	}
	directory := dependencies.WorkingDir
	if flags.NArg() == 1 {
		directory = flags.Arg(0)
		if !filepath.IsAbs(directory) {
			directory = filepath.Join(dependencies.WorkingDir, directory)
		}
	}
	path := filepath.Join(filepath.Clean(directory), ".agentapi", "config.yaml")
	if err := config.SaveFile(path, config.Default(), false); err != nil {
		if errors.Is(err, os.ErrExist) {
			return writeError(dependencies.Stderr, ExitInput, "config_exists", "refusing to overwrite existing .agentapi/config.yaml")
		}
		return writeError(dependencies.Stderr, ExitInfrastructure, "init_failed", err.Error())
	}
	return writeSuccess(dependencies.Stdout, map[string]string{"config": path})
}

func runSelfCheck(args []string, dependencies Dependencies) int {
	flags := flag.NewFlagSet("self-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", filepath.Join(dependencies.WorkingDir, ".agentapi", "config.yaml"), "config path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor self-check [--config <path>]")
	}
	checks := map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if info, err := os.Stat(*configPath); err == nil && info.Mode().IsRegular() {
		loaded, err := config.LoadFile(*configPath)
		if err != nil {
			return writeError(dependencies.Stderr, ExitInput, "invalid_config", err.Error())
		}
		checks["config"] = map[string]any{"path": *configPath, "targets": len(loaded.Targets), "valid": true}
	} else if err != nil && !os.IsNotExist(err) {
		return writeError(dependencies.Stderr, ExitInfrastructure, "config_stat_failed", err.Error())
	} else {
		checks["config"] = map[string]any{"path": *configPath, "present": false}
	}
	if dependencies.Executable == "" {
		dependencies.Executable, _ = os.Executable()
	}
	if dependencies.Executable != "" {
		if digest, err := executableDigest(dependencies.Executable); err == nil {
			checks["binary_digest"] = digest
		}
	}
	checks["network_calls"] = 0
	return writeSuccess(dependencies.Stdout, checks)
}

func runTarget(args []string, dependencies Dependencies) int {
	if len(args) == 0 {
		return writeError(dependencies.Stderr, ExitInput, "missing_target_command", "usage: doctor target add|list|inspect ...")
	}
	switch args[0] {
	case "add":
		return runTargetAdd(args[1:], dependencies)
	case "list":
		return runTargetList(args[1:], dependencies)
	case "inspect":
		return runTargetInspect(args[1:], dependencies)
	default:
		return writeError(dependencies.Stderr, ExitInput, "unknown_target_command", fmt.Sprintf("unknown target command %q", args[0]))
	}
}

func runTargetAdd(args []string, dependencies Dependencies) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor target add <name> --base-url <url> --protocol <id> --model <id> [--auth-ref <secret-ref>] [--config <path>]")
	}
	name := args[0]
	flags := flag.NewFlagSet("target add", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	baseURL := flags.String("base-url", "", "target base URL")
	protocol := flags.String("protocol", "", "protocol family")
	model := flags.String("model", "", "model ID")
	authRef := flags.String("auth-ref", "", "secret reference")
	configPath := flags.String("config", filepath.Join(dependencies.WorkingDir, ".agentapi", "config.yaml"), "config path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *baseURL == "" || *protocol == "" || *model == "" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor target add <name> --base-url <url> --protocol <id> --model <id> [--auth-ref <secret-ref>] [--config <path>]")
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "invalid_config", err.Error())
	}
	if _, exists := loaded.Targets[name]; exists {
		return writeError(dependencies.Stderr, ExitInput, "target_exists", fmt.Sprintf("target %q already exists", name))
	}
	target := config.Target{BaseURL: *baseURL, Protocol: *protocol, Model: *model}
	if *authRef != "" {
		target.Auth = &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: *authRef}}
	}
	loaded.Targets[name] = target
	if err := config.SaveFile(*configPath, loaded, true); err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "config_write_failed", err.Error())
	}
	return writeSuccess(dependencies.Stdout, map[string]string{"target": name})
}

func runTargetList(args []string, dependencies Dependencies) int {
	flags := flag.NewFlagSet("target list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", filepath.Join(dependencies.WorkingDir, ".agentapi", "config.yaml"), "config path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor target list [--config <path>]")
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "invalid_config", err.Error())
	}
	names := make([]string, 0, len(loaded.Targets))
	for name := range loaded.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return writeSuccess(dependencies.Stdout, map[string]any{"targets": names})
}

func runTargetInspect(args []string, dependencies Dependencies) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor target inspect <target> [--config <path>]")
	}
	name := args[0]
	flags := flag.NewFlagSet("target inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", filepath.Join(dependencies.WorkingDir, ".agentapi", "config.yaml"), "config path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor target inspect <target> [--config <path>]")
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "invalid_config", err.Error())
	}
	target, exists := loaded.Targets[name]
	if !exists {
		return writeError(dependencies.Stderr, ExitInput, "target_not_found", fmt.Sprintf("target %q does not exist", name))
	}
	if target.Auth != nil {
		target.Auth.Token.Ref = redactReference(target.Auth.Token.Ref)
	}
	return writeSuccess(dependencies.Stdout, target)
}

func redactReference(reference string) string {
	index := strings.Index(reference, "://")
	if index < 0 {
		return "[REDACTED]"
	}
	return reference[:index+3] + "[REDACTED]"
}

func executableDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func writeSuccess(writer io.Writer, data any) int {
	_ = json.NewEncoder(writer).Encode(result{SchemaVersion: resultSchema, Status: "pass", PrimaryExitCode: ExitSuccess, Conditions: []condition{}, Data: data})
	return ExitSuccess
}

func writeError(writer io.Writer, code int, reason, message string) int {
	_ = json.NewEncoder(writer).Encode(result{SchemaVersion: resultSchema, Status: "error", PrimaryExitCode: code, Conditions: []condition{{Code: reason, Message: message}}})
	return code
}

func writeFailure(writer io.Writer, code int, reason, message string, data any) int {
	_ = json.NewEncoder(writer).Encode(result{SchemaVersion: resultSchema, Status: "fail", PrimaryExitCode: code, Conditions: []condition{{Code: reason, Message: message}}, Data: data})
	return code
}

func usage() string {
	return `AgentAPI Doctor checks whether an OpenAI- or Anthropic-compatible endpoint behaves as claimed.

Usage:
  doctor <command> [options]

Quick paths:
  doctor demo                                  Run four safe local checks
  doctor test --base-url <url> --protocol <id> --model <id>
                                               Check an authorized endpoint
  doctor report markdown latest --output doctor-report.md
                                               Export the latest saved result

Pinned client case:
  doctor reproduce openai-python-responses --help
                                               Correlate raw SSE with a real SDK

Core commands:
  demo       Try AgentAPI Doctor without credentials or network access
  test       Check a configured or inline endpoint
  report     Export a saved run as terminal, JSON, JUnit, SARIF, Markdown, or HTML
  run        Inspect a saved run
  target     Manage saved target configuration

Other commands: reproduce, init, self-check, compare, baseline, completion, dev, version
Use "doctor help test", "doctor help demo", "doctor help report", or
"doctor help reproduce" for examples.`
}

func runHelp(args []string, dependencies Dependencies) int {
	if len(args) == 0 {
		return writeHelp(dependencies.Stdout, usage())
	}
	if len(args) != 1 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor help [test|demo|report|reproduce]")
	}
	switch args[0] {
	case "test":
		return writeHelp(dependencies.Stdout, testHelp)
	case "demo":
		return writeHelp(dependencies.Stdout, demoHelp)
	case "report":
		return writeHelp(dependencies.Stdout, reportHelp)
	case "reproduce":
		return writeHelp(dependencies.Stdout, reproduceHelp)
	default:
		return writeError(dependencies.Stderr, ExitInput, "unknown_help_topic", fmt.Sprintf("unknown help topic %q; available topics: test, demo, report, reproduce", args[0]))
	}
}

func helpRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "--help" || args[0] == "-h")
}

func writeHelp(writer io.Writer, help string) int {
	_, _ = fmt.Fprintln(writer, help)
	return ExitSuccess
}
