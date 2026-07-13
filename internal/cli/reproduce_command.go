package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/openaisdkcase"
)

const reproduceHelp = `Reproduce one pinned real-SDK compatibility failure locally.

Usage:
  doctor reproduce openai-python-responses \
    --python <python-3.12.12> \
    --fixture <reference|missing-terminal-event|duplicate-terminal-event|null-completed-output> \
    --bundle <new.zip> [--format terminal|json]

This command starts a random 127.0.0.1 synthetic fixture, runs exactly one
OpenAI Python SDK 2.38.0 Responses stream, correlates application-layer SSE
with the SDK observation, verifies the frozen runtime and installed dependency
metadata, writes a maintainer-ready bundle, and cleans up. It never contacts a
provider and never reads an API key.`

func runReproduce(ctx context.Context, args []string, dependencies Dependencies) int {
	if helpRequested(args) || len(args) == 2 && args[0] == "openai-python-responses" && helpRequested(args[1:]) {
		return writeHelp(dependencies.Stdout, reproduceHelp)
	}
	if len(args) == 0 || args[0] != "openai-python-responses" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor reproduce openai-python-responses --python <path> --fixture <id> --bundle <new.zip>")
	}
	flags := flag.NewFlagSet("reproduce openai-python-responses", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	python := flags.String("python", "", "exact Python 3.12.12 executable with the locked SDK installed")
	fixture := flags.String("fixture", openaisdkcase.FixtureMissingTerminalEvent, "synthetic fixture ID")
	bundle := flags.String("bundle", "", "new maintainer-ready ZIP path")
	format := flags.String("format", "terminal", "terminal or json")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *python == "" || *bundle == "" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor reproduce openai-python-responses --python <path> --fixture <id> --bundle <new.zip> [--format terminal|json]")
	}
	if !slices.Contains(openaisdkcase.SupportedFixtures(), *fixture) {
		return writeError(dependencies.Stderr, ExitInput, "unknown_fixture", fmt.Sprintf("unsupported fixture %q; choose %s", *fixture, strings.Join(openaisdkcase.SupportedFixtures(), ", ")))
	}
	if *format != "terminal" && *format != "json" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_format", "--format must be terminal or json")
	}
	pythonPath := *python
	if !filepath.IsAbs(pythonPath) {
		pythonPath = absolutePath(dependencies.WorkingDir, pythonPath)
	}
	info, err := os.Stat(pythonPath)
	if err != nil || !info.Mode().IsRegular() {
		return writeError(dependencies.Stderr, ExitInput, "python_not_found", fmt.Sprintf("Python executable is not a regular file: %s", pythonPath))
	}
	if info.Mode().Perm()&0o111 == 0 {
		return writeError(dependencies.Stderr, ExitInput, "python_not_executable", fmt.Sprintf("Python file is not executable: %s", pythonPath))
	}

	result, err := openaisdkcase.Run(ctx, openaisdkcase.Request{Python: pythonPath, Fixture: *fixture})
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "reproduction_failed", err.Error())
	}
	bundlePath := absolutePath(dependencies.WorkingDir, *bundle)
	if err := writeNewFile(bundlePath, result.Bundle); err != nil {
		code, reason := ExitInfrastructure, "bundle_write_failed"
		if errors.Is(err, os.ErrExist) {
			code, reason = ExitInput, "bundle_exists"
		}
		return writeError(dependencies.Stderr, code, reason, err.Error())
	}
	data := map[string]any{"bundle": bundlePath, "result": result}
	if result.Status != openaisdkcase.StatusConfirmed {
		return writeFailure(dependencies.Stderr, ExitIncomplete, "reproduction_unknown", result.Summary, data)
	}
	if *format == "json" {
		return writeSuccess(dependencies.Stdout, data)
	}
	_, _ = fmt.Fprintf(dependencies.Stdout, "OpenAI Python Responses reproduction: CONFIRMED\nFixture: %s\nRaw terminal events: %d\nSDK outcome: %s\nFault domain: %s\nBundle: %s\n\n%s\n", result.Fixture, result.RawTerminalCount, result.SDKStatus, result.FaultDomain, bundlePath, result.Summary)
	return ExitSuccess
}
