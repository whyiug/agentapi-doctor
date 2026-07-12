package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/productrun"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

const demoUsage = "usage: doctor demo [--data-root <path>] [--output <path>] [--format terminal|json]"

const demoHelp = `Run four compatibility checks against a bundled local fixture.

Usage:
  doctor demo [--format terminal|json] [--output <path>] [--data-root <path>]

Quick path:
  doctor demo

The demo needs no API key, makes no public network request, and stops its loopback server automatically.`

func runDemo(ctx context.Context, args []string, dependencies Dependencies) int {
	if helpRequested(args) {
		return writeHelp(dependencies.Stdout, demoHelp)
	}
	return runDemoWithServer(ctx, args, dependencies, startDemoReferenceServer)
}

func runDemoWithServer(ctx context.Context, args []string, dependencies Dependencies, start func() (string, func() error, error)) int {
	presentationFormat := requestedCommandFormat(args, "terminal")
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dataRoot := flags.String("data-root", filepath.Join(dependencies.WorkingDir, ".agentapi"), "local evidence and run store")
	output := flags.String("output", "", "write canonical report JSON")
	format := flags.String("format", "terminal", "display format")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *format != "terminal" && *format != "json" {
		return emitCommandError(presentationFormat, dependencies, ExitInput, "invalid_arguments", demoUsage)
	}
	presentationFormat = *format
	if *output != "" {
		if err := validateNewFilePath(absolutePath(dependencies.WorkingDir, *output)); err != nil {
			return emitOutputPathError(err, presentationFormat, dependencies)
		}
	}

	baseURL, stop, err := start()
	if err != nil {
		return emitCommandError(presentationFormat, dependencies, ExitInfrastructure, "demo_server_failed", "start local reference server: "+err.Error())
	}

	var bufferedStdout, bufferedStderr bytes.Buffer
	bufferedDependencies := dependencies
	bufferedDependencies.Stdout = &bufferedStdout
	bufferedDependencies.Stderr = &bufferedStderr
	code := func() int {
		target := config.Target{
			BaseURL:  baseURL + "/v1",
			Protocol: "openai-responses",
			Model:    "synthetic-model",
			Metadata: map[string]string{"runtime": "in-process-reference-demo"},
		}
		planned, planErr := productrun.Build(productrun.PlanRequest{TargetName: "demo", Target: target})
		if planErr != nil {
			return emitCommandError(presentationFormat, bufferedDependencies, ExitInfrastructure, "demo_plan_failed", "build demo plan: "+planErr.Error())
		}
		return executePlannedTest(ctx, planned, testOptions{
			targetName: "demo", target: target, dataRoot: *dataRoot, output: *output,
			format: presentationFormat, allowPlainHTTP: true, beforePersist: stop,
		}, bufferedDependencies)
	}()

	if stopErr := stop(); stopErr != nil {
		primary := PrimaryExitCode([]int{code, ExitInfrastructure})
		message := "stop local reference server: " + stopErr.Error()
		if code != ExitSuccess {
			message = fmt.Sprintf("demo command exited with code %d; %s", code, message)
		}
		return emitCommandError(presentationFormat, dependencies, primary, "demo_cleanup_failed", message)
	}
	_, _ = io.Copy(dependencies.Stdout, &bufferedStdout)
	_, _ = io.Copy(dependencies.Stderr, &bufferedStderr)
	return code
}

func startDemoReferenceServer() (string, func() error, error) {
	handler, err := referenceserver.New(referenceserver.Config{})
	if err != nil {
		return "", nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{
		Handler:           handler,
		ReadTimeout:       3 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	var once sync.Once
	var stopErr error
	stop := func() error {
		once.Do(func() {
			closeErr := server.Close()
			serveErr := <-done
			if closeErr != nil {
				stopErr = closeErr
			} else if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				stopErr = serveErr
			}
		})
		return stopErr
	}
	return fmt.Sprintf("http://%s", listener.Addr().String()), stop, nil
}
