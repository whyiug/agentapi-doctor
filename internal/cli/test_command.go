package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/productrun"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/secret"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const testUsage = "usage: doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>] [--format json|terminal]\n   or: doctor test --base-url <url> --protocol <id> --model <id> [--auth-env <name>] [--auth-header <name>] [--allow-plain-http] [--data-root <path>] [--plan-only] [--resolve] [--output <path>] [--format json|terminal]"

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const minimumCredentialCanaryBytes = 8

type credentialValidationError struct {
	err error
}

func (validation *credentialValidationError) Error() string { return validation.err.Error() }
func (validation *credentialValidationError) Unwrap() error { return validation.err }

type cliCredentialResolver struct {
	delegate secret.Resolver
}

func (resolver cliCredentialResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	value, err := resolver.delegate.Resolve(ctx, reference)
	if err != nil {
		return nil, &credentialValidationError{err: err}
	}
	if len(value) < minimumCredentialCanaryBytes {
		secret.Wipe(value)
		return nil, &credentialValidationError{err: fmt.Errorf("resolved credential must contain at least %d bytes for exact redaction-canary enforcement", minimumCredentialCanaryBytes)}
	}
	return value, nil
}

type testOptions struct {
	targetName     string
	target         config.Target
	configPath     string
	dataRoot       string
	output         string
	format         string
	planOnly       bool
	resolve        bool
	inline         bool
	allowPlainHTTP bool
	beforePersist  func() error
}

func runTest(ctx context.Context, args []string, dependencies Dependencies) int {
	options, err := parseTestOptions(args, dependencies.WorkingDir)
	if err != nil {
		return emitCommandError(options.format, dependencies, ExitInput, "invalid_arguments", err.Error())
	}

	if !options.inline {
		loaded, loadErr := config.LoadFile(absolutePath(dependencies.WorkingDir, options.configPath))
		if loadErr != nil {
			return emitCommandError(options.format, dependencies, ExitInput, "invalid_config", loadErr.Error())
		}
		target, exists := loaded.Targets[options.targetName]
		if !exists {
			return emitCommandError(options.format, dependencies, ExitInput, "target_not_found", fmt.Sprintf("target %q does not exist", options.targetName))
		}
		options.target = target
	}

	planned, err := productrun.Build(productrun.PlanRequest{TargetName: options.targetName, Target: options.target})
	if err != nil {
		return emitCommandError(options.format, dependencies, ExitInput, "plan_failed", err.Error())
	}
	if options.planOnly {
		return emitPlan(planned, options.resolve, options.output, options.format, dependencies)
	}
	return executePlannedTest(ctx, planned, options, dependencies)
}

func parseTestOptions(args []string, workingDirectory string) (testOptions, error) {
	legacy := len(args) > 0 && args[0] != "" && !strings.HasPrefix(args[0], "-")
	flagArgs := args
	defaultFormat := "json"
	if !legacy {
		defaultFormat = "terminal"
	}
	options := testOptions{inline: !legacy, format: requestedCommandFormat(args, defaultFormat)}
	if legacy {
		options.targetName = args[0]
		flagArgs = args[1:]
		options.format = requestedCommandFormat(flagArgs, defaultFormat)
	} else {
		options.targetName = "inline"
	}

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", filepath.Join(workingDirectory, ".agentapi", "config.yaml"), "config path")
	dataRoot := flags.String("data-root", filepath.Join(workingDirectory, ".agentapi"), "local evidence and run store")
	planOnly := flags.Bool("plan-only", false, "build a plan without network access")
	resolve := flags.Bool("resolve", false, "include the offline built-in resolved run plan")
	output := flags.String("output", "", "write canonical plan or report JSON")
	format := flags.String("format", "", "display format")
	baseURL := flags.String("base-url", "", "inline target base URL")
	protocol := flags.String("protocol", "", "inline target protocol")
	model := flags.String("model", "", "inline target model")
	authEnv := flags.String("auth-env", "", "environment variable containing the inline credential")
	authHeader := flags.String("auth-header", "", "custom inline credential header")
	allowPlainHTTP := flags.Bool("allow-plain-http", false, "allow an explicitly selected plain HTTP target")
	if err := flags.Parse(flagArgs); err != nil || flags.NArg() != 0 {
		return options, errors.New(testUsage)
	}
	seen := make(map[string]bool)
	flags.Visit(func(item *flag.Flag) { seen[item.Name] = true })

	options.configPath = *configPath
	options.dataRoot = *dataRoot
	options.output = *output
	options.planOnly = *planOnly
	options.resolve = *resolve
	options.allowPlainHTTP = *allowPlainHTTP
	if seen["format"] {
		if !validCommandFormat(*format) {
			return options, errors.New(testUsage + "; --format must be json or terminal")
		}
		options.format = *format
	}
	if options.resolve && !options.planOnly {
		return options, errors.New(testUsage + "; --resolve requires --plan-only")
	}

	inlineFlags := []string{"base-url", "protocol", "model", "auth-env", "auth-header", "allow-plain-http"}
	if legacy {
		for _, name := range inlineFlags {
			if seen[name] {
				return options, errors.New(testUsage + "; inline target flags cannot be combined with <target>")
			}
		}
		return options, nil
	}
	if seen["config"] {
		return options, errors.New(testUsage + "; --config cannot be combined with inline target flags")
	}
	if *baseURL == "" || *protocol == "" || *model == "" {
		return options, errors.New(testUsage + "; inline mode requires --base-url, --protocol, and --model")
	}
	if seen["auth-env"] && *authEnv == "" {
		return options, errors.New(testUsage + "; --auth-env cannot be empty")
	}
	if seen["auth-header"] && *authHeader == "" {
		return options, errors.New(testUsage + "; --auth-header cannot be empty")
	}
	if seen["auth-header"] && !seen["auth-env"] {
		return options, errors.New(testUsage + "; --auth-header requires --auth-env")
	}
	if *authEnv != "" && !environmentName.MatchString(*authEnv) {
		return options, errors.New(testUsage + "; --auth-env must name one portable environment variable")
	}

	options.target = config.Target{BaseURL: *baseURL, Protocol: *protocol, Model: *model}
	if *authEnv != "" {
		auth := &config.Auth{Type: "bearer", Token: config.SecretReference{Ref: "env://" + *authEnv}}
		if *authHeader != "" {
			auth.Type = "header"
			auth.Header = *authHeader
		}
		options.target.Auth = auth
	}
	if err := options.target.Validate(); err != nil {
		return options, fmt.Errorf("%s; invalid inline target: %w", testUsage, err)
	}
	parsed, _ := url.Parse(options.target.BaseURL)
	if parsed.Scheme == "http" && !options.allowPlainHTTP {
		return options, errors.New(testUsage + "; plain HTTP requires --allow-plain-http")
	}
	if parsed.Scheme != "http" && options.allowPlainHTTP {
		return options, errors.New(testUsage + "; --allow-plain-http is only valid for an http:// base URL")
	}
	return options, nil
}

func requestedCommandFormat(args []string, fallback string) string {
	selected := fallback
	for index, argument := range args {
		value := ""
		switch {
		case argument == "--format" && index+1 < len(args):
			value = args[index+1]
		case strings.HasPrefix(argument, "--format="):
			value = strings.TrimPrefix(argument, "--format=")
		}
		if validCommandFormat(value) {
			selected = value
		}
	}
	return selected
}

func validCommandFormat(value string) bool {
	return value == "json" || value == "terminal"
}

func executePlannedTest(ctx context.Context, planned productrun.PlannedRun, options testOptions, dependencies Dependencies) int {
	if options.output != "" {
		if err := validateNewFilePath(absolutePath(dependencies.WorkingDir, options.output)); err != nil {
			return emitOutputPathError(err, options.format, dependencies)
		}
	}

	root := absolutePath(dependencies.WorkingDir, options.dataRoot)
	resolver := cliCredentialResolver{delegate: secret.Resolver{LookupEnv: dependencies.LookupEnv}}
	execution, executionErr := productrun.Execute(ctx, productrun.ExecuteRequest{
		Planned: planned, DataRoot: root, Secrets: resolver, BeforePersist: options.beforePersist,
	})
	if execution.Report.RunID == "" {
		code, reason := classifyExecutionError(ctx, executionErr)
		message := "execution failed before a report could be persisted"
		if executionErr != nil {
			message += ": " + executionErr.Error()
		}
		if options.format == "terminal" {
			return writeTerminalError(dependencies.Stderr, code, message)
		}
		return writeError(dependencies.Stderr, code, reason, message)
	}
	if options.output != "" {
		path := absolutePath(dependencies.WorkingDir, options.output)
		if err := writeNewFile(path, execution.ReportJSON); err != nil {
			code, reason := ExitInfrastructure, "report_write_failed"
			if errors.Is(err, os.ErrExist) {
				code, reason = ExitInput, "output_exists"
			}
			if options.format == "terminal" {
				return writeTerminalError(dependencies.Stderr, code, err.Error())
			}
			return writeError(dependencies.Stderr, code, reason, err.Error())
		}
	}
	return emitExecution(ctx, execution, executionErr, root, options, dependencies)
}

func emitExecution(ctx context.Context, execution productrun.Execution, executionErr error, root string, options testOptions, dependencies Dependencies) int {
	code := execution.Report.PrimaryExitCode
	if executionErr != nil && code == ExitSuccess {
		code, _ = classifyExecutionError(ctx, executionErr)
	}
	if options.format == "terminal" {
		writer := dependencies.Stdout
		if code != ExitSuccess {
			writer = dependencies.Stderr
		}
		rendered, err := report.Terminal(execution.Report)
		if err != nil {
			return writeTerminalError(dependencies.Stderr, ExitInfrastructure, "render terminal report: "+err.Error())
		}
		_, _ = writer.Write(rendered)
		_, _ = fmt.Fprintf(writer, "Evidence: %s\nRun store: %s\n", filepath.Join(root, "evidence"), filepath.Join(root, "runs"))
		if options.output != "" {
			_, _ = fmt.Fprintf(writer, "Report JSON: %s\n", absolutePath(dependencies.WorkingDir, options.output))
		}
		if executionErr != nil {
			_, _ = fmt.Fprintf(writer, "Execution error: %s\n", terminalLine(executionErr.Error()))
		}
		return code
	}

	data := executionSummary(execution, root, options.output, dependencies.WorkingDir)
	if code == ExitSuccess {
		return writeSuccess(dependencies.Stdout, data)
	}
	message := "one or more candidate checks did not pass"
	if executionErr != nil {
		message = executionErr.Error()
	}
	return writeFailure(dependencies.Stderr, code, "candidate_run_not_passed", message, data)
}

func emitOutputPathError(err error, format string, dependencies Dependencies) int {
	code, reason := ExitInfrastructure, "invalid_output_path"
	if errors.Is(err, os.ErrExist) {
		code, reason = ExitInput, "output_exists"
	}
	if format == "terminal" {
		return writeTerminalError(dependencies.Stderr, code, err.Error())
	}
	return writeError(dependencies.Stderr, code, reason, err.Error())
}

func emitPlan(planned productrun.PlannedRun, resolved bool, output, format string, dependencies Dependencies) int {
	var (
		encoded []byte
		value   any = planned.Intent
		err     error
	)
	if resolved {
		encoded, err = productrun.PlanJSON(planned)
		if err == nil {
			value, err = productrun.DecodePlanJSON(encoded)
		}
	} else {
		encoded, err = schema.CanonicalMarshal(planned.Intent)
	}
	if err != nil {
		return emitCommandError(format, dependencies, ExitInfrastructure, "plan_encode_failed", err.Error())
	}
	path := ""
	if output != "" {
		path = absolutePath(dependencies.WorkingDir, output)
		if err := writeNewFile(path, encoded); err != nil {
			code, reason := ExitInfrastructure, "plan_write_failed"
			if errors.Is(err, os.ErrExist) {
				code, reason = ExitInput, "output_exists"
			}
			if format == "terminal" {
				return writeTerminalError(dependencies.Stderr, code, err.Error())
			}
			return writeError(dependencies.Stderr, code, reason, err.Error())
		}
	}
	if format == "terminal" {
		_, _ = fmt.Fprintf(dependencies.Stdout, "Target: %s\nProtocol: %s\nModel: %s\nNetwork calls: 0\nResolved plan: %t\nChecks: %d\n", terminalLine(planned.TargetName), terminalLine(planned.Target.Protocol), terminalLine(planned.Target.Model), resolved, len(planned.Resolved.Scenarios))
		if path != "" {
			_, _ = fmt.Fprintf(dependencies.Stdout, "Plan JSON: %s\n", path)
		}
		return ExitSuccess
	}
	if output == "" {
		return writeSuccess(dependencies.Stdout, map[string]any{
			"network_calls": 0, "resolved": resolved, "plan": value,
		})
	}
	return writeSuccess(dependencies.Stdout, map[string]any{
		"network_calls": 0, "resolved": resolved, "output": path,
		"intent_plan_ref": planned.Intent.ObjectRef, "resolved_plan_ref": planned.Resolved.ObjectRef,
	})
}

func executionSummary(execution productrun.Execution, dataRoot, output, workingDirectory string) map[string]any {
	data := map[string]any{
		"run_id": execution.Report.RunID, "profile_outcome": execution.Report.Outcome,
		"primary_exit_code": execution.Report.PrimaryExitCode,
		"counts":            report.Count(execution.Report),
		"record_digest":     execution.RecordDigest,
		"run_store":         filepath.Join(dataRoot, "runs"),
		"conditions":        execution.Report.Conditions,
	}
	if output != "" {
		data["output"] = absolutePath(workingDirectory, output)
	}
	return data
}

func writeTerminalError(writer io.Writer, code int, message string) int {
	_, _ = fmt.Fprintf(writer, "AgentAPI Doctor: ERROR\n%s\n", terminalLine(message))
	return code
}

func emitCommandError(format string, dependencies Dependencies, code int, reason, message string) int {
	if format == "terminal" {
		return writeTerminalError(dependencies.Stderr, code, message)
	}
	return writeError(dependencies.Stderr, code, reason, message)
}

func terminalLine(value string) string {
	return strings.Map(func(character rune) rune {
		if character == '\r' || character == '\n' || character == '\x00' {
			return ' '
		}
		return character
	}, value)
}

func classifyExecutionError(ctx context.Context, err error) (int, string) {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return ExitInterrupted, "interrupted"
	}
	if errors.Is(err, secret.ErrNotFound) || errors.Is(err, secret.ErrExecDisabled) || errors.Is(err, secret.ErrKeyring) {
		return ExitPermission, "credential_unavailable"
	}
	var credentialError *credentialValidationError
	if errors.As(err, &credentialError) {
		return ExitPermission, "credential_invalid"
	}
	return ExitInfrastructure, "execution_failed"
}
