package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/internal/productrun"
	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/secret"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const testUsage = "usage: doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>]"

func runTest(ctx context.Context, args []string, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", testUsage)
	}
	targetName := args[0]
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", filepath.Join(dependencies.WorkingDir, ".agentapi", "config.yaml"), "config path")
	dataRoot := flags.String("data-root", filepath.Join(dependencies.WorkingDir, ".agentapi"), "local evidence and run store")
	planOnly := flags.Bool("plan-only", false, "build a plan without network access")
	resolve := flags.Bool("resolve", false, "include the exact resolved run plan")
	output := flags.String("output", "", "write canonical plan or report JSON")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *resolve && !*planOnly {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", testUsage+"; --resolve requires --plan-only")
	}
	loaded, err := config.LoadFile(absolutePath(dependencies.WorkingDir, *configPath))
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "invalid_config", err.Error())
	}
	target, exists := loaded.Targets[targetName]
	if !exists {
		return writeError(dependencies.Stderr, ExitInput, "target_not_found", fmt.Sprintf("target %q does not exist", targetName))
	}
	planned, err := productrun.Build(productrun.PlanRequest{TargetName: targetName, Target: target})
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "plan_failed", err.Error())
	}
	if *planOnly {
		return emitPlan(planned, *resolve, *output, dependencies)
	}
	if *output != "" {
		if err := validateNewFilePath(absolutePath(dependencies.WorkingDir, *output)); err != nil {
			code, reason := ExitInfrastructure, "invalid_output_path"
			if errors.Is(err, os.ErrExist) {
				code, reason = ExitInput, "output_exists"
			}
			return writeError(dependencies.Stderr, code, reason, err.Error())
		}
	}

	root := absolutePath(dependencies.WorkingDir, *dataRoot)
	resolver := secret.Resolver{LookupEnv: dependencies.LookupEnv}
	execution, executionErr := productrun.Execute(ctx, productrun.ExecuteRequest{
		Planned: planned, DataRoot: root, Secrets: resolver,
	})
	if execution.Report.RunID == "" {
		code, reason := classifyExecutionError(ctx, executionErr)
		message := "execution failed before a report could be persisted"
		if executionErr != nil {
			message += ": " + executionErr.Error()
		}
		return writeError(dependencies.Stderr, code, reason, message)
	}
	if *output != "" {
		path := absolutePath(dependencies.WorkingDir, *output)
		if err := writeNewFile(path, execution.ReportJSON); err != nil {
			code, reason := ExitInfrastructure, "report_write_failed"
			if errors.Is(err, os.ErrExist) {
				code, reason = ExitInput, "output_exists"
			}
			return writeError(dependencies.Stderr, code, reason, err.Error())
		}
	}
	data := executionSummary(execution, root, *output, dependencies.WorkingDir)
	code := execution.Report.PrimaryExitCode
	if executionErr != nil && code == ExitSuccess {
		code, _ = classifyExecutionError(ctx, executionErr)
	}
	if code == ExitSuccess {
		return writeSuccess(dependencies.Stdout, data)
	}
	message := "one or more candidate checks did not pass"
	if executionErr != nil {
		message = executionErr.Error()
	}
	return writeFailure(dependencies.Stderr, code, "candidate_run_not_passed", message, data)
}

func emitPlan(planned productrun.PlannedRun, resolved bool, output string, dependencies Dependencies) int {
	var (
		encoded []byte
		value   any = planned.Intent
		err     error
	)
	if resolved {
		encoded, err = productrun.PlanJSON(planned)
		value = planned
	} else {
		encoded, err = schema.CanonicalMarshal(planned.Intent)
	}
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "plan_encode_failed", err.Error())
	}
	if output == "" {
		return writeSuccess(dependencies.Stdout, map[string]any{
			"network_calls": 0, "resolved": resolved, "plan": value,
		})
	}
	path := absolutePath(dependencies.WorkingDir, output)
	if err := writeNewFile(path, encoded); err != nil {
		code, reason := ExitInfrastructure, "plan_write_failed"
		if errors.Is(err, os.ErrExist) {
			code, reason = ExitInput, "output_exists"
		}
		return writeError(dependencies.Stderr, code, reason, err.Error())
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

func classifyExecutionError(ctx context.Context, err error) (int, string) {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return ExitInterrupted, "interrupted"
	}
	if errors.Is(err, secret.ErrNotFound) || errors.Is(err, secret.ErrExecDisabled) || errors.Is(err, secret.ErrKeyring) {
		return ExitPermission, "credential_unavailable"
	}
	return ExitInfrastructure, "execution_failed"
}
