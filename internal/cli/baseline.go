package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/report"
)

const maxBaselineBytes int64 = 16 << 20

func runBaseline(args []string, dependencies Dependencies) int {
	if len(args) == 0 {
		return writeError(dependencies.Stderr, ExitInput, "missing_baseline_command", "usage: doctor baseline <accept|list|inspect|compare> ...")
	}
	switch args[0] {
	case "accept":
		return baselineAccept(args[1:], dependencies)
	case "list":
		return baselineList(args[1:], dependencies)
	case "inspect":
		return baselineInspect(args[1:], dependencies)
	case "compare":
		return baselineCompare(args[1:], dependencies)
	default:
		return writeError(dependencies.Stderr, ExitInput, "unknown_baseline_command", fmt.Sprintf("unknown baseline command %q", args[0]))
	}
}

func baselineAccept(args []string, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline accept <run-ref> --name <name>")
	}
	reference := args[0]
	flags := flag.NewFlagSet("baseline accept", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "baseline name")
	storePath := flags.String("store", filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), "run store")
	baselinePath := flags.String("baseline-dir", filepath.Join(dependencies.WorkingDir, ".agentapi", "baselines"), "baseline directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *name == "" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline accept <run-ref> --name <name>")
	}
	bundle, err := loadReport(reference, *storePath, true, dependencies)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "run_not_found", err.Error())
	}
	baseline, err := report.NewBaseline(*name, bundle)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "baseline_invalid", err.Error())
	}
	encoded, err := report.BaselineJSON(baseline)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "baseline_encode_failed", err.Error())
	}
	path, err := baselineFile(dependencies.WorkingDir, *baselinePath, *name)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "baseline_invalid", err.Error())
	}
	if err := writeNewFile(path, encoded); err != nil {
		code := ExitInfrastructure
		reason := "baseline_write_failed"
		if errors.Is(err, os.ErrExist) {
			code = ExitInput
			reason = "baseline_exists"
		}
		return writeError(dependencies.Stderr, code, reason, err.Error())
	}
	return writeSuccess(dependencies.Stdout, map[string]any{"name": *name, "run_id": bundle.RunID, "path": path})
}

func baselineList(args []string, dependencies Dependencies) int {
	flags := flag.NewFlagSet("baseline list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("baseline-dir", filepath.Join(dependencies.WorkingDir, ".agentapi", "baselines"), "baseline directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline list")
	}
	path := absolutePath(dependencies.WorkingDir, *directory)
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return writeSuccess(dependencies.Stdout, map[string]any{"baselines": []string{}})
	}
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "baseline_list_failed", err.Error())
	}
	names := []string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			name := strings.TrimSuffix(entry.Name(), ".json")
			if _, err := baselineFile(dependencies.WorkingDir, path, name); err == nil {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return writeSuccess(dependencies.Stdout, map[string]any{"baselines": names})
}

func baselineInspect(args []string, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline inspect <name>")
	}
	name := args[0]
	flags := flag.NewFlagSet("baseline inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("baseline-dir", filepath.Join(dependencies.WorkingDir, ".agentapi", "baselines"), "baseline directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline inspect <name>")
	}
	baseline, err := loadBaseline(dependencies.WorkingDir, *directory, name)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "baseline_not_found", err.Error())
	}
	return writeSuccess(dependencies.Stdout, baseline)
}

func baselineCompare(args []string, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline compare <run-ref> --baseline <name>")
	}
	reference := args[0]
	flags := flag.NewFlagSet("baseline compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("baseline", "", "baseline name")
	storePath := flags.String("store", filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), "run store")
	directory := flags.String("baseline-dir", filepath.Join(dependencies.WorkingDir, ".agentapi", "baselines"), "baseline directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *name == "" {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor baseline compare <run-ref> --baseline <name>")
	}
	before, err := loadBaseline(dependencies.WorkingDir, *directory, *name)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "baseline_not_found", err.Error())
	}
	bundle, err := loadReport(reference, *storePath, true, dependencies)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "run_not_found", err.Error())
	}
	after, err := report.NewBaseline(*name, bundle)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "run_not_comparable", err.Error())
	}
	return emitComparison(before, after, dependencies)
}

func runCompare(args []string, dependencies Dependencies) int {
	if len(args) != 2 || args[0] == "" || args[1] == "" || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor compare <run-ref> <run-ref>")
	}
	left, err := loadReport(args[0], filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), true, dependencies)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "left_run_not_found", err.Error())
	}
	right, err := loadReport(args[1], filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), true, dependencies)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "right_run_not_found", err.Error())
	}
	before, err := report.NewBaseline("comparison", left)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "left_run_not_comparable", err.Error())
	}
	after, err := report.NewBaseline("comparison", right)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "right_run_not_comparable", err.Error())
	}
	return emitComparison(before, after, dependencies)
}

func emitComparison(before, after report.Baseline, dependencies Dependencies) int {
	differences, err := report.Compare(before, after)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "incomparable", err.Error())
	}
	regression := false
	for _, difference := range differences {
		if difference.Change == report.Regression || difference.Change == report.NewFailure {
			regression = true
		}
	}
	data := map[string]any{"baseline": before.Name, "differences": differences}
	if regression {
		return writeFailure(dependencies.Stdout, ExitBaselineRegression, "baseline_regression", "one or more scenarios regressed", data)
	}
	return writeSuccess(dependencies.Stdout, data)
}

func loadReport(reference, storePath string, allowLatest bool, dependencies Dependencies) (report.Bundle, error) {
	loaded, err := loadValidatedRun(reference, storePath, allowLatest, dependencies)
	if err != nil {
		return report.Bundle{}, err
	}
	return loaded.Bundle, nil
}
func baselineFile(working, directory, name string) (string, error) {
	if !scaffoldName.MatchString(name) {
		return "", errors.New("invalid baseline name")
	}
	candidate := absolutePath(working, directory)
	return filepath.Join(candidate, name+".json"), nil
}
func loadBaseline(working, directory, name string) (report.Baseline, error) {
	path, err := baselineFile(working, directory, name)
	if err != nil {
		return report.Baseline{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return report.Baseline{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBaselineBytes {
		return report.Baseline{}, errors.New("baseline must be a bounded regular non-symlink file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return report.Baseline{}, err
	}
	baseline, err := report.DecodeBaseline(raw)
	if err != nil {
		return report.Baseline{}, err
	}
	if baseline.Name != name {
		return report.Baseline{}, errors.New("baseline name does not match filename")
	}
	return baseline, nil
}
