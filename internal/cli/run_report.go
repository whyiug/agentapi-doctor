package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/whyiug/agentapi-doctor/internal/report"
	"github.com/whyiug/agentapi-doctor/internal/runstore"
)

func runRun(args []string, dependencies Dependencies) int {
	if len(args) == 0 {
		return writeError(dependencies.Stderr, ExitInput, "missing_run_command", "usage: doctor run inspect <run-ref>")
	}
	switch args[0] {
	case "inspect":
		return runInspect(args[1:], dependencies)
	default:
		return writeError(dependencies.Stderr, ExitInput, "unknown_run_command", fmt.Sprintf("unknown run command %q", args[0]))
	}
}

func runInspect(args []string, dependencies Dependencies) int {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor run inspect <run-ref> [--store <path>] [--allow-latest]")
	}
	reference := args[0]
	flags := flag.NewFlagSet("run inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	storePath := flags.String("store", filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), "run store")
	allowLatest := flags.Bool("allow-latest", true, "allow local latest pointer")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor run inspect <run-ref> [--store <path>] [--allow-latest]")
	}
	store, err := runstore.Open(absolutePath(dependencies.WorkingDir, *storePath), 0)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "run_store_open_failed", err.Error())
	}
	record, err := store.Get(reference, *allowLatest)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "run_not_found", err.Error())
	}
	var bundle any
	if err := json.Unmarshal(record.Bundle, &bundle); err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "run_corrupt", err.Error())
	}
	return writeSuccess(dependencies.Stdout, map[string]any{"run_id": record.RunID, "bundle_digest": record.BundleDigest, "bundle": bundle})
}

func runReport(args []string, dependencies Dependencies) int {
	if len(args) < 2 || args[0] == "" || args[1] == "" || args[0][0] == '-' || args[1][0] == '-' {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor report <terminal|json|junit|sarif|markdown|html> <run-ref> [--output <path>] [--store <path>] [--allow-latest]")
	}
	format, reference := args[0], args[1]
	if !slices.Contains([]string{"terminal", "json", "junit", "sarif", "markdown", "html"}, format) {
		return writeError(dependencies.Stderr, ExitInput, "invalid_report_format", fmt.Sprintf("unsupported report format %q", format))
	}
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "output path")
	storePath := flags.String("store", filepath.Join(dependencies.WorkingDir, ".agentapi", "runs"), "run store")
	allowLatest := flags.Bool("allow-latest", true, "allow local latest pointer")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor report <format> <run-ref> [--output <path>]")
	}
	store, err := runstore.Open(absolutePath(dependencies.WorkingDir, *storePath), 0)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "run_store_open_failed", err.Error())
	}
	record, err := store.Get(reference, *allowLatest)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInput, "run_not_found", err.Error())
	}
	bundle, err := report.Decode(record.Bundle)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "invalid_report_bundle", err.Error())
	}
	renderers := map[string]func(report.Bundle) ([]byte, error){"terminal": report.Terminal, "json": report.JSON, "junit": report.JUnit, "sarif": report.SARIF, "markdown": report.Markdown, "html": report.HTML}
	rendered, err := renderers[format](bundle)
	if err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "report_render_failed", err.Error())
	}
	if *output != "" {
		path := absolutePath(dependencies.WorkingDir, *output)
		if err := writeNewFile(path, rendered); err != nil {
			return writeError(dependencies.Stderr, ExitInfrastructure, "report_write_failed", err.Error())
		}
		return writeSuccess(dependencies.Stdout, map[string]any{"run_id": bundle.RunID, "format": format, "output": path})
	}
	if _, err := dependencies.Stdout.Write(rendered); err != nil {
		return writeError(dependencies.Stderr, ExitInfrastructure, "report_write_failed", err.Error())
	}
	if len(rendered) == 0 || rendered[len(rendered)-1] != '\n' {
		_, _ = dependencies.Stdout.Write([]byte("\n"))
	}
	return ExitSuccess
}

func absolutePath(workingDirectory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(workingDirectory, path)
}

func writeNewFile(path string, data []byte) error {
	clean := filepath.Clean(path)
	if err := validateNewFilePath(clean); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return err
	}
	if err := validateNewFilePath(clean); err != nil {
		return err
	}
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace a symlink")
		}
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(clean), ".doctor-output-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(name, clean); err != nil {
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	committed = true
	return nil
}

// validateNewFilePath rejects an existing destination and every symlink or
// non-directory ancestor. The final hard-link commit still supplies the
// no-overwrite guarantee if another process races this preflight check.
func validateNewFilePath(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errors.New("output path must be absolute")
	}
	if _, err := os.Lstat(clean); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	for current := filepath.Dir(clean); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("output path contains a symlink")
			}
			if !info.IsDir() {
				return errors.New("output path ancestor is not a directory")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
