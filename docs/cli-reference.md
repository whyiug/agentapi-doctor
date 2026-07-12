# CLI Reference

[Documentation home](README.md) | [Configuration](configuration.md)

This page documents the implemented `doctor` command surface in the current
source tree. It is a pre-release interface and may change before the first
tagged release. The machine-readable contract is
[`cli/spec.yaml`](../cli/spec.yaml).

## General behavior

Run `doctor help` for the top-level usage line. There are no global flags;
place each command's flags in the positions shown below.

Most commands emit a JSON envelope:

```json
{
  "schema_version": "urn:agentapi-doctor:cli-result:v1alpha1",
  "status": "pass",
  "primary_exit_code": 0,
  "conditions": [],
  "data": {}
}
```

Errors use the same envelope on stderr. Exceptions are:

- `doctor version` without `--json` prints one text line;
- `doctor completion` prints a shell completion script; and
- `doctor report` writes the selected report format directly to stdout unless
  `--output` is used;
- inline `doctor test` and `doctor demo` default to a terminal report, while
  `--format json` selects the JSON envelope.

Commands that create a config, plan, report, baseline, or scaffold refuse to
overwrite an existing destination.

## Project and target setup

### `doctor init [<directory>]`

Create `<directory>/.agentapi/config.yaml`, or
`./.agentapi/config.yaml` when no directory is supplied.

### `doctor self-check [--config <path>]`

Validate local runtime information and, when present, the config file. This is
offline and reports `network_calls: 0`.

### `doctor target add`

```text
doctor target add <name> --base-url <url> --protocol <id> --model <id>
  [--auth-ref <secret-ref>] [--config <path>]
```

Add one target. `--auth-ref` creates bearer authentication; use YAML directly
for custom-header authentication. Existing target names are not overwritten.

### `doctor target list [--config <path>]`

List configured target names.

### `doctor target inspect <target> [--config <path>]`

Show one target. Secret-reference details are redacted.

## Plan and execute

### `doctor test`

```text
doctor test <target> [--config <path>] [--data-root <path>]
  [--plan-only] [--resolve] [--output <path>] [--format json|terminal]

doctor test --base-url <url> --protocol <id> --model <id>
  [--auth-env <name>] [--auth-header <name>] [--allow-plain-http]
  [--data-root <path>] [--plan-only] [--resolve] [--output <path>]
  [--format json|terminal]
```

The first form loads a named target from config. The second creates an inline
target for one run and never creates or changes `.agentapi/config.yaml`.
Without `--plan-only`, both forms execute at most four checks and persist the
canonical run under `<data-root>/runs`; the default data root is `.agentapi`.

Flags:

| Flag | Behavior |
| --- | --- |
| `--config <path>` | Use an alternate config file. |
| `--base-url <url>` | Select an inline target; requires `--protocol` and `--model`. |
| `--protocol <id>` | Use `openai-chat`, `openai-responses`, or `anthropic-messages`. |
| `--model <id>` | Model identifier placed in each bounded synthetic request. |
| `--auth-env <name>` | Read the inline credential from this environment variable. |
| `--auth-header <name>` | Send the credential in a custom header instead of Bearer authorization; requires `--auth-env`. |
| `--allow-plain-http` | Explicitly allow an inline `http://` target; HTTPS is otherwise required. This does not override forbidden-address checks. |
| `--data-root <path>` | Change the evidence and run-store root. |
| `--plan-only` | Build a plan without target I/O, secret resolution, or run persistence. |
| `--resolve` | Include the offline built-in `ResolvedRunPlan` snapshot; this does not probe target capabilities and requires `--plan-only`. |
| `--output <path>` | Write canonical plan JSON or the canonical run report to a new file. |
| `--format <json\|terminal>` | Select stdout/stderr presentation; configured targets default to JSON and inline targets default to terminal. |

The normal run is the command that can contact the configured target. Use it
only with explicit authorization.

### `doctor demo`

```text
doctor demo [--data-root <path>] [--output <path>]
  [--format terminal|json]
```

Run the built-in `openai-responses` fixture in-process on a random loopback
port. It needs no credential or config, contacts no external endpoint, stops
its listener automatically, and defaults to the terminal report.

## Inspect and compare runs

Run references are UUIDv7 run IDs or the local convenience name `latest`.
Use exact run IDs in CI and durable evidence.

### `doctor run inspect`

```text
doctor run inspect <run-ref> [--store <path>] [--allow-latest]
  [--include-plan]
```

Load the canonical stored bundle, its digest, and whether a persisted plan is
available. The default store is `.agentapi/runs`. `--allow-latest` defaults to
true; pass `--allow-latest=false` to require an exact ID. `--include-plan`
includes the validated persisted plan; legacy records without one fail
clearly when that flag is requested.

### `doctor compare <left-run-ref> <right-run-ref>`

Compare two runs from the default `.agentapi/runs` store. A detected regression
uses exit code 6.

## Baselines

Baseline names use a lowercase letter followed by at most 63 lowercase
letters, digits, dots, underscores, or hyphens. The default directory is
`.agentapi/baselines`.

### `doctor baseline accept`

```text
doctor baseline accept <run-ref> --name <name>
  [--store <path>] [--baseline-dir <path>]
```

Create a new baseline from a stored run. Existing baseline files are not
overwritten.

### `doctor baseline list [--baseline-dir <path>]`

List baseline names. A missing baseline directory produces an empty list.

### `doctor baseline inspect <name> [--baseline-dir <path>]`

Load and validate one baseline.

### `doctor baseline compare`

```text
doctor baseline compare <run-ref> --baseline <name>
  [--store <path>] [--baseline-dir <path>]
```

Compare a run with a named baseline. A regression or new failure uses exit
code 6.

## Reports

```text
doctor report <terminal|json|junit|sarif|markdown|html> <run-ref>
  [--output <path>] [--store <path>] [--allow-latest]
```

The default store is `.agentapi/runs`. Without `--output`, the rendered report
is written directly to stdout. With `--output`, the report is written to a new
file and the CLI emits a JSON success envelope.

Examples:

```sh
./bin/doctor report terminal latest
RUN_ID='<exact-run-id>'
./bin/doctor report sarif "$RUN_ID" --output ./doctor.sarif
./bin/doctor report html "$RUN_ID" --output ./doctor-report.html
```

## Developer helpers

### `doctor dev scaffold`

```text
doctor dev scaffold <requirement|scenario|fixture|profile|driver> <name>
  --output <directory>
```

Create `<directory>/<name>.yaml` from a draft template. Names follow the same
format as baseline names, and existing files are not overwritten.

### `doctor completion <bash|zsh|fish|powershell>`

Write a top-level command completion script to stdout.

### `doctor version [--json]`

Print build version, commit, and build time. Local source builds normally
identify themselves as development builds unless build metadata was injected.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Hard checks passed, or the command completed successfully. |
| 1 | Target/profile check failure. |
| 2 | Configuration, DSL, or command-input error. |
| 3 | Harness, driver, storage, or infrastructure error. |
| 4 | Budget exhausted or result incomplete/inconclusive. |
| 5 | Authentication, credential, or permission error. |
| 6 | Baseline regression. |
| 130 | Interrupted or cancelled. |

When multiple conditions exist, the CLI chooses one primary exit code using
the precedence recorded in `cli/spec.yaml`. Automation should use both the
process exit code and the structured conditions instead of parsing prose.
