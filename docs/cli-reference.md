# CLI Reference

[Documentation home](README.md) | [Configuration](configuration.md)

This page documents the supported `doctor` command surface in `v0.1.0`. It is
a pre-1.0 interface and may change in a later minor release with documented
migration notes. The machine-readable contract is
[`cli/spec.yaml`](../cli/spec.yaml).

## General behavior

Run `doctor help` for quick paths and the command list, or
`doctor help <command>` for focused usage. Every documented command and
subcommand accepts `-h` or `--help` and returns 0 without side effects. There
are no global flags; place each command's flags in the positions shown below.

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

Commands that create a config, plan, report, or baseline refuse to
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
Treat `.agentapi/` as private local state and add it to the tested project's
`.gitignore`.

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

### `doctor reproduce openai-python-responses`

```text
doctor reproduce openai-python-responses
  --python <python-3.12.12>
  --fixture <reference|missing-terminal-event|duplicate-terminal-event|null-completed-output>
  --bundle <new.zip> [--format terminal|json]
```

Run one frozen OpenAI Python SDK 2.38.0 Responses streaming case and write a
maintainer-ready evidence ZIP. The command is Linux amd64 only, starts a random
`127.0.0.1` fixture, sends one request with a synthetic token, never reads an
API key, and never contacts a provider. The supplied Python environment must
report CPython 3.12.12 on Linux x86_64 and the exact 16 locked distribution
names and versions. Wheel hashes are enforced while constructing the
environment; runtime attestation records installed metadata and the Python
executable digest, but does not rehash every installed package file.

The result correlates captured raw SSE with the SDK observation. A matching
reference or targeted mutant returns 0 and reports `confirmed`; an environment,
wire, fixture-identity, or SDK-observation mismatch writes an `unknown` bundle
and returns 4. The bundle path must not already exist.

See the [real SDK case](cases/openai-python-responses-null-output.md) for the
offline wheelhouse install, expected output, evidence files, and interpretation
boundary.

## Inspect and compare runs

Run references are UUIDv7 run IDs or the local convenience name `latest`.
Use exact run IDs by default. `latest` is rejected unless the command receives
the explicit local convenience flag `--allow-latest`; never use it in CI or
durable evidence.

### `doctor run inspect`

```text
doctor run inspect <run-ref> [--store <path>] [--allow-latest]
  [--include-plan]
```

Load the canonical stored bundle, its digest, and whether a persisted plan is
available. The default store is `.agentapi/runs`. `--allow-latest` defaults to
false. `--include-plan`
includes the validated persisted plan; legacy records without one fail
clearly when that flag is requested.

### `doctor compare [--allow-latest] <left-run-ref> <right-run-ref>`

Compare two runs from the default `.agentapi/runs` store. A detected regression
uses exit code 6.

## Baselines

Baseline names use a lowercase letter followed by at most 63 lowercase
letters, digits, dots, underscores, or hyphens. The default directory is
`.agentapi/baselines`.

### `doctor baseline accept`

```text
doctor baseline accept <run-ref> --name <name>
  [--store <path>] [--baseline-dir <path>] [--allow-latest]
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
  [--store <path>] [--baseline-dir <path>] [--allow-latest]
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
./bin/doctor report terminal latest --allow-latest
RUN_ID='<exact-run-id>'
./bin/doctor report sarif "$RUN_ID" --output ./doctor.sarif
./bin/doctor report html "$RUN_ID" --output ./doctor-report.html
```

## Shell and build information

### `doctor completion <bash|zsh|fish|powershell>`

Write a top-level command completion script to stdout.

### `doctor version [--json]`

Print build version, commit, and build time. Release archives use injected
immutable metadata; tagged `go install` builds fall back to Go module and VCS
build information. Untagged local builds identify themselves as development
builds.

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
