# Reference

This page maps the runnable source and versioned contracts. For command syntax,
see the [CLI reference](../cli-reference.md); for a first run, use the
[Quick Start](../quick-start.md).

## Runnable components

- `cmd/doctor` and `internal/cli` — initialization, target/config management,
  offline planning, client-side execution, run inspection, comparison,
  baselines, reporting, completions, and development scaffolding.
- `internal/productrun` and `internal/rawdriver` — execution against one exact
  configured origin for `openai-chat`, `openai-responses`, and
  `anthropic-messages`.
- `reference/server` and `reference/mutant-server` — deterministic synthetic
  protocol fixtures and 13 executable targeted mutation modes.
- `internal/config`, `internal/planner`, `internal/budget`, and
  `internal/executor` — typed configuration, IntentPlan/ResolvedRunPlan, hard
  budgets, and execution contracts.
- `internal/redaction`, `internal/cas`, and `internal/runstore` —
  sanitize-before-store evidence and local run persistence.
- `cmd/registry`, `registry/api`, and `internal/registry` — local Registry HTTP
  surface with memory or single-node SQLite storage and consistent backup.
- `web/matrix` — static Matrix UI source; the project does not currently host
  it as a service.

Build and check the current source with:

```sh
make build
make check
make race
make docker-check   # optional; requires Docker
```

## CLI execution and reports

The CLI runs locally, while its configured exact origin may be a local,
private-network, or remote authorized endpoint:

```text
doctor demo [--data-root <path>] [--output <path>] [--format terminal|json]
doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>] [--format json|terminal]
doctor test --base-url <url> --protocol <id> --model <id> [--auth-env <name>] [--auth-header <name>] [--allow-plain-http]
```

`--plan-only` performs no target network I/O. `--resolve` is valid only with
`--plan-only`; it includes the offline built-in `ResolvedRunPlan` and does not
probe target capabilities. A normal run stores its report below
`<data-root>/runs` (`.agentapi/runs` by default).

Stored runs can be inspected or rendered with:

```text
doctor run inspect <run-ref> [--store <path>] [--allow-latest] [--include-plan]
doctor report <terminal|json|junit|sarif|markdown|html> <run-ref> [--output <path>] [--store <path>] [--allow-latest]
```

`latest` is convenient for local interactive use. CI and durable evidence
references should use an exact run ID. The machine-readable command contract is
[`cli/spec.yaml`](../../cli/spec.yaml).

## Schemas and generated indexes

The repository includes versioned artifacts for:

- configuration and the common envelope;
- IntentPlan, CapabilityObservation, and ResolvedRunPlan;
- evidence, results, reports, and catalog statistics;
- scenarios, protocol snapshots, Requirement Catalog records, packs, and
  profiles;
- Driver RPC control/data frames and support manifests;
- Registry observations and Registry OpenAPI; and
- the schema index and migration floor.

Run `make schema-check` to verify schema references, generated catalog digests,
and support-manifest consistency. These are pre-release contracts until a
release explicitly declares a stable compatibility floor.

## Catalog counts

[`specs/catalog-statistics.json`](../../specs/catalog-statistics.json) records
260 metadata scenarios across seven packs. Those reference and targeted-mutant
records must not be confused with the 13 executable targeted mutation modes or
the four selected checks per protocol in the current client-side runner.

## Registry and release tooling

The Registry OpenAPI, SQLite store, backup path, Compose configuration, Matrix,
GitHub Action/reusable workflow, Homebrew/Scoop metadata, GoReleaser
configuration, checksums/SBOM/provenance flow, and CI/CD workflows are testable
from this repository. No hosted verifier or service exists, and no distribution
artifact has been published yet.

Generated views never replace their source: a versioned artifact and its digest
define the exact input used for a run or observation.
