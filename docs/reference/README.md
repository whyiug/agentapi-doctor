# Reference

This page distinguishes the supported Doctor product from source-only
development components. For command syntax, see the
[CLI reference](../cli-reference.md); for a first run, use the
[Quick Start](../quick-start.md).

## Supported v0.1.0 surface

The supported product is the local `doctor` CLI in `cmd/doctor` and
`internal/cli`. Its user workflows cover target and configuration management,
offline preparation, bounded endpoint checks, run inspection, baselines,
comparison, reporting, and shell completions.

`internal/productrun` and `internal/rawdriver` execute four raw checks against
one exact configured origin for `openai-chat`, `openai-responses`, or
`anthropic-messages`. The checks are observations, not vendor certification.

Run Doctor with either a saved target or explicit endpoint inputs:

```text
doctor demo [--data-root <path>] [--output <path>] [--format terminal|json]
doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>] [--format json|terminal]
doctor test --base-url <url> --protocol <id> --model <id> [--auth-env <name>] [--auth-header <name>] [--allow-plain-http]
```

`--plan-only` performs no target network I/O. `--resolve` is valid only with
`--plan-only`; it includes the offline built-in `ResolvedRunPlan` and does not
probe target capabilities. A normal run stores its report below
`<data-root>/runs` (`.agentapi/runs` by default).

Inspect or render a stored run with:

```text
doctor run inspect <run-ref> [--store <path>] [--allow-latest] [--include-plan]
doctor report <terminal|json|junit|sarif|markdown|html> <run-ref> [--output <path>] [--store <path>] [--allow-latest]
```

Use an exact run ID for CI and durable evidence references. The mutable local
`latest` pointer is rejected unless `--allow-latest` is explicit. The
machine-readable command contract is [`cli/spec.yaml`](../../cli/spec.yaml).

Doctor release archives, checksums, SBOMs, signatures, and provenance are the
supported distribution path. No hosted service, managed image, GitHub Action,
Homebrew formula, Scoop manifest, or package-manager channel is part of the
v0.1.0 support surface.

## Persistence and security boundary

`internal/config`, `internal/planner`, `internal/budget`, and
`internal/executor` implement typed configuration, run preparation, hard
budgets, and execution contracts. `internal/redaction`, `internal/cas`, and
`internal/runstore` implement sanitize-before-store evidence and local run
persistence.

Schemas and migration promises apply only where the release documentation and
[`schemas/migration-floor.yaml`](../../schemas/migration-floor.yaml) explicitly
include an artifact. Other checked-in schemas are experimental repository
contracts and are not stable third-party APIs.

## Experimental repository components

The following source is available for development and deterministic testing,
but is not a supported v0.1.0 product or extension API:

- `reference/server` and `reference/mutant-server` synthetic fixtures;
- `pkg/packapi`, Requirement Catalog records, authored packs, and profiles;
- `pkg/driverprotocol` and generic out-of-process driver contracts;
- `cmd/registry`, `registry/api`, `internal/registry`, and `web/matrix`;
- Registry OpenAPI, support manifests, and trust/attestation models; and
- Compose, OCI, GitHub Action, Homebrew, and Scoop candidates.

The repository records 260 candidate metadata scenarios in
[`specs/catalog-statistics.json`](../../specs/catalog-statistics.json) and 13
targeted synthetic server modes. A normal Doctor run selects four raw checks
for its protocol; catalog counts do not imply executable or supported
coverage.

Build and test repository source with:

```sh
make build
make check
make race
make docker-check   # optional; requires Docker
```

Generated views never replace their source. A promoted versioned artifact and
its digest define the exact input used for a run or observation.
