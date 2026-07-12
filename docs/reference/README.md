# Reference

All surfaces listed here are pre-release candidates. A checked-in schema,
manifest, or executable path is not evidence of support, independent review,
Genesis, or publication.

## Runnable source surfaces

- `cmd/doctor` and `internal/cli` — candidate local CLI for initialization,
  target/config management, offline plan generation, local candidate execution,
  run inspection, comparison/baseline operations, report rendering,
  completions, and development scaffolding.
- `internal/productrun` and `internal/rawdriver` — exact-origin local execution
  for three protocol IDs, with four Requirement-Catalog-linked candidate checks
  selected per target protocol.
- `reference/server` and `reference/mutant-server` — deterministic synthetic
  protocol fixtures and 12 executable targeted mutation modes.
- `internal/config`, `internal/planner`, `internal/budget`, and
  `internal/executor` — candidate configuration, IntentPlan/ResolvedRunPlan,
  budget, and execution contracts.
- `internal/redaction`, `internal/cas`, and `internal/runstore` —
  sanitize-before-store evidence and local run persistence candidates.
- `cmd/registry`, `registry/api`, and `internal/registry` — local Registry HTTP
  surface with memory or single-node SQLite storage and consistent backup.
- `web/matrix` — static candidate Matrix UI source. It is not hosted by the
  project.

Build and check the current source with:

```sh
go build ./cmd/doctor ./cmd/registry ./cmd/reference-server
make -f Product.mk product-check
make test-protected-verifier
```

`make test-protected-verifier` runs the bounded verifier unit suite without
creating approval or phase state. The whole-tree `make verify` check and
complete `make test-bootstrap` suite intentionally reject this
product-candidate tree before Genesis unless an exact separate control-plane
candidate has been approved. Use `make -f Product.mk race-product` and
`make -f Product.mk docker-build-check` for the
additional concurrency and container paths.

## CLI candidate

The local execution command is:

```text
doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>]
```

`--plan-only` performs no target network I/O. `--resolve` is valid only with
`--plan-only`; the current built-in scenarios resolve exact artifacts offline
without a capability probe. A normal run stores its report below
`<data-root>/runs` (`.agentapi/runs` by default).

Stored reports can be rendered with:

```text
doctor report <terminal|json|junit|sarif|markdown|html> <run-ref> [--output <path>] [--store <path>] [--allow-latest]
```

`latest` is for interactive local use. CI and durable references should use an
exact run ID.

The machine-readable source for the candidate command surface is
[`cli/spec.yaml`](../../cli/spec.yaml). Breaking a future stable operand,
flag/default, exit code, or JSON output requires the applicable versioning and
governance process; that stable contract has not been declared yet.

## Candidate schemas and generated indexes

The repository currently includes versioned candidate artifacts for:

- configuration and the common envelope;
- IntentPlan, CapabilityObservation, and ResolvedRunPlan;
- evidence, result, report bundle, and catalog statistics;
- scenarios, protocol snapshots, Requirement Catalog records, packs, and
  profiles;
- Driver RPC control/data frames and support manifests/locks;
- Registry observations and Registry OpenAPI; and
- the schema index and migration floor.

Run `make -f Product.mk schema-check` to verify schema references, generated catalog digests,
and support-manifest consistency. These artifacts are public candidate inputs,
not a stable migration promise.

## Catalog counts

[`specs/catalog-statistics.json`](../../specs/catalog-statistics.json) records
260 candidate metadata scenarios across seven packs. The associated reference
and targeted-mutant counts are metadata/provenance records. They must not be
confused with the 12 executable targeted mutation modes or the three-by-four
checks in the current local runner. The catalog explicitly records that Tier 1,
independent review, real-SDK validation, and live-provider verification are
false.

## Registry and release candidates

The Registry OpenAPI, SQLite store, local backup, Compose configuration, Matrix,
GitHub Action/reusable workflow, Homebrew/Scoop metadata, GoReleaser
configuration, checksums/SBOM/provenance flow, and CI/CD workflows are all
testable repository candidates. No hosted verifier or service exists, and no
distribution artifact has been published.

Generated views do not become a separate authority: the versioned source
artifact and its digest control candidate semantics. After Genesis, any change
to execution authority must follow the Plan's append-only state rules.
