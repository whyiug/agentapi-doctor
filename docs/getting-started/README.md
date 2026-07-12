# Getting Started from Source

The repository provides a source-buildable `doctor` candidate and a
deterministic local reference server. It does not provide a supported package
release or compatibility certification. Everything below is pre-Genesis,
pre-release development behavior outside any claim of active phase execution.

## Prerequisites

- Git;
- the Go toolchain selected by `go.mod`; and
- Python 3 for bootstrap, integration, and documentation checks.

Docker is optional and needed only for the container/Compose paths. Do not put
an API key in the repository: the synthetic quickstart uses no credential.

## Run the local synthetic fixture

The following session builds both binaries, starts only a loopback listener,
and installs a trap that stops the process and removes its temporary log. Run
it from a fresh checkout because `doctor init` intentionally refuses to
overwrite an existing `.agentapi/config.yaml`.

```sh
git clone --branch agent/full-project-r4 --single-branch https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -o ./bin/doctor ./cmd/doctor
go build -o ./bin/reference-server ./cmd/reference-server

reference_log="${TMPDIR:-/tmp}/agentapi-doctor-reference.$$"
./bin/reference-server -listen 127.0.0.1:8090 >"$reference_log" 2>&1 &
reference_pid=$!
trap 'kill "$reference_pid" 2>/dev/null || true; wait "$reference_pid" 2>/dev/null || true; rm -f "$reference_log"' EXIT INT TERM
sleep 1

./bin/doctor init
./bin/doctor test local-reference
./bin/doctor report terminal latest
```

The generated config defines `local-reference` as an `openai-responses` target
at `http://127.0.0.1:8090/v1`. The test command therefore executes exactly four
candidate checks from that built-in protocol slice. It saves a canonical report
under `.agentapi/runs`, and the report command reads that same store by default.

The candidate runner also has four selected checks for each of `openai-chat`
and `anthropic-messages`. A configured target selects one protocol and four
checks per run; the quickstart does not execute all twelve checks at once.

## Inspect a run plan without network access

`--plan-only` builds and validates the candidate IntentPlan and exact
ResolvedRunPlan without dialing the target, resolving a secret, or writing run
evidence:

```sh
./bin/doctor test local-reference --plan-only
./bin/doctor test local-reference --plan-only --output ./local-plan.json
```

`--resolve` is accepted only together with `--plan-only`. The current built-in
slice has no capability probe and resolves its exact candidate artifacts
offline; the separate flag preserves the intended planning boundary rather
than turning a normal run into an implicit probe.

The complete candidate command shape is:

```text
doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>]
```

A normal run stores records in `<data-root>/runs`; the default data root is
`.agentapi`, so `doctor report terminal latest` uses `.agentapi/runs`. If a run
uses a custom data root, point the renderer to it explicitly:

```sh
./bin/doctor test local-reference --data-root ./local-data
./bin/doctor report terminal latest --store ./local-data/runs
```

Use an exact run ID instead of `latest` in CI or durable evidence references.
Report output is also available as JSON, JUnit, SARIF, Markdown, and standalone
HTML.

## Understand what the result means

- The reference fixture is deterministic, synthetic, and operated by the
  local user. A PASS verifies only the selected candidate assertions against
  that fixture.
- The 12 checked-in targeted mutation modes are executable local fixtures.
  Separately, the Requirement Catalog's 260 candidate scenarios and associated
  reference/mutant records are metadata; they are not 260 executable mutants.
- Catalog assertions remain `candidate` / `pending_review`. No support Tier,
  real SDK/client result, vendor endorsement, or stable protocol claim follows
  from a run.
- A normal test is allowed to contact only the configured target. Never point
  it at a public service unless you are explicitly authorized to test it.

## Run repository checks

For development, run the narrowest relevant test first and then the applicable
aggregate checks:

```sh
make -f Product.mk product-check
make test-protected-verifier
make -f Product.mk race-product
```

`make -f Product.mk docker-build-check` additionally builds and smokes the
three hardened container targets without build-time network access.
`make test-protected-verifier` runs the bounded verifier unit tests only. The
whole-tree `make verify` command and complete `make test-bootstrap` suite
intentionally reject product implementation before Genesis unless they are run
against a separately approved exact control-plane candidate;
`candidate_valid`, when applicable there, does not activate P00 or approve a
phase.

The redaction and content-addressed-store security fixtures use synthetic
canaries only:

```sh
go test ./internal/redaction -run TestJSONAndTextNeverPersistCanaryOrCredential -v
go test ./internal/cas -run TestStoreAcceptsOnlySanitizedPayloadAndDetectsTamper -v
```

See [Synthetic fixtures](synthetic-fixtures.md) before contributing evidence,
and [Compatibility layers](../concepts/compatibility-layers.md) for the failure
boundaries a complete result preserves.
