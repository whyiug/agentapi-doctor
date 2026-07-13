# Getting Started from Source

[Documentation home](../README.md) | [简体中文](../zh-CN/getting-started.md)

This contributor-oriented guide moves from a source checkout to an authorized
target run, stored evidence, and exported reports. Most users should install
the prebuilt CLI through the [Quick Start](../quick-start.md). A passing result
is not vendor certification.

For the shortest credential-free path, use the one-command
[Quick Start](../quick-start.md).

## Prerequisites

- Git
- The Go toolchain selected by `go.mod`
- A POSIX-compatible shell for the examples below
- Python 3 and Make for the full contributor checks
- Docker only for container checks and local Compose services

## Build from the default branch

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
go build -trimpath -o ./bin/reference-server ./cmd/reference-server

./bin/doctor version
./bin/doctor self-check
```

Windows users can build `./bin/doctor.exe` and
`./bin/reference-server.exe` with the same package paths. See
[Installation](../installation.md) for PowerShell release verification.

## Initialize the local project

```sh
./bin/doctor init
./bin/doctor target list
```

Initialization creates `.agentapi/config.yaml` and refuses to overwrite it.
The generated `local-reference` target points to
`http://127.0.0.1:8090/v1` and uses `openai-responses`.

Treat the entire `.agentapi/` directory as private local state. This source
tree ignores it; add `.agentapi/` to the `.gitignore` of every downstream
project before running Doctor there.

Read [Configuration](../configuration.md) before editing the file or adding a
credential.

## Run the synthetic fixture

Start the checked-in fixture in one shell:

```sh
./bin/reference-server -listen 127.0.0.1:8090
```

Run the configured checks in another:

```sh
./bin/doctor test local-reference
./bin/doctor run inspect latest --allow-latest
./bin/doctor report terminal latest --allow-latest
```

Stop only the reference-server process you started. A normal run stores
canonical records in `.agentapi/runs` and redacted evidence in
`.agentapi/evidence`.

## Add an authorized endpoint

Use a secret reference rather than a secret value:

```sh
export EXAMPLE_API_TOKEN='replace-with-a-local-or-test-token'

./bin/doctor target add example \
  --base-url https://api.example.invalid/v1 \
  --protocol openai-responses \
  --model example-model \
  --auth-ref env://EXAMPLE_API_TOKEN
```

`example.invalid` is deliberately non-routable. Replace it only with a local
service or endpoint you are explicitly authorized to test.

The current runner implements `openai-chat`, `openai-responses`, and
`anthropic-messages`. It appends the corresponding operation path to the
configured base URL, stays on the exact configured origin, and does not follow
redirects.

Inspect the target without revealing its secret reference:

```sh
./bin/doctor target inspect example
```

## Inspect the plan before network access

`--plan-only` does not dial the target, resolve credentials, or write run
evidence:

```sh
./bin/doctor test example --plan-only
./bin/doctor test example --plan-only --resolve
./bin/doctor test example --plan-only --resolve --output ./example-plan.json
```

`--resolve` requires `--plan-only` and includes the offline built-in
`ResolvedRunPlan`; it does not probe target capabilities. Output files are
created only when the path does not already exist.

## Execute and keep an exact run reference

```sh
./bin/doctor test example
```

The JSON result contains `data.run_id` and the primary exit code. Use that
exact run ID for CI and durable evidence:

```sh
RUN_ID='<exact-run-id-from-doctor-test>'
./bin/doctor run inspect "$RUN_ID"
./bin/doctor report json "$RUN_ID" --output ./doctor-report.json
```

`latest` is a mutable local convenience pointer and requires explicit
`--allow-latest`.

For a custom data root, pass its run store to later commands:

```sh
./bin/doctor test local-reference --data-root ./local-data
./bin/doctor report terminal latest --allow-latest --store ./local-data/runs
```

## Render reports and compare runs

Reports are available as `terminal`, `json`, `junit`, `sarif`, `markdown`,
and `html`:

```sh
./bin/doctor report junit latest --allow-latest --output ./doctor-junit.xml
./bin/doctor report sarif latest --allow-latest --output ./doctor.sarif
./bin/doctor report html latest --allow-latest --output ./doctor-report.html
```

Create and compare a named local baseline:

```sh
./bin/doctor baseline accept latest --allow-latest --name local-known-good
./bin/doctor baseline list
./bin/doctor baseline compare latest --allow-latest --baseline local-known-good
```

You can also compare two exact runs from the default store:

```sh
OLD_RUN_ID='<exact-older-run-id>'
NEW_RUN_ID='<exact-newer-run-id>'
./bin/doctor compare "$OLD_RUN_ID" "$NEW_RUN_ID"
```

See the [CLI reference](../cli-reference.md) for exact flags, baseline naming,
output behavior, and exit codes.

## Interpret the result correctly

- The local fixture is synthetic and deterministic. Its PASS only verifies the
  current runner and fixture together.
- A normal target run selects four built-in raw-wire checks for the configured
  protocol.
- The reference server contains 13 executable targeted modes.
- The Requirement Catalog's 260 candidate scenario records are metadata, not
  260 executable tests.
- Current checks do not prove complete SDK, agent, model, provider, or
  deployment compatibility.
- A report is not certification, endorsement, or a guarantee of behavior
  outside the tested endpoint, model, built-in pack/profile digests, plan, and
  evidence. It does not automatically attest the CLI source commit.

Only test endpoints you are authorized to assess. Keep real credentials,
private traces, and unredacted payloads out of issues and artifacts.

## Run contributor checks

Run the narrowest relevant test first, then the appropriate aggregate:

```sh
make check
make test
make race
make docker-check
```

- `make check` runs the complete local quality gate.
- `make test` runs all Go tests.
- `make race` runs all Go tests with the race detector.
- `make docker-check` builds and smokes the hardened local image targets.

Read [Synthetic fixtures](synthetic-fixtures.md) before contributing evidence,
and [CONTRIBUTING.md](../../CONTRIBUTING.md) before opening a pull request.

## Where to go next

- [Troubleshooting](../troubleshooting.md)
- [Concepts](../concepts/README.md)
- [Security and privacy](../security-and-privacy/README.md)
- [Registry self-hosting](../registry/README.md)
- [Known limitations](../known-limitations/README.md)
