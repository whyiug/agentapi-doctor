# AgentAPI Doctor

[English](README.md) | [简体中文](README.zh-CN.md)

AgentAPI Doctor is an evidence-first compatibility laboratory for agentic LLM
APIs. It helps you determine whether a failure belongs to the HTTP/wire layer,
the provider or model, the client, or the test harness—and keeps the evidence
needed to reproduce that conclusion.

> **Project status:** active development. The CLI can be built and exercised
> from source, but there is currently no tagged release, published package, or
> hosted service. A passing result is a version-bound observation, not vendor
> certification or an endorsement.

## What works today

- A local raw-HTTP runner for `openai-chat`, `openai-responses`, and
  `anthropic-messages`.
- Four built-in checks selected for each target protocol.
- A loopback-only synthetic reference server with 12 executable targeted
  reference/mutant modes.
- Offline planning, hard request/token/time budgets, exact-origin transport,
  redaction before persistence, and content-addressed evidence.
- Local run inspection, comparison, baselines, and terminal, JSON, JUnit,
  SARIF, Markdown, and standalone HTML reports.
- A source-buildable SQLite Registry, local Compose setup, and Matrix UI.

The Requirement Catalog contains **260 candidate scenario records**. Those
records are metadata for future coverage and review; they are not 260
executable tests. The current reference server exposes **12 executable
targeted modes**, while a normal target run selects **4 checks** for that
target's protocol.

## 60-second local check

This example uses only a synthetic service bound to `127.0.0.1`. It needs no
API key and contacts no public endpoint.

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
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

The final report should show `COMPATIBLE` and four passing cases for the local
fixture. That verifies the checked-in runner and fixture together; it does not
make a claim about another endpoint.

See the dedicated [Quick Start](docs/quick-start.md) for interpretation and
cleanup details.

## Install and use

There is no supported binary or package release yet. Build the current source
with the Go toolchain selected by `go.mod`:

```sh
mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
./bin/doctor version
```

`make build` compile-checks all project commands but does not install them.
Docker images can also be built locally from the checked-in Dockerfile.

Start with:

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli-reference.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Full documentation map](docs/README.md)

## Develop

The main local checks are:

```sh
make check
make test
make race
make docker-check
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change. Commits use
the Developer Certificate of Origin sign-off.

## Safety and result boundaries

Only test endpoints and source repositories you are authorized to assess.
Never place production keys, private traces, or unredacted provider payloads
in issues, pull requests, fixtures, reports, or artifacts.

Current results cover a deliberately small raw-wire slice. They do not yet
establish compatibility for a complete SDK, agent, model, provider, or
deployment. See [Known limitations](docs/known-limitations/README.md) for the
exact current boundaries.

## Community and security

- Ask usage questions through [SUPPORT.md](SUPPORT.md).
- Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- See [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md) for
  project stewardship.

## License

Unless a file says otherwise, source and documentation are licensed under the
[Apache License 2.0](LICENSE). Dataset and Registry-specific terms are
described in [DATA_LICENSE.md](DATA_LICENSE.md). Dependency license texts are
collected in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
