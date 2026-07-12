# AgentAPI Doctor

AgentAPI Doctor is an evidence-first compatibility laboratory for agentic LLM
APIs. It is designed to explain whether a failure belongs to the wire,
provider/model, client, or harness layer instead of treating one successful
HTTP request as compatibility.

> **Status:** this is a pre-Genesis, pre-release development candidate. The
> authoritative execution boundary remains P00.B00. The source tree contains
> runnable local components, but it has no stable release,
> support tier, certification, approved protocol claim, hosted verifier, or GA
> result. Candidate output must not be presented as vendor certification.

The digest-bound files under `execution/` are historical control-plane
artifacts, not a live repository-settings API. Fields named `currentStatus` or
`currentEnvironment` record the environment observed when that exact candidate
was assembled. They are intentionally not rewritten by this product branch;
changed GitHub settings must be captured and independently approved in a new
exact control-plane candidate before Genesis.

## Why this project exists

An endpoint can look compatible to `curl` and still fail in an SSE parser,
tool-call state machine, SDK validator, retry path, or agent loop. AgentAPI
Doctor keeps raw evidence, normalized results, and failure attribution separate
so a maintainer can reproduce the smallest relevant behavior without receiving
production secrets or an unbounded trace.

The current source candidate deliberately starts smaller than that full design:

- a local raw-HTTP runner for `openai-chat`, `openai-responses`, and
  `anthropic-messages`;
- four Requirement-Catalog-linked candidate checks selected by the configured
  target protocol (four checks per run, not twelve);
- a loopback-only synthetic reference server and 12 executable targeted
  reference/mutant pairs;
- redaction-before-persistence, content-addressed evidence, hard budgets,
  exact-origin transport, local run storage, and terminal/JSON/JUnit/SARIF/
  Markdown/HTML report renderers;
- a single-node SQLite self-hosted Registry candidate, backup command, local
  Compose bundle, and static Matrix source; and
- versioned candidate JSON Schemas, Registry OpenAPI, offline checks, release
  packaging configuration, and CI/CD workflows.

The Requirement Catalog also contains **260 metadata candidate scenarios** with
reference and targeted-mutant metadata. That number does not mean 260 mutants
are executable, reviewed, supported, or assigned to a Tier. The catalog and
its source interpretations remain `candidate` / `pending_review`.

## About 60 seconds: a local synthetic run

This quickstart builds from source, binds the fixture only to
`127.0.0.1:8090`, runs the four OpenAI Responses candidate checks selected by
the default `local-reference` target, renders the stored report, and cleans up
the process it started. It needs no API key and contacts no public target.

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

`doctor init` creates `.agentapi/config.yaml` and refuses to overwrite an
existing file. A normal `doctor test` run writes its canonical report under
`.agentapi/runs`; `latest` is a local convenience pointer. To inspect an exact
offline plan without contacting the target, run:

```sh
./bin/doctor test local-reference --plan-only
```

These results exercise a deterministic synthetic fixture. They are useful as a
development and regression path, not evidence that a real provider, SDK, or
agent is compatible.

## Current boundaries

- Only the three raw protocol slices above are executable through the local
  candidate runner. Real SDK/client drivers and agent profiles are not a
  supported surface yet.
- The self-hosted Registry candidate can persist local records in SQLite, but
  its commit flow cannot perform hosted verification or publish project trust
  labels. No project-operated Registry, Matrix, runner, or service exists.
- Distribution manifests and workflows are candidates. No package, container,
  Homebrew formula, Scoop manifest, RC, or stable release is published.
- Public schemas and OpenAPI are versioned candidate artifacts, not a stable
  migration promise.
- There is no Genesis, active phase state, external security/privacy/legal
  review, adopter evidence, release quorum, TSC vote, or GA approval.

Use only endpoints and source repositories you are authorized to test. Never
put production keys, private traces, or unredacted provider payloads in an
issue, pull request, fixture, report, or artifact.

The authoritative design is [agentapi-doctor-Plan.md](agentapi-doctor-Plan.md).
The pre-Genesis execution boundary is documented in
[execution/README.md](execution/README.md), and the complete current limitations
are listed in [docs/known-limitations](docs/known-limitations/README.md).

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Commits
  require a Developer Certificate of Origin sign-off.
- Use [SUPPORT.md](SUPPORT.md) to choose the appropriate public channel.
- Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), never
  through a public issue.
- Governance is described in [GOVERNANCE.md](GOVERNANCE.md). The repository is
  still governed by its Bootstrap Charter; no TSC has been formed.

## License

Unless a file states otherwise, repository content is licensed under the
[Apache License 2.0](LICENSE). Data and Registry-specific rights are described
in [DATA_LICENSE.md](DATA_LICENSE.md); no public Registry dataset currently
exists.
