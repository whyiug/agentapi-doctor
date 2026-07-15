<div align="center">

# AgentAPI Doctor

### 200 OK is not compatibility. Check the stream. Keep the evidence.

A local CLI for inference-server, gateway, and SDK maintainers debugging the
gap between `200 OK` and a client that still fails. Doctor runs bounded
lifecycle checks for OpenAI Chat, Responses, and Anthropic Messages, then
leaves a redacted report you can reproduce, compare, and share.

[![Release](https://img.shields.io/github/v/release/whyiug/agentapi-doctor?label=release)](https://github.com/whyiug/agentapi-doctor/releases)
[![CI](https://github.com/whyiug/agentapi-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/whyiug/agentapi-doctor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/whyiug/agentapi-doctor/actions/workflows/codeql.yml/badge.svg)](https://github.com/whyiug/agentapi-doctor/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Quick Start](docs/quick-start.md) ·
[What it checks](#what-doctor-checks) ·
[llama.cpp A/B case](docs/cases/llama-cpp-responses-pr-21174.md) ·
[Real SDK case](docs/cases/openai-python-responses-null-output.md) ·
[Example failure report](docs/examples/missing-terminal-event-report.html) ·
[简体中文](README.zh-CN.md)

</div>

<p align="center">
  <img src="docs/assets/agentapi-doctor-failure.svg" width="900" alt="AgentAPI Doctor detects a stream whose terminal event is missing">
</p>

## From download to an answer

Linux and macOS can install the exact `v0.1.1` release without Go:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.1/install.sh | sh
$HOME/.local/bin/doctor demo
```

The pinned installer verifies the release archive against `checksums.txt`
before extraction. If you prefer to inspect it first, download
[`install.sh`](install.sh), then run `sh install.sh`. Windows users can download
the verified ZIP from [GitHub Releases](https://github.com/whyiug/agentapi-doctor/releases/tag/v0.1.1);
the [Installation guide](docs/installation.md) includes checksum steps for every
platform.

The demo needs no API key. It starts a random loopback fixture, runs four
lifecycle checks, stores local evidence, and stops the fixture automatically:

```text
Result: CHECKS PASSED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] Candidate raw-wire interpretations; not certification.
```

Demo success validates this exact synthetic fixture and the installed CLI. It
does not certify another endpoint, SDK, provider, or deployment.

## Check an authorized endpoint

No project initialization or YAML is required:

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://your-endpoint.example/v1' \
  --protocol openai-chat \
  --model 'your-model-id' \
  --auth-env DOCTOR_TOKEN
```

Use `openai-responses` or `anthropic-messages` for those API shapes. Omit
`--auth-env` for an unauthenticated endpoint. The endpoint can be local, on a
private network, or remote; it only needs to be yours or explicitly authorized
for testing.

Each run sends at most four requests under one 60-second deadline. The token is
read from the named environment variable, not a command argument. Requests stay
on the configured origin, redirects are not followed, and evidence remains in
the local `.agentapi/` directory. Treat that directory as private local state
and add `.agentapi/` to the tested project's `.gitignore`.

Got a FAIL or INCONCLUSIVE result you can share? Add a five-line sanitized
summary to [Compatibility Clinic #1](https://github.com/whyiug/agentapi-doctor/discussions/14).
A summary is enough; leave out tokens, private URLs, and payloads you have not
reviewed.

## What Doctor checks

| A basic smoke test sees | Doctor also checks |
| --- | --- |
| HTTP status | Required response envelope |
| First SSE chunk | Stream media type and lifecycle |
| Some generated text | Terminal event presence, status, and exactly-once behavior |
| A transient console log | Content-addressed, secret-redacted evidence bound to the exact run |

Today, each Quick Check selects four executable raw HTTP checks for one of:

- OpenAI Chat Completions;
- OpenAI Responses;
- Anthropic Messages.

It can render the same result as terminal output, JSON, JUnit, SARIF, Markdown,
or a self-contained offline HTML report. Named baselines and stable exit codes
make the result usable in CI.

## A commit-pinned external A/B

In [llama.cpp PR #21174](https://github.com/ggml-org/llama.cpp/pull/21174), the
PR author described an earlier Doctor run as useful independent evidence. We
then retested the updated head locally against the same bounded checks:

| Target | Existing OpenAI SDK smoke | Selected PR tests | Doctor v0.1.1 |
| --- | ---: | ---: | ---: |
| master at test time, `f955e394` | 2/2 | 1/9 | 3 PASS + 1 FAIL |
| PR head, `a28a6d324` | not separately rerun | 9/9 | 4 PASS |

The master failure was a Responses output item with no nonnegative output
index. The same Doctor check and the selected upstream sequence/index tests
passed on the PR head. See the
[commit-pinned case](docs/cases/llama-cpp-responses-pr-21174.md) for the exact
commits, test blob, binary and model hashes, build boundary, and limitations.
This comparison supports those checks only; it is not a merge-readiness or
full-compatibility claim.

## See a failure—not just a self-test

When the checked-in synthetic server omits the Responses terminal event, Doctor
rejects the stream even though its media type looks correct:

```text
Result: CHECKS FAILED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 3 | FAIL 1 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] Candidate raw-wire interpretations; not certification.
PASS  stream media type
PASS  required response envelope
FAIL  terminal event exactly once
PASS  terminal status
```

Download the [offline failure report](docs/examples/missing-terminal-event-report.html)
and open it locally, or reproduce it with the documented
[Synthetic Fixture](docs/getting-started/synthetic-fixtures.md).
This example is a real, deterministic wire/lifecycle observation. It is not by
itself a real SDK run or automatic root-cause attribution.

## Why a real SDK changes the answer

A status-only smoke test can accept `200 OK` and `text/event-stream` without
ever asking whether the terminal object is usable. The source tree now includes
one deliberately narrow counterexample using the real, pinned OpenAI Python SDK:

| Observation of the same synthetic stream | Result |
| --- | --- |
| HTTP/SSE smoke | `200 OK`; a `response.completed` event arrived |
| Raw terminal object | `output` is `null`, not the array modeled by the pinned SDK |
| OpenAI Python SDK 2.38.0 | rejects the stream during event iteration |
| Doctor bundle | correlates `wire.sse` with the sanitized SDK observation and exact dependency lock |

Reproduce it on Linux amd64 with CPython 3.12.12:

```sh
doctor reproduce openai-python-responses \
  --python .venv/bin/python \
  --fixture null-completed-output \
  --bundle ./openai-python-null-output.zip
```

This command uses a random loopback fixture and a synthetic token; it never
contacts a provider or reads an API key. See the
[reproducible case study](docs/cases/openai-python-responses-null-output.md) for
the hash-locked install and exact evidence boundary. The case proves one frozen
SDK behavior, not compatibility or incompatibility of any vendor endpoint.

## Where it fits

| Your goal | Best tool today |
| --- | --- |
| Check whether one key or endpoint responds | `curl` or a browser checker |
| Explore models and prompts | A web playground |
| Repeatedly inspect lifecycle behavior and keep diffable evidence | **AgentAPI Doctor** |
| Reproduce one known Responses/SDK failure | Use Doctor's pinned OpenAI Python case and evidence bundle |
| Prove an arbitrary SDK or Agent compatible | Run that exact client against the authorized endpoint; Doctor does not claim this coverage |

Doctor is not a model-quality benchmark, provider ranking, relay checker, or
vendor certification service. The current catalog also contains candidate
metadata that is not executable coverage; see [Known Limitations](docs/known-limitations/README.md).

## Evidence and privacy

- Credentials are resolved from an environment or protected file reference and
  are redacted before persistence.
- Exact endpoint, model, plan, profile, pack, and evidence digests stay bound to
  the run so two results can be meaningfully compared.
- Structured model content and tool arguments are not necessarily anonymous.
  Review evidence before sharing it.
- The provider still receives the bounded synthetic prompts and may retain them
  under its own policy.
- Structural checks request 64 output tokens. The Chat/Responses terminal-status
  check requests 512 so default-thinking models can reach a natural terminal
  more often. A provider may reject or ignore either field, so these are not
  enforced cost ceilings.

Only test systems you are explicitly authorized to assess.

## Why this project exists

Real reports repeatedly show the same gap: direct requests work, but an SSE
terminal, tool-call delta, strict Responses event, proxy, or client state machine
breaks later. Examples include [Open WebUI #21768](https://github.com/open-webui/open-webui/issues/21768),
[llama.cpp #20607](https://github.com/ggml-org/llama.cpp/issues/20607), and
[Codex #24973](https://github.com/openai/codex/issues/24973).

The public [Roadmap](ROADMAP.md) keeps the next work focused on reproducible
endpoint checks, report reuse, and verified client cases. Registry, public
matrix, and hosted-service candidates remain outside the supported v0.1 scope.

## Documentation and community

[Quick Start](docs/quick-start.md) ·
[Installation](docs/installation.md) ·
[CLI reference](docs/cli-reference.md) ·
[Troubleshooting](docs/troubleshooting.md) ·
[Known limitations](docs/known-limitations/README.md) ·
[llama.cpp A/B case](docs/cases/llama-cpp-responses-pr-21174.md) ·
[Real SDK case](docs/cases/openai-python-responses-null-output.md) ·
[Roadmap](ROADMAP.md) ·
[All docs](docs/README.md)

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), propose a
real compatibility failure or fixture, and use [SECURITY.md](SECURITY.md) for
private vulnerability reports. Please do not open a public issue containing a
credential or unredacted provider response.

Source and documentation use the [Apache License 2.0](LICENSE) unless a file
says otherwise. Vendored dependency notices are recorded in
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
