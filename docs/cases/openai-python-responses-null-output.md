# When `200 OK` Still Breaks the OpenAI Python SDK

[Project home](../../README.md) | [Documentation index](../README.md)

This case shows the narrow gap AgentAPI Doctor is built to make reviewable: a
Responses stream can return `200 OK`, use `text/event-stream`, and emit a
`response.completed` event, while the terminal object is still unusable by a
real client.

The reproducer runs OpenAI Python SDK 2.38.0 against a deterministic local
fixture whose completed response has `output: null`. It records the raw SSE and
the SDK observation from the same request, then writes both into a checksummed
ZIP. No provider is contacted and no API key is read.

## The useful difference

| Layer | Exact observation |
| --- | --- |
| Status-only smoke | HTTP 200 and `text/event-stream` |
| Event-name smoke | one `response.completed` event |
| Raw terminal semantics | `response.output` is `null`, not an array |
| OpenAI Python 2.38.0 | `TypeError` during event iteration; no terminal event reaches the application |
| Doctor correlation | `confirmed`, fault domain `wire`, with raw and SDK evidence in one bundle |

The fault-domain result is justified here because Doctor owns the loopback
fixture, verifies its mutation identity, and inspects the captured bytes. A
client exception by itself would remain `unknown`; it is not automatic proof
that an arbitrary endpoint is at fault.

## Frozen inputs

| Input | Pin |
| --- | --- |
| Platform | Linux amd64 |
| Runtime | CPython 3.12.12 |
| SDK | `openai==2.38.0` |
| SDK source tag | [`v2.38.0`](https://github.com/openai/openai-python/tree/v2.38.0) |
| SDK wheel | `openai-2.38.0-py3-none-any.whl`, SHA-256 recorded in `fixture.json` |
| Full dependencies | 16 wheel-only, hash-locked distributions |
| Fixture | `null-completed-output` |

The exact lock and provenance record live under
[`runners/python/openai-responses/`](../../runners/python/openai-responses/).
The fixture is independently authored under this project's Apache-2.0 license;
it contains no copied vendor payload, credential, production trace, or upstream
test.

## Reproduce the release

Install the `v0.1.0-rc.2` Linux amd64 binary using the main README, and provide
CPython 3.12.12. The release archive deliberately does not bundle Python or
third-party wheels.

Fetch the dependency lock from the same immutable tag, verify its project-
recorded digest, materialize the wheelhouse, then install from it without an
index:

```sh
CASE_ROOT="$(mktemp -d)"
LOCK="$CASE_ROOT/requirements.lock"
WHEELHOUSE="$CASE_ROOT/wheelhouse"

curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.0-rc.2/runners/python/openai-responses/requirements-linux-x86_64-py312.lock \
  -o "$LOCK"
echo '38cd96f1a1b6a1ba4eb3445fd667fe402374eab16057d0277854187218327a0d  '"$LOCK" \
  | sha256sum --check --strict

python3.12 -m pip download \
  --require-hashes \
  --only-binary=:all: \
  --dest "$WHEELHOUSE" \
  --requirement "$LOCK"

python3.12 -m venv "$CASE_ROOT/venv"
"$CASE_ROOT/venv/bin/python" -m pip install \
  --no-index \
  --require-hashes \
  --only-binary=:all: \
  --find-links "$WHEELHOUSE" \
  --requirement "$LOCK"
"$CASE_ROOT/venv/bin/python" -m pip check
```

Show that the unmodified reference stream completes:

```sh
mkdir -p "$CASE_ROOT/output"

doctor reproduce openai-python-responses \
  --python "$CASE_ROOT/venv/bin/python" \
  --fixture reference \
  --bundle "$CASE_ROOT/output/reference.zip"
```

Then reproduce the targeted terminal-envelope failure:

```sh
doctor reproduce openai-python-responses \
  --python "$CASE_ROOT/venv/bin/python" \
  --fixture null-completed-output \
  --bundle "$CASE_ROOT/output/null-completed-output.zip"
```

Expected summary:

```text
OpenAI Python Responses reproduction: CONFIRMED
Fixture: null-completed-output
Raw terminal events: 1
SDK outcome: exception
Fault domain: wire
```

`CONFIRMED` means the frozen synthetic observation matched its checked-in
oracle. It does not certify or reject OpenAI, another provider, a gateway, or an
endpoint outside this local run.

The CLI refuses to overwrite a bundle. Choose a new path for each run. When
finished, remove only the environment and temporary directory you created:

```sh
test -n "${CASE_ROOT:-}" && rm -rf -- "$CASE_ROOT"
```

Contributors can use the checked-in lock instead and build `./cmd/doctor` with
the Go toolchain selected by `go.mod`; the protocol observation and bundle
structure are the same, while `generator.json` correctly identifies the local
build rather than the release binary.

## What the bundle gives a maintainer

The ZIP is deterministic for the same fixture, canonical inputs, SDK
environment, and Doctor executable, and contains:

- `SUMMARY.md` and `result.json` — bounded verdict and layer attribution;
- `wire.sse` — the exact application-layer response used by the SDK;
- `sdk-observation.json` — event types, terminal count, final shape, installed
  distribution metadata, runtime mismatches, and a sanitized exception
  observation;
- `environment.json` and `fixture.json` — observed-versus-expected runtime,
  Python executable digest, SDK, dependency-lock digest, wheel, mutation, and
  provenance pins;
- `generator.json` — Doctor build version, source revision when available, Go
  runtime, and the generating executable's SHA-256;
- `repro/runner.py`, `repro/requirements.lock`, and `repro/README.md` — the
  minimal rerun inputs;
- `manifest.json` and `SHA256SUMS` — the expected file set and content hashes.

The wheel hashes govern wheelhouse construction and installation. At runtime,
Doctor verifies CPython/platform identity plus the exact installed distribution
names and versions; it records the Python executable digest, but does not claim
to rehash every installed package file.

The ordinary Product CI job creates the wheelhouse from the hash lock, installs
with `--no-index`, and executes the reference plus all three targeted mutants
twice through `TestRealPinnedSDK`. That job must pass before the
`Product CI / aggregate` gate can pass; a separate unit test verifies that
identical inputs produce a byte-identical bundle.

After creating the locked environment, the reusable core of that CI gate is:

```sh
export AGENTAPI_DOCTOR_OPENAI_PYTHON="$PWD/.venv/bin/python"
go test ./internal/openaisdkcase \
  -run '^TestRealPinnedSDK$' \
  -count=2 \
  -timeout=2m
```

The checked-in [Product CI workflow](../../.github/workflows/ci.yml) is the
complete Ubuntu clean-runner example, including the pinned setup action,
wheelhouse download, offline install, and aggregate dependency.

## Scope and limitations

- This is a real released SDK executing a real high-level Responses streaming
  path, but the endpoint and payload are synthetic and loopback-only.
- It is a frozen regression baseline, not a recommendation to use this Python
  or SDK version in production.
- It does not run a proxy, an Agent loop, tool execution, or a vendor service.
- It does not generalize one observation to other SDK versions, endpoints,
  models, or deployments.
- The other included fixtures cover missing and duplicate terminal events. They
  preserve their own raw and SDK observations; they are not additional vendor
  claims.

This boundary is intentional: one small, exact case is more useful to a
maintainer than a large compatibility claim that cannot be reproduced.
