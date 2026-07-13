# Configuration

[Documentation home](README.md) | [Getting Started](getting-started/README.md)

One-off checks do not require configuration:

```sh
doctor test --base-url https://api.example.invalid/v1 \
  --protocol openai-responses --model example-model \
  --auth-env EXAMPLE_API_TOKEN --format terminal
```

For repeated checks, named targets, baselines, or CI, the `doctor` CLI reads
YAML configuration from `.agentapi/config.yaml` by default. Pass
`--config <path>` to commands that support an alternate file.

## Create the initial file

```sh
./bin/doctor init
./bin/doctor self-check
```

`doctor init [<directory>]` creates `<directory>/.agentapi/config.yaml` with
private permissions where the operating system exposes POSIX modes. It refuses
to overwrite an existing file. `doctor self-check` validates the file without
making a network request.

Configuration is strict:

- the file must be UTF-8 YAML, at most 1 MiB, and contain exactly one document;
- unknown fields are rejected;
- the file must be a regular file, not a symbolic link; and
- `apiVersion` must be `urn:agentapi-doctor:config:v1beta2`.

## Add a target with the CLI

The safest way to add a normal bearer-token target is:

```sh
export EXAMPLE_API_TOKEN='replace-with-a-local-or-test-token'

./bin/doctor target add example \
  --base-url https://api.example.invalid/v1 \
  --protocol openai-responses \
  --model example-model \
  --auth-ref env://EXAMPLE_API_TOKEN

./bin/doctor target list
./bin/doctor target inspect example
```

`example.invalid` is intentionally non-routable; replace it only with an
endpoint you are authorized to test. The secret value remains outside the
configuration. `target inspect` redacts the identifying part of a secret
reference.

The implemented protocol IDs are:

- `openai-chat`
- `openai-responses`
- `anthropic-messages`

Each currently selects four built-in raw-wire checks.

## Target fields

```yaml
apiVersion: urn:agentapi-doctor:config:v1beta2
targets:
  local-service:
    baseURL: http://127.0.0.1:8000/v1
    protocol: openai-responses
    model: synthetic-model
    auth:
      type: bearer
      token:
        ref: env://LOCAL_SERVICE_TOKEN
    metadata:
      runtime: local-development
```

### `baseURL`

`baseURL` must be an absolute `http` or `https` URL with a host. Embedded
credentials, query strings, fragments, escaped path separators, backslashes,
and non-canonical path segments are rejected.

The runner treats a non-root base path as the complete API prefix and appends
only the protocol operation:

| Protocol | Appended operation |
| --- | --- |
| `openai-chat` | `chat/completions` |
| `openai-responses` | `responses` |
| `anthropic-messages` | `messages` |

An origin-only URL defaults to the `/v1` API prefix. Otherwise the runner does
not insert a version segment: `https://host.example/gateway/v1` plus
`openai-responses` becomes `/gateway/v1/responses`, while an
OpenAI-compatible `/api/v3` prefix becomes `/api/v3/chat/completions`. Include
the version segment required by your endpoint in `baseURL`. Redirects are not
followed.

Plain HTTP is accepted for an explicitly configured target, which is useful
for loopback development. Use HTTPS for a remote endpoint and never send a
credential over a network you do not trust.

### `model` and `metadata`

`model` is sent in the synthetic request body exactly as configured.
`metadata` is an optional string-to-string map for local identification; it
does not grant a support or compatibility status.

### Authentication

Bearer authentication produces:

```text
Authorization: Bearer <resolved-secret>
```

For a one-off API that uses a custom token header, combine
`--auth-env NAME --auth-header x-api-key`. For a stored target, edit the YAML:

```yaml
auth:
  type: header
  header: x-api-key
  token:
    ref: env://LOCAL_SERVICE_TOKEN
```

The current CLI resolves:

- `env://NAME` — recommended and supported on all platforms;
- `file:///absolute/path` — supported on Unix-like systems only when the file
  is regular, not a symlink, at most 64 KiB, and has no group/other permission
  bits.

Although the configuration grammar reserves `keyring://` and `exec://`,
the current `doctor test` command does not enable either resolver. Windows
also rejects `file://` because POSIX mode bits cannot prove that the file's
DACL is private. Use `env://` on Windows.

Resolved credentials must be non-empty, contain no NUL byte, and currently
need at least 8 bytes so the runner can enforce its exact redaction-canary
invariant. Secret values are never meant to be written into YAML, command-line
arguments, reports, or fixtures.

### Migrate from v1beta1

The release-candidate `v1beta1` format exposed `defaults` fields that the fixed
Quick Check contract did not consume. Doctor now rejects that format instead
of silently ignoring cost, retry, or capture settings. Delete the top-level
`defaults` block and change `apiVersion` to
`urn:agentapi-doctor:config:v1beta2`; all target definitions remain unchanged.

Quick Check always executes four selected requests, with zero retries,
redaction before persistence, and digest-bound per-scenario output limits.
Those limits are part of the built-in check identity, not user-configurable
cost ceilings.

## Validate without running a target

```sh
./bin/doctor self-check
./bin/doctor test local-reference --plan-only
./bin/doctor test local-reference --plan-only --resolve
```

`self-check` reports the OS, architecture, Go runtime, config state, and binary
digest when available; it reports `network_calls: 0`. `--plan-only` builds a
plan without dialing the target, resolving a secret, or creating run evidence.

The machine-readable configuration contract is
[`schemas/config/config.schema.json`](../schemas/config/config.schema.json).
