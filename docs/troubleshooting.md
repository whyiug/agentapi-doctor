# Troubleshooting

[Documentation home](README.md) | [CLI reference](cli-reference.md)

Start with these non-destructive checks:

```sh
doctor version --json
doctor self-check
```

`self-check` is offline. It validates the config when present and reports the
local OS, architecture, Go runtime, and binary digest when available.

## The release download returns 404

Confirm the exact `v0.1.0-rc.1` entry is visible on
[GitHub Releases](https://github.com/whyiug/agentapi-doctor/releases) and use
its exact asset name. There is no moving package-manager channel. If the release
entry is not yet public, use the contributor source path in
[Installation](installation.md#source-install-for-contributors) rather than
guessing a tag, version, or checksum. Files under `integrations/` remain
unpublished candidates.

## `doctor` is not found after `make build`

`make build` compile-checks the supported commands; it does not install them or
write `./bin/doctor`. Build an executable explicitly:

```sh
mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
./bin/doctor version
```

On Windows, use `./bin/doctor.exe`.

## The Go toolchain is rejected

This section applies to source builds and contributors; prebuilt archives do
not require Go.

Use the version selected by `go.mod`. Check both `go version` and the
`toolchain` line in that file. Do not work around a toolchain mismatch by
editing `go.mod` unless the change itself is being reviewed.

## `doctor init` says the config already exists

This is intentional: initialization never overwrites
`.agentapi/config.yaml`. Use the existing file, pass a different directory to
`doctor init <directory>`, or move the old file aside after inspecting it.
Do not delete a config until you have checked it for target definitions you
still need.

## The config is invalid

Common causes are:

- an unknown or misspelled field;
- more than one YAML document;
- a non-canonical duration such as `300s` where `5m0s` is expected;
- a relative URL, embedded URL credential, query, or fragment in `baseURL`;
- a plaintext secret instead of a reference such as `env://TOKEN`;
- an empty target map; or
- a config path that is a symlink or not a regular file.

Validate without contacting a target:

```sh
./bin/doctor self-check --config ./path/to/config.yaml
```

See [Configuration](configuration.md) and the
[configuration schema](../schemas/config/config.schema.json).

## An inline test rejects plain HTTP

One-off `doctor test --base-url ...` commands require HTTPS by default. For a
trusted local or private-network endpoint, explicitly add
`--allow-plain-http`. Do not use it to send a credential across an untrusted
network. The flag is invalid with an `https://` URL so accidental, stale flags
remain visible.

## Port 8090 is already in use

The default `local-reference` target expects `127.0.0.1:8090`. Do not stop an
unknown process on a shared machine. Start your own fixture on another
loopback port and add a separate target:

```sh
./bin/reference-server -listen 127.0.0.1:18090
```

In another shell:

```sh
./bin/doctor target add local-alt \
  --base-url http://127.0.0.1:18090/v1 \
  --protocol openai-responses \
  --model synthetic-model
./bin/doctor test local-alt
```

Stop only the reference-server process you started.

## A target or protocol is not found

List and inspect the active config:

```sh
./bin/doctor target list
./bin/doctor target inspect example
```

The current runner implements exactly `openai-chat`, `openai-responses`, and
`anthropic-messages`. Protocol names are exact. Use `--config` consistently
if the target lives outside the default `.agentapi/config.yaml`.

## A credential is unavailable

For `env://NAME`, export the variable in the environment that launches
`doctor`:

```sh
export LOCAL_SERVICE_TOKEN='replace-with-a-local-or-test-token'
./bin/doctor test local-service
```

The value must be non-empty, contain no NUL byte, and currently be at least
8 bytes. The current CLI does not provide a keyring resolver and keeps the
`exec://` resolver disabled.

For `file://` on Unix-like systems, use an absolute, regular, non-symlink file
with no group/other permission bits:

```sh
chmod 600 /absolute/path/to/token
```

`file://` fails closed on Windows; use `env://` there. Never paste the secret
value into the config, a command argument, an issue, or a report.

## The request reaches the wrong path

Configure the API prefix, not a complete operation URL. The runner appends
`chat/completions`, `responses`, or `messages` according to the configured
protocol. An origin-only URL defaults to `/v1`; any non-root path is treated
as the complete prefix, so include the endpoint's required version segment.
For example, `/gateway/v1` and `/api/v3` are both preserved exactly.

The transport is bound to the configured scheme and host and does not follow
redirects. Redirect responses, DNS failures, TLS errors, timeouts, oversized
bodies, and HTTP authentication failures remain distinct from a protocol
assertion failure.

## `latest` or a run ID cannot be found

A normal run stores data under `<data-root>/runs`. If you used a custom data
root, pass the matching store:

```sh
./bin/doctor test local-reference --data-root ./local-data
./bin/doctor run inspect latest --store ./local-data/runs
./bin/doctor report terminal latest --store ./local-data/runs
```

For CI, capture the exact `run_id` returned by `doctor test` and use
`--allow-latest=false` when inspecting or rendering it.

## An output or baseline already exists

The CLI does not overwrite plans, report files, baselines, configs, or
scaffolds. Choose a new path or name. Inspect the existing file before moving
or removing it.

## A run is non-zero

Do not reduce every non-zero status to “the provider failed.” Exit codes
separate target failures, input/config errors, harness or infrastructure
errors, incomplete runs, credential failures, and baseline regressions.
See [Exit codes](cli-reference.md#exit-codes).

Preserve the structured condition code, exact run ID, redacted config, and the
smallest local reproduction when asking for help. Follow [SUPPORT.md](../SUPPORT.md)
for public support and [SECURITY.md](../SECURITY.md) for suspected
vulnerabilities.

## Docker or Compose ports conflict

`compose.yaml` binds only to loopback by default. Choose unused host ports:

```sh
AGENTAPI_REGISTRY_PORT=28080 \
AGENTAPI_REFERENCE_PORT=28090 \
docker compose up --build registry reference
```

Stop this project's services with `docker compose down`. Do not stop or remove
unrelated containers, networks, volumes, images, or services.
