# Quick Start

[Project home](../README.md) | [简体中文](zh-CN/quick-start.md)

Two commands run a credential-free demo. One additional `doctor test` command
can assess any authorized local, private-network, or remote HTTP(S) endpoint
that exposes a supported API shape.

## Install the current source snapshot

Requires the Go toolchain:

```sh
go install github.com/whyiug/agentapi-doctor/cmd/doctor@latest
```

There is no tagged release or published binary package yet. `@latest` is a
source install that follows the latest available source snapshot, so repeating
the command later may install different code.

If `doctor` is not found, ensure the configured `GOBIN`—or
`$(go env GOPATH)/bin` when `GOBIN` is empty—is on `PATH`.

## Run the built-in demo

```sh
doctor demo
```

The demo runs an in-process synthetic fixture. It needs no API key, starts a
temporary HTTP listener on a random loopback port, stops that listener before
returning, and contacts no external endpoint. It writes its redacted local
evidence under `.agentapi/`.

Demo success verifies only the installed CLI and its synthetic fixture. It is
not a claim about another endpoint.

## Test an authorized endpoint

The one-shot interface is:

```text
doctor test --base-url URL --protocol ID --model ID
  [--auth-env NAME] [--auth-header x-api-key] [--allow-plain-http]
  --format terminal
```

No `init` step or YAML file is required.

### HTTPS with bearer authentication

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN \
  --format terminal
```

Replace the `.invalid` URL and model before running. `--auth-env` names an
environment variable; the token value is not placed in the command line.

- No authentication: omit `--auth-env`.
- Custom token header: use `--auth-env DOCTOR_TOKEN --auth-header x-api-key`.
- Trusted local/private plain HTTP: add `--allow-plain-http`.

Plain HTTP is rejected by default. Do not use `--allow-plain-http` when sending
a credential across an untrusted network. This flag does not override the
hard rejection of metadata-service, link-local, multicast, unspecified, or
invalid destinations.

## Supported endpoint shapes

| Protocol ID | Derived operation |
| --- | --- |
| `openai-chat` | `/v1/chat/completions` |
| `openai-responses` | `/v1/responses` |
| `anthropic-messages` | `/v1/messages` |

The endpoint may be local, on a private network, or remote. A non-root base
path is treated as the complete API prefix, so both `/v1` and custom prefixes
such as `/api/v3` are preserved. Requests stay on the configured origin and
redirects are not followed.

The selected endpoint receives bounded synthetic prompts and may log or retain
them under its own policy. Use an authorized test account and test credential;
do not send production data through these checks.

## Cost, evidence, and result boundaries

Each endpoint run:

- sends at most **4 requests**;
- asks for at most **64 output tokens per request**;
- uses one **60-second execution deadline**, followed by bounded cleanup and
  local persistence;
- prints the requested report format; and
- stores redacted evidence and the run record under `.agentapi/`.

The current reference fixture contains 12 executable targeted modes. The
catalog's 260 candidate records are metadata, not 260 executable requests.

Only test systems you have explicit permission to assess. PASS is bound to the
exact endpoint, model, built-in pack/profile digests, and four checks. It is
not vendor certification and does not prove complete SDK, agent, provider, or
deployment compatibility.

Next: [CLI reference](cli-reference.md) ·
[Installation details](installation.md) ·
[Troubleshooting](troubleshooting.md) ·
[Known limitations](known-limitations/README.md)
