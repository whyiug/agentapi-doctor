# AgentAPI Doctor

[English](README.md) | [简体中文](README.zh-CN.md)

**Test any local, private-network, or remote HTTP(S) endpoint you are
authorized to assess** when it exposes `openai-chat`, `openai-responses`, or
`anthropic-messages` behavior. AgentAPI Doctor keeps redacted, reproducible
evidence instead of treating one successful request as compatibility.

## Try it

```sh
go install github.com/whyiug/agentapi-doctor/cmd/doctor@latest
doctor demo
```

`doctor demo` runs the built-in synthetic fixture with no API key or external
endpoint.

> There is no tagged release or published binary package yet. This is a source
> install: `@latest` follows the latest available source snapshot and may
> change between installs.

## Test an authorized endpoint

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN \
  --format terminal
```

Replace the `.invalid` URL and model before running. Omit `--auth-env` for an
endpoint without authentication. Add `--auth-header x-api-key` when the
environment value belongs in a custom header instead of a bearer
`Authorization` header. Plain HTTP is rejected unless you explicitly add
`--allow-plain-http`; use that only for a trusted local or private endpoint.

No `init` step or YAML configuration is required for this one-shot command.
Each endpoint run sends at most **4 requests**, asks for at most **64 output
tokens per request**, uses a **60-second execution deadline**, prints the
selected report format, and saves redacted evidence under `.agentapi/`.

Only test systems you have explicit permission to assess. A PASS is bound to
the exact endpoint, model, built-in pack/profile digests, and four checks; it
is not vendor certification or proof of complete SDK, agent, provider, or
deployment compatibility.

## Documentation

[Quick Start](docs/quick-start.md) ·
[Installation](docs/installation.md) ·
[CLI reference](docs/cli-reference.md) ·
[Troubleshooting](docs/troubleshooting.md) ·
[All documentation](docs/README.md)

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change. Report
suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).

Source and documentation use the [Apache License 2.0](LICENSE) unless a file
says otherwise. See [DATA_LICENSE.md](DATA_LICENSE.md) and
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) for additional terms.
