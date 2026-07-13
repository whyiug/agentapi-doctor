# Quick Start

[Project home](../README.md) | [简体中文](zh-CN/quick-start.md)

Install one binary, run a credential-free demo, then check any authorized local,
private-network, or remote endpoint. No project initialization or YAML is
required.

## 1. Install the release candidate

On Linux or macOS:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.0-rc.2/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

The script comes from the exact release tag and verifies the downloaded archive
against that release's `checksums.txt` before extraction. To inspect it first:

```sh
curl --proto '=https' --tlsv1.2 -fSLO \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.0-rc.2/install.sh
less install.sh
sh install.sh
```

Windows users can download `agentapi-doctor_0.1.0-rc.2_windows_amd64.zip` or
`agentapi-doctor_0.1.0-rc.2_windows_arm64.zip` from
[v0.1.0-rc.2](https://github.com/whyiug/agentapi-doctor/releases/tag/v0.1.0-rc.2).
See [Installation](installation.md) for exact PowerShell checksum and extraction
steps.

## 2. Run the no-key demo

```sh
doctor demo
```

The demo starts an in-process fixture on a random loopback port, executes four
checks, stores redacted evidence under `.agentapi/`, and stops the fixture before
returning. It makes no external request and needs no credential.

Expected summary:

```text
Profile outcome: COMPATIBLE
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
```

This validates the installed CLI and exact synthetic fixture, not another
endpoint.

## 3. Check an authorized endpoint

For an HTTPS endpoint with bearer authentication:

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN
```

Replace the `.invalid` URL and model before running. `--auth-env` names the
environment variable; the token value is not put in the command line.

- No authentication: omit `--auth-env`.
- Custom token header: add `--auth-header x-api-key`.
- Trusted local/private plain HTTP: add `--allow-plain-http`.

Do not use plain HTTP for a credential over an untrusted network. Metadata,
link-local, multicast, unspecified, and invalid destinations remain blocked.

## Supported endpoint shapes

| Protocol ID | Operation derived from the configured API prefix |
| --- | --- |
| `openai-chat` | `chat/completions` |
| `openai-responses` | `responses` |
| `anthropic-messages` | `messages` |

A base path such as `/v1` or `/api/v3` is preserved as the complete API prefix.
Requests remain on the configured origin and redirects are not followed.

## Read and share a result

FAIL/WARN/INCONCLUSIVE cases show a human-readable check name plus expected and
observed behavior. When the evidence supports a finding, the report also shows
its fault domain and remediation; otherwise it explicitly says no domain was
attributed and gives the next review step. The terminal prints the exact export
command after every run. For example:

```sh
doctor report markdown '<run-id>' --output doctor-report.md
doctor report html '<run-id>' --output doctor-report.html
```

Review an exported report before sharing it. Recognized secrets are redacted,
but structured model content and tool arguments are not necessarily anonymous.

## Request and cost boundary

Each endpoint run:

- sends at most **4 requests**;
- uses one **60-second deadline**;
- asks for no more than **64 output tokens per request**; and
- stores evidence and the run record beneath `.agentapi/`.

The output-token field is a provider request, not a client-enforced cost ceiling;
a provider can reject or ignore it. PASS is bound to the exact endpoint, model,
versioned artifacts, and four executed checks. It is not complete SDK/Agent
compatibility or vendor certification.

Next: [CLI reference](cli-reference.md) ·
[Real SDK case](cases/openai-python-responses-null-output.md) ·
[Installation](installation.md) ·
[Troubleshooting](troubleshooting.md) ·
[Known limitations](known-limitations/README.md)
