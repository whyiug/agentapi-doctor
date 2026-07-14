# Quick Start

[Project home](../README.md) | [简体中文](zh-CN/quick-start.md)

Install one binary, run a credential-free demo, then check any authorized local,
private-network, or remote endpoint. No project initialization or YAML is
required.

`v0.1.1` is the stable Doctor distribution. The project remains pre-1.0, so
Go packages, experimental schemas, Registry, driver, and pack interfaces are
not stable public APIs unless the release documentation explicitly says so.

## 1. Install v0.1.1

On Linux or macOS:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.1/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

The script comes from the exact release tag and verifies the downloaded archive
against that release's `checksums.txt` before extraction. To inspect it first:

```sh
curl --proto '=https' --tlsv1.2 -fSLO \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.1/install.sh
less install.sh
sh install.sh
```

Windows users can download `agentapi-doctor_0.1.1_windows_amd64.zip` or
`agentapi-doctor_0.1.1_windows_arm64.zip` from
[v0.1.1](https://github.com/whyiug/agentapi-doctor/releases/tag/v0.1.1).
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
Result: CHECKS PASSED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] Candidate raw-wire interpretations; not certification.
```

This validates the installed CLI and exact synthetic fixture, not another
endpoint.

> [!WARNING]
> Doctor writes run evidence beneath `.agentapi/` in the current directory.
> Treat it as private local state and add this entry to every downstream
> project's `.gitignore` before running Doctor there:

```gitignore
.agentapi/
```

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

`CHECKS FAILED`, WARN, and INCONCLUSIVE results show a human-readable check name
plus expected and observed behavior. When the evidence supports a finding, the
report also shows its fault domain and remediation; otherwise it explicitly
says no domain was attributed and gives the next review step. The terminal
keeps the candidate interpretation boundary visible when a check fails:

```text
Result: CHECKS FAILED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 3 | FAIL 1 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] Candidate raw-wire interpretations; not certification.
```

It also prints the exact export command after every run. For example:

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
- requests **64 output tokens** for structural checks and **512** for the
  OpenAI Chat/Responses terminal-status check; and
- stores evidence and the run record beneath the private `.agentapi/` tree.

The requested maximum is 704 output tokens for one four-request Chat or
Responses run and 256 for Anthropic Messages. The output-token field is a
provider request, not a client-enforced cost ceiling; a provider can reject or
ignore it. A reported token-limit terminal remains INCONCLUSIVE, and reported
reasoning-token usage is diagnostic only. PASS is bound to the exact endpoint,
model, versioned artifacts, and four executed checks. It is not complete
SDK/Agent compatibility or vendor certification.

Next: [CLI reference](cli-reference.md) ·
[Real SDK case](cases/openai-python-responses-null-output.md) ·
[Installation](installation.md) ·
[Troubleshooting](troubleshooting.md) ·
[Known limitations](known-limitations/README.md)
