# Synthetic Fixtures

A synthetic fixture is the preferred way to preserve a public regression
without copying private traffic or uncertain-license source material.

## Required record

Every fixture should identify:

- a stable fixture ID and affected protocol/client surface;
- a public provenance URL or a statement that the case was independently
  authored;
- author, SPDX identifier, and allowed use;
- affected and fixed versions when known;
- the raw symptom and independently established ground truth;
- transformations used to synthesize or redact it;
- the expected failure family and evidence pointer; and
- the Requirement Catalog entry, reference-pass case, and targeted mutant.

Do not copy an upstream test or issue body merely because it is publicly
visible. Public access does not establish reuse rights.

## Safety rules

- Replace credentials, account IDs, URLs, payload text, and personal data with
  deterministic synthetic values.
- Reproduce only against local fixtures, test clients, or systems you are
  authorized to use.
- Bind services to `127.0.0.1` and bound execution with timeouts and budgets.
- Scan raw, normalized, report, log, temporary, and crash-output sinks for the
  same canary.
- Preserve the failure fingerprint, not incidental private content.

## Minimal contribution flow

1. Document provenance and rights.
2. Create the smallest local fixture that retains the behavior.
3. Show the reference implementation passing.
4. Show one targeted mutant failing at the intended assertion.
5. Verify deterministic replay at least twice.
6. Run secret/redaction checks before sharing an artifact.

Use the repository's fixture issue form only for non-sensitive material. A
suspected vulnerability follows [the security policy](../../SECURITY.md).

## Reproduce the README lifecycle failure

The README's failing output comes from the checked-in
`missing-terminal-event` mutation. This is a local synthetic check: it needs no
credential and contacts no external endpoint.

From a source checkout, start the fixture in one shell on an unused loopback
port:

```sh
go run ./cmd/reference-server \
  -listen 127.0.0.1:18091 \
  -mutant missing-terminal-event
```

If that port is already occupied, choose another loopback high port. Do not
stop an unknown process on a shared machine.

In a second shell, run the bounded check with a temporary evidence root:

```sh
DEMO_DATA_ROOT="$(mktemp -d)"

go run ./cmd/doctor test \
  --base-url http://127.0.0.1:18091/v1 \
  --protocol openai-responses \
  --model synthetic-model \
  --allow-plain-http \
  --data-root "$DEMO_DATA_ROOT" \
  --format terminal
```

The expected result is three passes, one targeted failure, and process exit
code 1. Only `terminal-exactly-once` fails: the fixture passes non-streaming
requests through unchanged and removes the terminal event only where the
mutation applies. This demonstrates raw wire/lifecycle detection only; it is
not an SDK or root-cause attribution claim.

Stop the reference server you started with `Ctrl-C`, then remove only this
demo's temporary evidence:

```sh
test -n "${DEMO_DATA_ROOT:-}" && rm -rf -- "$DEMO_DATA_ROOT"
unset DEMO_DATA_ROOT
```
