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
