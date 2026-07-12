# Contributing to AgentAPI Doctor

Thank you for helping build rigorous, reproducible compatibility tooling. The
project values small changes with traceable evidence over broad unsupported
claims.

AgentAPI Doctor is a pre-Genesis, pre-release development candidate whose
authoritative execution boundary remains P00.B00. Product-component branches
may be reviewed as non-authoritative design candidates, but repository rules do
not permit treating them as approved work or merging them into the protected
line before a new exact control-plane approval and Genesis. A contribution never
implies that a protocol, client, provider, support Tier, phase, or release is
approved.

## Before you start

Read these documents:

1. [README.md](README.md) for the current runnable surface and boundaries;
2. [agentapi-doctor-Plan.md](agentapi-doctor-Plan.md) for design intent;
3. [AGENTS.md](AGENTS.md) for repository safety and pre-Genesis execution
   rules;
4. [GOVERNANCE.md](GOVERNANCE.md) for the decision process; and
5. [SECURITY.md](SECURITY.md) before reporting a suspected vulnerability.

Do not open a public issue containing a secret, private trace, embargoed
vulnerability, or unredacted provider payload. Do not claim an approval,
reviewer, adopter, release, hosted observation, Genesis transition, or phase
result that did not actually occur.

## Useful contribution units

A contribution does not need to span the architecture. Useful bounded units
include:

- a synthetic, redacted fixture derived from a public fact with recorded
  provenance;
- a Requirement Catalog source revision;
- one candidate assertion with a reference-pass and targeted-mutant-fail test;
- an SDK/client version update backed by an exact support-manifest lock;
- a protocol profile, driver, report, or Registry correction;
- a schema change with its required compatibility and migration work;
- an error-message, accessibility, security, or documentation correction; or
- a reproducible upstream issue bundle containing no sensitive data.

Do not copy tests, issue text, logs, or fixtures whose reuse rights are unclear.
Record source, author, applicable license, and allowed use for imported facts or
derived fixtures. The catalog's 260 candidate metadata scenarios are not proof
that 260 executable checks or mutants have been independently implemented.

## Local checks

Use the Go version selected by `go.mod`, Python 3, and a GNU- or
POSIX-compatible `make`. Docker is needed only for the container build check.
Run the narrowest relevant test first, then the applicable repository checks:

```sh
# Schemas, generated catalogs/support locks, formatting, Go tests/vet,
# integration/package validators, documentation links, and vendoring.
make -f Product.mk product-check

# Protected-verifier unit tests that do not assert whole-tree candidacy.
make test-protected-verifier

# Concurrency and persistence safety (run separately from product-check).
make -f Product.mk race-product

# All three offline, non-root, read-only container targets (requires Docker).
make -f Product.mk docker-build-check
```

Useful narrower targets include `make -f Product.mk test-product`,
`make -f Product.mk schema-check`, `make -f Product.mk integration-check`, and
`make -f Product.mk docs-check`, and `make -f Product.mk license-check`. CI also runs pinned static
analysis, vulnerability analysis, CodeQL, dependency review, workflow linting,
nightly bounded fuzz regressions, and candidate release/container checks as
configured under `.github/workflows/`.

`make verify` and the complete `make test-bootstrap` suite include whole-tree
protected bootstrap assertions for an exact approved P00.B00 candidate. They
intentionally reject this separate product-candidate tree while Genesis is
absent; do not treat that expected rejection as a test to weaken.
`make test-protected-verifier` exercises the bounded verifier unit suite
without claiming whole-tree approval. Conversely, a passing product test
proves only the behavior asserted by that test. The release path invokes a
fail-closed GA gate, which is expected to remain blocked while Genesis and
required evidence are absent. Never make either gate green by fabricating
state or editing an approval, waiver, threshold, observation, or attestation.

Tests must use an isolated temporary `HOME`, deterministic local fixtures, and
no ambient credentials. Unit, golden, bootstrap, gate, and product checks are
offline. Live-provider behavior belongs only in a separately authorized,
allowlisted canary with synthetic data; it is not part of an ordinary pull
request.

Every bug fix needs a minimal regression fixture. Every normative assertion
needs a cited Requirement Catalog source, a passing reference case, and a
targeted mutant that fails. Keep wire, model, client, and harness failure
classes distinct. Do not make a failing check green by deleting it, adding an
unconditional retry, weakening its threshold, hand-entering a metric, or
turning missing evidence into PASS.

## Developer Certificate of Origin

This project uses the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) rather
than a contributor license agreement. By adding a `Signed-off-by` trailer, you
certify that you have the right to submit the contribution under the project's
license and that the certification is accurate.

Sign each commit with:

```sh
git commit -s
```

The trailer must use a name and email address that identify the contributor:

```text
Signed-off-by: Example Contributor <contributor@example.org>
```

Do not add another person's sign-off without authorization. A pull request
checkbox or review does not replace a missing commit trailer.

## Change description

A reviewable change explains:

- the user or system problem;
- included and excluded scope;
- Requirement, RFC, ADR, or Plan references;
- affected public interfaces and compatibility implications;
- security, privacy, data, and licensing impact;
- reference-pass, mutant-fail, negative, race, and cross-platform tests as
  applicable;
- generated artifacts and how drift was checked; and
- migration or documentation changes.

Large design, schema, scoring, privacy, telemetry, ABI, governance, license, or
breaking CLI/config changes require the RFC process in
[GOVERNANCE.md](GOVERNANCE.md).

## Reviews and authorship

Authors do not approve their own changes. CODEOWNERS identifies routing, not a
waiver from independent review. Critical schema, security, and release changes
will require the governance policy's qualified approvals after a real review
roster exists. During bootstrap, a change remains provisional or blocked
rather than inventing an independent reviewer.

By contributing, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Contributions are accepted under the
[Apache License 2.0](LICENSE) unless a file states a different, compatible
license.
