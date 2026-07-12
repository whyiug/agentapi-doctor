# Contributing to AgentAPI Doctor

Thank you for helping build reproducible compatibility diagnostics for agentic
LLM APIs. Contributions of code, tests, fixtures, documentation, protocol
research, and usability feedback are welcome.

## Before you start

- Read the [README](README.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
- Use a public issue or discussion for ordinary bugs and proposals.
- Report suspected vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md).
- Never include production credentials, private traces, customer data, or
  unredacted provider payloads in a fixture, issue, pull request, or artifact.

For a large public-contract, schema, protocol, privacy, or architecture change,
open an RFC or a design discussion before investing in a large implementation.
Small fixes can go directly to a pull request.

## Development setup

Use the Go version selected by `go.mod`, Python 3, and `make`. Docker is needed
only for container checks. The repository vendors Go dependencies, so normal
builds and tests can run reproducibly from the checkout.

Run the complete local gate:

```sh
make check
```

Useful narrower commands are:

```sh
make build
make test
make race
make vet
make schema-check
make integration-check
make docs-check
make license-check
make docker-check   # requires Docker
```

Run the narrowest relevant test while iterating, then run `make check` before
submitting. CI also performs cross-platform builds, race tests, static and
vulnerability analysis, CodeQL, dependency review, workflow linting, and
offline container smoke tests.

## Test and evidence expectations

- Bug fixes should include a focused regression test.
- Protocol assertions should cite their public source and include a passing
  reference case plus a targeted negative or mutant case when practical.
- Tests must be deterministic and local by default. Do not contact a real
  provider or public target from ordinary test suites.
- Use synthetic credentials and isolated temporary directories. Tests must not
  inherit ambient API keys.
- Keep wire, provider/model, client, and harness failures distinct.
- Update documentation and migration notes when users would otherwise be
  surprised.

Do not copy fixtures, tests, logs, or issue text without compatible reuse
rights. Record the origin and applicable license for imported material.

## Commits and DCO

The project uses the
[Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a contributor license agreement. Sign off each commit:

```sh
git commit -s
```

The resulting `Signed-off-by` trailer certifies that you have the right to
submit the contribution under the project's license. Do not add another
person's sign-off without their authorization.

## Pull requests

A useful pull request description covers:

- the problem and observable outcome;
- what is in and out of scope;
- public-interface and compatibility impact;
- security, privacy, data, and licensing impact;
- tests and exact validation commands; and
- documentation or migration changes.

Keep changes reviewable and avoid unrelated generated or formatting churn.
Maintainers may request changes, split a large proposal, or ask for additional
evidence in a security-sensitive area. Passing CI is required but does not
replace review of behavior and risk.

Contributions are accepted under the [Apache License 2.0](LICENSE) unless a
file states a different compatible license.
