# Roadmap

AgentAPI Doctor grows from reproducible user failures, not from catalog size or
architecture completeness. The detailed research and stop conditions are in
[`0713-plan.md`](0713-plan.md).

## v0.1.0-rc.1: Quick Check

- One prebuilt `doctor` CLI for Linux, macOS, and Windows.
- Four bounded raw HTTP checks per run for OpenAI Chat, OpenAI Responses, or
  Anthropic Messages.
- Human-readable failure diagnostics, local redacted evidence, six report
  formats, baselines, and stable exit codes.
- A no-key loopback demo and deterministic lifecycle-failure fixture.

This RC does not claim real SDK/Agent compatibility or automatic root-cause
attribution.

## v0.1.0-rc.2: one real-client case

The second release candidate adds one pinned OpenAI Python SDK / Responses
streaming slice covering terminal-event and strict-envelope failures. It
produces both raw-wire and SDK observations plus a maintainer-ready redacted
reproduction bundle.

The slice is Linux amd64 only, uses CPython 3.12.12 and OpenAI Python 2.38.0,
and runs against independently authored loopback fixtures. It is a reproducible
case, not general endpoint or SDK support.

## Next: prove external reuse

The active product question is now whether an external maintainer or integrator
finds the bundle easier to reproduce than hand-assembled logs. The project will
collect real, consented reuse evidence before selecting a second client profile
or expanding distribution infrastructure.

## Conditional backlog

These items start only after external use supplies evidence for them:

- a second pinned client profile;
- a supported GitHub Action or reusable workflow;
- longer-running compatibility-drift pilots;
- a version-bound community matrix or Registry;
- a local Web UI or hosted checker;
- additional package-manager channels.

Until then, existing Registry, Matrix, driver, and distribution candidates are
development assets, not supported product surfaces.
