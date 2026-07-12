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

## Next: one real-client case

The only active product expansion is a pinned OpenAI Python SDK / Responses
streaming profile covering terminal-event and strict-envelope failures. It must
produce both raw-wire and SDK observations plus a maintainer-ready redacted
reproduction bundle.

Success means one public failure family is deterministic on a clean runner and
an external maintainer or integrator finds the bundle easier to reproduce than
hand-assembled logs.

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
