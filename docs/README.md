# Documentation

This is the documentation map for AgentAPI Doctor. The repository is
pre-Genesis and pre-release: runnable source is not evidence that a protocol,
client, hosted service, support Tier, or release is approved.

Status words are used deliberately:

- **current candidate** — can be exercised from checked-in source and tests,
  but has no stable/support claim;
- **provisional** — design or metadata awaiting the applicable review; and
- **future** — required by the Plan but not implemented or operated.

## Learn and use

- [Getting started](getting-started/README.md) — build the candidate CLI and run
  a cleaned-up, loopback-only synthetic check.
- [Known limitations](known-limitations/README.md) — exact gaps in execution,
  hosting, distribution, governance, and readiness.
- [Concepts](concepts/README.md) — compatibility layers, evidence, oracles,
  packs, and profiles.
- [Protocol families](protocols/README.md) — provisional protocol boundaries
  and candidate catalog context, without support claims.
- [Clients](clients/README.md) — driver/profile identity and future
  support-matrix rules.

## Build and operate

- [Authoring packs](authoring-packs/README.md)
- [Authoring drivers](authoring-drivers/README.md)
- [Security and privacy](security-and-privacy/README.md)
- [Registry](registry/README.md) — runnable SQLite self-host candidate; no
  hosted Registry or verifier exists.
- [Operations](operations/README.md)
- [Migration](migration/README.md)
- [Reference](reference/README.md) — current executable, schema, catalog,
  Registry, and distribution candidate surfaces.
- [Contributing documentation](contributing/README.md)

## Core Chinese guides

The [简体中文核心指南](zh-CN/README.md) covers getting started, architecture,
contributing, and protocol boundaries. English and versioned source artifacts
remain normative; the translations are explicitly draft and make no invented
source-commit or review claim.

## Authority

The implementation design is [the Plan](../agentapi-doctor-Plan.md). Before
Genesis, repository rules permit only the phase-external P00.B00 bootstrap
candidate: there is no authoritative phase state or active work unit. After a
real Genesis and P01 approval, the Plan assigns execution authority to the
versioned manifests and append-only transition chain. Generated reference
material may explain a schema, but only the versioned artifact and its digest
define that candidate contract.
