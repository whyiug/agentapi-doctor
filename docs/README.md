# AgentAPI Doctor Documentation

[Project home](../README.md) | [简体中文](zh-CN/README.md)

AgentAPI Doctor is under active development. You can build and run the current
source, but there is no tagged release, published package, or hosted service
yet. Reports are reproducible observations tied to the endpoint, model,
built-in pack/profile digests, plan, and evidence; they are not vendor
certification and do not automatically attest the CLI source commit.

## Start here

- [Quick Start](quick-start.md) — install the current source snapshot, run the
  one-command demo, or check an authorized endpoint without YAML.
- [Installation](installation.md) — build from source or build local Docker
  images; understand what is not published yet.
- [Getting Started](getting-started/README.md) — configure a target, plan a
  run, execute checks, and render reports.
- [Configuration](configuration.md) — target URLs, protocols, budgets,
  capture modes, retries, and secret references.
- [CLI reference](cli-reference.md) — every implemented command, flag, output
  mode, and exit code.
- [Troubleshooting](troubleshooting.md) — common build, config, credential,
  network, run-store, and Docker failures.
- [Known limitations](known-limitations/README.md) — current coverage and
  publication boundaries.

## Understand the results

- [Concepts](concepts/README.md)
  - [Compatibility layers](concepts/compatibility-layers.md)
  - [Evidence and oracles](concepts/evidence-and-oracles.md)
  - [Profiles and packs](concepts/profiles-and-packs.md)
- [Protocol families](protocols/README.md)
- [Clients](clients/README.md)
- [Reference](reference/README.md) — executable surfaces, schemas, catalog
  counts, Registry, and distribution sources.

The Requirement Catalog contains 260 candidate metadata scenario records.
The local reference server currently exposes 12 executable targeted modes,
and a normal target run selects 4 checks for that target's protocol.

## Operate and integrate

- [Security and privacy](security-and-privacy/README.md)
- [Self-hosted Registry](registry/README.md)
- [Operations](operations/README.md)
  - [Release verification](operations/release-verification.md)
  - [Backup and recovery](operations/backup-and-recovery.md)
  - [Incident response](operations/incident-response.md)
  - [Offline proxy and CA notes](operations/offline-proxy-and-ca.md)
- [Migration](migration/README.md)

## Extend the project

- [Authoring packs](authoring-packs/README.md)
- [Authoring drivers](authoring-drivers/README.md)
- [Synthetic fixtures](getting-started/synthetic-fixtures.md)
- [Contributing documentation](contributing/README.md)
- [Naming research](naming/README.md)

## Project context and policies

- [Roadmap](../ROADMAP.md)
- [Competitive landscape](COMPETITIVE-LANDSCAPE.md)
- [Security policy](../SECURITY.md)
- [Data policy](../DATA_POLICY.md)
- [Threat-model overview](security-and-privacy/threat-model.md) and
  [full threat model](THREAT-MODEL.md)
- [Governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md), and
  [Code of Conduct](../CODE_OF_CONDUCT.md)

## Language coverage

The [简体中文指南](zh-CN/README.md) includes the project overview, Quick
Start, source workflow, architecture, protocol boundaries, and contribution
guide. Detailed reference pages that have not yet been translated are linked
from that index and clearly marked as English.

Machine-readable behavior is defined by the checked-in schemas and
`cli/spec.yaml`. If prose and a versioned schema disagree, treat that as a
documentation bug and report it.
