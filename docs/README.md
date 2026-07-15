# AgentAPI Doctor Documentation

[Project home](../README.md) | [Simplified Chinese](zh-CN/README.md)

The supported v0.1.x product is the local `doctor` CLI distributed in verified
GitHub Release archives. There is no hosted service or supported
package-manager channel. Doctor reports reproducible observations tied to an
endpoint, model, built-in check definitions, run inputs, and evidence; they are
not vendor certification.

## Start here

- [Quick Start](quick-start.md) - install the CLI, run the loopback demo, or
  check an authorized endpoint without YAML.
- [Installation](installation.md) - verify a release archive or build from
  source.
- [Getting Started](getting-started/README.md) - configure a target, prepare a
  run, execute checks, and render reports.
- [Configuration](configuration.md) - target fields, fixed Quick Check
  boundaries, and secret references.
- [CLI reference](cli-reference.md) - implemented commands, flags, output
  modes, and exit codes.
- [Troubleshooting](troubleshooting.md) - common build, configuration,
  credential, network, and run-store failures.
- [Known limitations](known-limitations/README.md) - current coverage and
  publication boundaries.

## Understand and share results

- [Concepts](concepts/README.md)
- [Compatibility layers](concepts/compatibility-layers.md)
- [Evidence and oracles](concepts/evidence-and-oracles.md)
- [Profiles and packs](concepts/profiles-and-packs.md)
- [Protocol families](protocols/README.md)
- [Clients](clients/README.md)
- [Commit-pinned llama.cpp Responses A/B](cases/llama-cpp-responses-pr-21174.md)
- [Pinned OpenAI Python SDK case](cases/openai-python-responses-null-output.md)
- [Reference](reference/README.md)
- [Migration and artifact compatibility](migration/README.md)

## Security and project policy

- [Security and privacy](security-and-privacy/README.md)
- [Data policy](../DATA_POLICY.md)
- [Security policy](../SECURITY.md)
- [Threat-model overview](security-and-privacy/threat-model.md) and
  [full threat model](THREAT-MODEL.md)
- [Roadmap](../ROADMAP.md)
- [Governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md), and
  [Code of Conduct](../CODE_OF_CONDUCT.md)

## Experimental contributor surfaces

The following areas are source-only development assets. They are not supported
v0.1.x product surfaces, hosted services, stable extension contracts, or
compatibility claims:

- [Scenario pack authoring](authoring-packs/README.md)
- [Generic driver authoring](authoring-drivers/README.md)
- [Registry and Matrix candidate](registry/README.md)
- [Operator design notes](operations/README.md)
- [Google API research](protocols/google/README.md)
- [Model Context Protocol research](protocols/mcp/README.md)
- [Synthetic fixture development](getting-started/synthetic-fixtures.md)
- [Naming research](naming/README.md)

See [contributing documentation](contributing/README.md) before changing these
areas. Candidate schemas, catalogs, packs, profiles, drivers, and Registry
interfaces can change without a v0.1.x compatibility promise unless a release
explicitly promotes them.

## Language coverage

The [Simplified Chinese guide](zh-CN/README.md) covers the project overview,
Quick Start, source workflow, architecture, protocol boundaries, and
contribution guide. Detailed English-only pages are linked from that index.

Machine-readable behavior promoted by a release is defined by the applicable
checked-in schema and `cli/spec.yaml`. If prose and a promoted versioned
contract disagree, report it as a documentation bug.
