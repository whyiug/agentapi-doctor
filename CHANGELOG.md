# Changelog

All notable changes to published AgentAPI Doctor releases will be documented in
this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and any future stable
CLI/Core versions will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Source-buildable `doctor`, Registry, synthetic reference-server, catalog,
  schema, and support-validation commands.
- A local candidate execution path with offline Intent/Resolved plan creation,
  exact-origin transport, hard budgets, secret-reference resolution,
  redaction-before-persistence, content-addressed evidence, run storage, and
  six report renderers.
- Four executable candidate checks for each of the `openai-chat`,
  `openai-responses`, and `anthropic-messages` protocol slices.
- A loopback-by-default synthetic reference server with 12 executable targeted
  mutation modes and reference-pass/mutant-fail regression coverage.
- A seven-pack Requirement Catalog containing 260 candidate scenario,
  reference-fixture, and targeted-mutant metadata records. These records remain
  pending review and are not 260 executable mutations or support claims.
- Versioned candidate schemas for configuration, plans, evidence, results,
  reports, packs, profiles, driver frames, support metadata, and Registry
  observations, plus a candidate Registry OpenAPI document.
- A single-node SQLite Registry candidate with explicit durable/ephemeral
  modes, scoped bearer tokens, local backup, a static Matrix, hardened
  container targets, and loopback-published Compose wiring.
- Candidate driver/profile/runtime/support manifests, local GitHub Action and
  reusable-workflow integrations, Homebrew/Scoop packaging metadata, release
  automation, SBOM/provenance configuration, and CI security checks.
- Community, governance, security, privacy, data-license, operations,
  contribution, architecture, and bilingual getting-started documentation.

### Security

- Added fail-closed archive extraction checks, exact-origin/no-redirect network
  policy, loopback listener defaults, bounded request/response handling,
  sanitize-before-store enforcement, symlink/permission checks, and tests that
  use synthetic credentials rather than ambient secrets.
- Redacts endpoint-reflected credentials before AssertionResult construction and
  finding fingerprinting, then enforces a whole-report no-redaction-needed
  invariant before run persistence.
- Rejects IANA special-purpose IPv4/IPv6 space in the future public-runner
  network mode while preserving explicitly authorized local-target behavior.

There are no tagged RC or stable releases. This section records development
facts only; it does not establish Genesis, phase completion, support, review,
adoption, publication, or GA readiness.
