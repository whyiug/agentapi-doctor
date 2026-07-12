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
- One-command synthetic demo and one-off endpoint checks that do not require a
  project config or persisted target definition.

### Changed

- Replaced the internal bootstrap lifecycle machinery with a conventional
  protected-main pull-request workflow and standard `make` development targets.
- Added English and Simplified Chinese project home pages and Quick Starts,
  plus installation, configuration, CLI reference, and troubleshooting guides.
- Release archives and minimal OCI images now carry a generated third-party
  license bundle; Registry and reference-server binaries expose exact build
  identity, and release smoke tests verify every native archive.
- Release publication now emits checksum-covered image-specific SPDX SBOMs for
  both published OCI image digests.
- First-run documentation now leads with a source install, a one-command demo,
  and direct checks for authorized local or remote endpoints.
- Local run records now atomically bind the canonical report to a validated,
  persistence-safe plan snapshot while retaining read-only compatibility with
  legacy report-only records.
- Non-root endpoint base paths are now treated as complete API prefixes, so
  versioned gateways such as `/api/v3` are not silently rewritten with `/v1`.
- The default four-check run deadline is 60 seconds; deadline exhaustion now
  persists an inconclusive partial report instead of using the user-cancelled
  exit code.

### Security

- Added fail-closed archive extraction checks, exact-origin/no-redirect network
  policy, loopback listener defaults, bounded request/response handling,
  sanitize-before-store enforcement, symlink/permission checks, and tests that
  use synthetic credentials rather than ambient secrets.
- On Windows, retained filesystem snapshots now resolve their volume and file
  identity before later comparisons, preventing same-path replacement from
  being accepted through Go's lazy `SameFile` lookup.
- Redacts endpoint-reflected credentials before AssertionResult construction and
  finding fingerprinting, then enforces a whole-report no-redaction-needed
  invariant before run persistence.
- Rejects IANA special-purpose IPv4/IPv6 space in the future public-runner
  network mode while preserving explicitly authorized local-target behavior.
- Every built-in provider request includes its protocol's provider-side
  64-token output-limit field in addition to the existing four-request,
  response-size, and execution-time limits. This is not a client-enforced token
  ceiling: a provider may reject or ignore it. Explicit unsupported-field
  400/422 responses and output-limit terminal states observed while evaluating
  completion status are reported as inconclusive prerequisites rather than
  target incompatibilities.
- Secret references and free-form target metadata are omitted from persisted
  plan snapshots and resolved plan-only output. They remain bound only inside
  the ephemeral execution plan, avoiding a persisted low-entropy digest that
  could be guessed offline.
- Evidence envelopes are stored separately from sanitized payloads, and every
  report Evidence reference is verified through the complete
  report-to-envelope-to-payload graph before it is treated as reproducible.
- Evidence `v1alpha2` binds schema, producer, creation time, graph relations,
  and its resolvable sanitized payload into the content-addressed identity.
  Streaming persistence is capped at 512 logical events before falling back
  to one bounded structured projection; opaque response content is represented
  by metadata instead of persisting target-controlled raw text.
- Result schema `v1alpha2` carries Evidence references on non-verdict cases, so
  authentication, permission, transient, and transport observations remain
  reachable from the persisted report rather than becoming CAS orphans. It
  also gives authentication and permission their own reason codes instead of
  mislabeling them as local harness failures.
- New reports use report-bundle `v1alpha2` for that case-level graph edge;
  report readers retain read-only support for `v1alpha1` bundles.

There are no tagged RC or stable releases. This section records development
facts and does not claim support, external review, adoption, or publication.
