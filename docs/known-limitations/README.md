# Known Limitations

AgentAPI Doctor is a pre-Genesis, pre-release candidate. The following
limitations are part of its current product boundary, not a release roadmap
that should be represented as completed work.

## Execution and compatibility

- There is no supported binary/package release or stable CLI/config contract;
  the `doctor` binary is currently built from source.
- The runnable local slice covers only raw HTTP behavior for `openai-chat`,
  `openai-responses`, and `anthropic-messages`. It selects four candidate
  checks for the configured target protocol.
- No real SDK/client driver or complete agent loop has an approved support
  Tier. Checked-in driver, profile, runtime-adapter, and support manifests are
  candidate/unresolved metadata.
- The Requirement Catalog has 260 candidate scenario records with reference
  and targeted-mutant metadata. They are not 260 executable conformance tests.
  The local reference server exposes 12 executable targeted mutation modes.
- No real provider result, live canary result, public compatibility report,
  certification badge, or vendor endorsement is published.
- Built-in Requirement Catalog interpretations remain
  `candidate` / `pending_review`; they have not completed independent source
  review.
- Windows does not currently accept `file://` secret references because Go's
  synthesized mode bits cannot prove that a DACL is private; use `env://` in
  this candidate. Unix-like systems continue to require no group/other mode
  bits. `exec://` remains disabled unless explicitly approved.

## Registry, Matrix, and distribution

- A runnable single-node SQLite self-hosted Registry candidate, static Matrix
  source, backup command, Docker targets, and local Compose bundle exist. They
  do not constitute a production-supported service.
- On Windows, SQLite paths must use a local drive-letter path. UNC shares,
  device paths, and drive-relative paths are rejected rather than treated as
  local durable storage.
- No hosted verifier, project-operated Registry or Matrix, public runner,
  managed image, production SLO, recovery drill, or public Registry dataset
  exists. A local durable upload cannot receive a project trust label.
- Homebrew, Scoop, GitHub Action, reusable-workflow, release, SBOM, provenance,
  and signature configuration are unpublished distribution candidates. No RC
  or stable artifact has been released.
- The candidate release workflow is fail-closed: there is no approved RC gate,
  the GA gate has no authoritative phase state, and the currently configured
  release Environment cannot itself prove the required two-maintainer and
  independent-organization approvals.
- Public JSON Schemas and Registry OpenAPI are versioned candidate artifacts;
  there is no stable compatibility or migration promise yet.

## Governance and readiness

- Genesis has not occurred. There is no authoritative phase state, active work
  unit, approved P00/P01 transition, phase completion, or GA result.
- No completed independent security design review, penetration test, privacy or
  legal review, verified adopter set, external support evidence, TSC, release
  quorum, or GA vote exists.
- There is no completed six-week/two-RC observation window, stable support
  period, or historical-corpus rights review.

Bootstrap validation establishes only that the phase-external P00.B00 candidate
passes its own structural and anti-placeholder checks. Product tests establish
only their asserted local behavior. Neither is approval or phase state.

Limitations are removed only after their authoritative contract and evidence
gates actually pass. This page must not be edited merely to improve project
appearance.
