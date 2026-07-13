# Known Limitations

AgentAPI Doctor is in active pre-release development. These are the current
product boundaries; they are not hidden compatibility claims.

## Execution and compatibility

- `v0.1.0-rc.3` is a release candidate, not a stable compatibility contract.
  The supported distribution is the `doctor` CLI archive for Linux, macOS, or
  Windows. Package-manager channels are not yet published.
- Client-side execution can target an explicitly authorized local,
  private-network, or remote origin. It currently covers raw HTTP behavior for
  `openai-chat`, `openai-responses`, and `anthropic-messages`, with four
  built-in checks chosen for the configured protocol.
- Structural checks request a 64-token output limit. The OpenAI Chat and
  Responses terminal-status checks request 512 tokens, for a four-request
  requested maximum of 704; all four selected Anthropic checks remain at 64
  and request 256 in total. These are not client-enforced token ceilings: a
  provider can reject or ignore the field. Explicit field rejection and
  limit-induced completion truncation remain inconclusive prerequisites rather
  than target incompatibility. Reported reasoning-token usage improves that
  diagnosis but never creates a failure by itself.
- The terminal-status value 512 is a bounded cross-provider default, not a
  guarantee that every reasoning model will finish. Models with larger default
  reasoning budgets may still produce an honest INCONCLUSIVE result. Doctor
  does not disable thinking, branch on model names, or retry with a hidden
  larger request.
- The four checks run sequentially under one 60-second deadline. A deadline
  produces a persisted partial, inconclusive report (exit 4), not a target
  incompatibility or a user-interruption exit.
- The source tree implements one Linux amd64, CPython 3.12.12, OpenAI Python
  2.38.0 Responses streaming reproducer against four loopback synthetic
  fixtures. It is not a driver for arbitrary endpoints, a general SDK support
  claim, or a complete Agent loop.
- The Requirement Catalog contains 260 metadata scenarios. These are not 260
  executable conformance tests; the reference server currently exposes 13
  executable targeted mutation modes.
- Catalog interpretations marked `candidate` / `pending_review` have not
  completed independent protocol-source review.
- No public result is a vendor certification, endorsement, or guarantee of
  behavior outside the exact endpoint, model, built-in pack/profile digests,
  plan, and evidence tested. A run does not automatically attest its CLI
  source commit.
- A real-SDK reproduction marked `confirmed` means its frozen local wire and
  SDK observations match the checked-in oracle. Its bundle records the Doctor
  build/source identity, Doctor and Python executable digests, installed
  distribution metadata, and canonical input digests. Wheel hashes are
  enforced when constructing the environment, not by rehashing every installed
  package file. A client exception alone is insufficient for endpoint
  attribution and produces `unknown` when Doctor cannot validate the
  controlled wire path.
- Local run snapshots omit secret references and free-form target metadata,
  but retain the endpoint URL and model needed to interpret a run. Protect the
  `.agentapi/` directory as private local state.
- The raw driver omits opaque non-JSON response content from persistence.
  Structured model content, identifiers, and tool arguments are not
  anonymized; known secret fields, configured canaries, and recognized token
  forms are redacted. Review local evidence before any export.
- Windows rejects `file://` secret references because Go mode bits cannot prove
  that a Windows DACL is private. Use `env://` on Windows. Unix-like systems
  require no group/other permission bits. `exec://` remains opt-in.

## Registry and Matrix

- The self-hosted Registry is a single-node implementation using memory or
  SQLite storage. It has no clustering, managed upgrades, or production SLO.
- Windows SQLite storage requires a local drive-letter path; UNC, device, and
  drive-relative paths are rejected.
- There is no project-operated Registry, hosted verifier, public runner, hosted
  Matrix, or public Registry dataset. A local observation does not receive a
  project trust label.
- Operators must provide their own TLS termination, authentication boundary,
  backups, monitoring, retention policy, and recovery testing.

## Distribution and contracts

- Release archives include SHA-256 checksums, one SPDX SBOM, and GitHub build
  provenance. Homebrew, Scoop, GitHub Action, reusable-workflow, OCI, Registry,
  and reference-server distributions remain unpublished candidates.
- Public JSON Schemas and Registry OpenAPI are versioned pre-release contracts.
  A stable compatibility and migration floor has not been declared.
- The rc.3 built-in pack/profile identity differs from rc.2 because request
  budgets are digest-bound. Existing run records remain readable, but an rc.2
  baseline is intentionally incomparable with an rc.3 run and should be
  recaptured rather than relabeled.
- No external penetration test, privacy/legal review, verified adopter set, or
  long-term support window is claimed.

Product tests establish only the behavior asserted by those tests. Limitations
should be removed when the corresponding implementation, documentation, and
repeatable evidence exist.
