# Known Limitations

AgentAPI Doctor is in active pre-release development. These are the current
product boundaries; they are not hidden compatibility claims.

## Execution and compatibility

- There is not yet a tagged binary or package release. Install the current
  source snapshot with
  `go install github.com/whyiug/agentapi-doctor/cmd/doctor@latest` or build a
  checkout.
- Client-side execution can target an explicitly authorized local,
  private-network, or remote origin. It currently covers raw HTTP behavior for
  `openai-chat`, `openai-responses`, and `anthropic-messages`, with four
  built-in checks chosen for the configured protocol.
- Each built-in request asks the provider for a 64-token output limit. This is
  not a client-enforced token ceiling: a provider can reject or ignore the
  field. Explicit field rejection and limit-induced completion truncation are
  reported as inconclusive prerequisites rather than target incompatibility.
- The four checks run sequentially under one 60-second deadline. A deadline
  produces a persisted partial, inconclusive report (exit 4), not a target
  incompatibility or a user-interruption exit.
- Real SDK/client drivers and complete agent loops are not yet supported. The
  checked-in driver, profile, and runtime manifests are development inputs.
- The Requirement Catalog contains 260 metadata scenarios. These are not 260
  executable conformance tests; the reference server currently exposes 12
  executable targeted mutation modes.
- Catalog interpretations marked `candidate` / `pending_review` have not
  completed independent protocol-source review.
- No public result is a vendor certification, endorsement, or guarantee of
  behavior outside the exact endpoint, model, built-in pack/profile digests,
  plan, and evidence tested. A run does not automatically attest its CLI
  source commit.
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

- Homebrew, Scoop, GitHub Action, reusable-workflow, OCI, SBOM, provenance, and
  release automation are tested in the repository but remain unpublished until
  the first tagged release.
- Public JSON Schemas and Registry OpenAPI are versioned pre-release contracts.
  A stable compatibility and migration floor has not been declared.
- No external penetration test, privacy/legal review, verified adopter set, or
  long-term support window is claimed.

Product tests establish only the behavior asserted by those tests. Limitations
should be removed when the corresponding implementation, documentation, and
repeatable evidence exist.
