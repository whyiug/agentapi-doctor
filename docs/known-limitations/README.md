# Known Limitations

AgentAPI Doctor is in active pre-release development. These are the current
product boundaries; they are not hidden compatibility claims.

## Execution and compatibility

- There is not yet a tagged binary or package release. Build the `doctor`
  command from source.
- Local execution currently covers raw HTTP behavior for `openai-chat`,
  `openai-responses`, and `anthropic-messages`, with four built-in checks chosen
  for the configured protocol.
- Real SDK/client drivers and complete agent loops are not yet supported. The
  checked-in driver, profile, and runtime manifests are development inputs.
- The Requirement Catalog contains 260 metadata scenarios. These are not 260
  executable conformance tests; the reference server currently exposes 12
  executable targeted mutation modes.
- Catalog interpretations marked `candidate` / `pending_review` have not
  completed independent protocol-source review.
- No public result is a vendor certification, endorsement, or guarantee of
  behavior outside the exact version, target, plan, and evidence tested.
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
