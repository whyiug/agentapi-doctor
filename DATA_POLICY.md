# Data Policy

## Current status

AgentAPI Doctor is local-first and pre-release. No project-operated hosted
Registry, public runner, telemetry service, or observation upload service is
available today. This policy describes current repository behavior and the
minimum boundaries any future hosted service must satisfy.

## Data classes

The project distinguishes:

- configuration and secret references;
- requests, responses, stream events, and tool data;
- raw capture-layer evidence and normalized internal representations;
- result, report, failure, and run metadata;
- local artifacts, fixtures, logs, and crash output;
- identity, signature, ownership, and audit metadata; and
- a future public projection of non-sensitive compatibility facts.

These classes must not be silently collapsed. In particular, a public fact is
not permission to publish its raw artifact, identity record, comment, model
text, or signature.

## Local use

Local runs do not opt users into telemetry or upload. Until a versioned feature
explicitly says otherwise:

- data remains in locations selected by the user;
- users control local retention and deletion;
- the local CLI must work without a public Registry;
- ambient credentials, keychains, real `.env` files, and the user's home
  directory are not test inputs; and
- tests use synthetic data and an isolated temporary `HOME`.

Users remain responsible for authorization to process endpoint traffic and for
the security of their local output directory.

## Collection minimization and redaction

Only data needed for a declared test or evidence purpose should be collected.
Strict capture must redact secrets before any persistent write, including raw
artifacts, normalized artifacts, reports, logs, temporary files, and crash
output. A failure to establish write-before-redact safety blocks that feature.

Redaction must cover credentials and authorization headers, cookies, secret
references, provider keys, private URLs where configured, and user-defined
patterns. Reports should prefer digests, bounded excerpts, and synthetic
reproductions. Redaction is not anonymization; residual re-identification risk
must be documented.

## Public observations

No public observation dataset exists today. A future public export may contain
only the non-sensitive factual projection defined in
[DATA_LICENSE.md](DATA_LICENSE.md), when the submitter:

1. has the right to submit the facts and underlying material;
2. explicitly opts into the stated public license;
3. previews the exact public projection;
4. passes secret, policy, and provenance checks; and
5. receives a durable record of the applicable terms and object digests.

Identity, comments, signatures, raw artifacts, private configuration, and model
text are not automatically part of that projection.

## Future hosted processing

Before a hosted Registry can accept data, the project must publish reviewed,
effective versions of its Registry Terms and Privacy Notice and implement:

- purpose-limited collection and access controls;
- two-phase upload with a public-projection preview;
- secret quarantine and deterministic validation;
- retention schedules for each data class;
- withdrawal, dispute, supersede, tombstone, and physical-deletion procedures;
- ownership and audit records;
- incident response and breach handling;
- backup/restore behavior with stated RPO/RTO; and
- applicable cross-border, age, and legal review.

The draft files in this repository are not a substitute for those controls.

## Sensitive-data incident

If sensitive data is found in repository content or an artifact, stop further
publication, preserve only the audit facts needed for response, restrict access,
and report it privately under [SECURITY.md](SECURITY.md). Do not copy the data
into a public issue while requesting removal.

Changes that reduce privacy defaults, alter retention, or change public
projection semantics require the RFC and review process in
[GOVERNANCE.md](GOVERNANCE.md).
