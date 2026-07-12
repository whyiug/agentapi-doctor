# ADR-0007: Local CAS and evidence manifest

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Local runs need tamper-evident, deduplicated evidence that remains usable
offline and can be replayed without a service. Large payloads must be bounded,
streamed, and recoverable after interruption. A searchable local index is
useful, but it must not become a hidden authority or the sole copy of evidence.

The evidence object model is proposed in
[RFC-0002](../rfcs/0002-evidence-and-result-schema.md); persistence remains
behind the write-before-redact boundary in [ADR-0006](ADR-0006-secret-references-and-write-before-redact-prohibition.md).

## Proposed decision

- Store only sanitized persistent payloads in a local SHA-256
  content-addressed store. Verify the content digest on commit, import, and
  read.
- Stream bounded objects through a task-owned staging area, use atomic commit,
  and discard incomplete or mismatched content. Proposed large-object storage
  uses independently verified compressed chunks and records the ordered chunk
  digests, sizes, compression parameters, and whole-object digest.
- Make an immutable, canonical evidence manifest the root of a run's persisted
  artifacts. It records schema and manifest version, object references,
  media/type and sizes, run/invocation/attempt relations, capture layer,
  redaction policy and records, source/transform/evaluator identities,
  unavailable reasons, and retention/publication class.
- Never allow a driver to assert a final CAS reference. The core creates the
  reference only after receiving, bounding, sanitizing, hashing, and committing
  the observation.
- Use pure-Go SQLite only as a local rebuildable index over manifests and CAS
  objects. Loss or corruption of the index must be recoverable without changing
  artifact identity. SQLite is not the sole evidence store.
- Keep the future hosted Registry storage boundary separate: PostgreSQL may be
  its transactional system of record and content-addressed object storage may
  hold large artifacts, but neither is required for local use.
- Make backup and restore preserve manifest/CAS identity and verify every
  restored object. Derived indexes and read models are rebuilt rather than
  treated as authority. Operational expectations are described in
  [backup and recovery](../docs/operations/backup-and-recovery.md).

## Consequences

Content addressing deduplicates immutable sanitized bytes and makes tampering
detectable. It does not prove that the bytes were lawful, complete, or produced
by an authorized runner. Chunk and manifest metadata increase implementation
complexity, and garbage collection must trace immutable roots without deleting
referenced objects.

Maintaining distinct local and hosted stores requires shared object and
integrity fixtures. Local users avoid PostgreSQL and object-service operations;
hosted operators still need migrations, backup/restore, retention, and
quarantine controls.

## Alternatives

- Store evidence only in SQLite: simple queries, but database corruption would
  destroy the sole copy and obscure content identity.
- Use PostgreSQL everywhere: breaks zero-service local and offline use.
- Let each report embed payloads: duplicates content and makes integrity,
  retention, and redaction harder to audit.
- Address encrypted raw plaintext by its pre-redaction hash: leaks correlation
  and violates the strict persistence boundary.

## Validation before acceptance

Test streaming and deduplication, atomic interruption at every commit stage,
digest mismatch, chunk loss/reordering/corruption, manifest traversal and size
limits, SQLite loss/rebuild/concurrency, backup/restore, and garbage-collection
reachability on supported platforms. Secret canaries must remain absent from
staging, CAS, index, manifest, and backups. Hosted PostgreSQL claims require
separate migration and recovery evidence; none is accepted by this ADR.
