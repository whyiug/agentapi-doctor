# ADR-0007: Local CAS and evidence records

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Local Doctor runs need tamper-evident evidence that works offline. Persistence
must stay behind the sanitize-before-store boundary and must not depend on a
hosted database or service.

## Decision

- Store only sanitized persistent payloads in a local SHA-256
  content-addressed store.
- Verify content digests on commit and supported reads.
- Use task-owned staging and atomic file operations so incomplete content does
  not become a completed run artifact.
- Link run records, results, reports, and evidence objects by versioned object
  references and preserve explicit unavailable reasons.
- Treat indexes and convenience pointers as derived state, never as artifact
  identity or the sole evidence copy.
- Keep persistence independent of any Registry or hosted store.

## Release boundary

This decision covers the file-based local CAS and run records used by Doctor.
Chunked large-object storage, a rebuildable SQLite index, garbage collection,
hosted PostgreSQL/object storage, and hosted backup guarantees remain deferred.

## Consequences

Content addressing detects accidental or malicious byte changes but does not
prove that an observation is complete, lawful, or from an authorized target.
Readers must continue to enforce schema, size, digest, and migration rules.

## Validation basis

Acceptance is based on the local CAS, atomic run persistence, digest checks,
sanitized evidence path, and release-reviewed run inspection/report behavior.
Only artifacts named by the migration floor receive a reader promise.
