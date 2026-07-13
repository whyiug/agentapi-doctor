# ADR-0010: Registry trust and attestation

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

A public compatibility Registry could mislead users if self-reports, owner
statements, independent reproductions, project runs, stale observations, and
disputes appear equivalent. Upload also creates secret, SSRF, privacy, rights,
abuse, identity, and recovery boundaries.

## Candidate direction

The design keeps immutable observations separate from mutable trust,
freshness, dispute, supersession, withdrawal, and deletion records. Proposed
labels describe evidence provenance rather than quality rank. Submitters cannot
self-award derived trust, and the local Doctor must remain independent of
hosted availability.

## Why deferred

The project operates no hosted Registry, verifier, runner, upload service, or
public Matrix. The single-node Registry and static Matrix source are
experimental and cannot satisfy the identity, quarantine, authorization,
privacy, operations, or independent-review requirements of a public service.

## Promotion criteria

Acceptance requires an accepted service RFC, effective terms and privacy
documentation, operator identity, bounded quarantine, ownership and signer
verification, SSRF and content-security defenses, dispute and deletion flows,
backup/restore drills, abuse controls, independent security and legal review,
and an explicit release announcement. No trust label is authorized before
those conditions are met.
