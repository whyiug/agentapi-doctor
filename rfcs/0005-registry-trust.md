# RFC-0005: Registry Trust and Attestation

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review
- **Deployment status:** no hosted Registry exists

## Problem

A public compatibility matrix could mislead users if self-reported
observations, owner statements, independent reproductions, project runs, stale
results, and disputes appear equivalent. Upload also introduces secret, SSRF,
identity, privacy, rights, abuse, and recovery risks.

## Candidate design

The design keeps immutable submitted observations separate from mutable
freshness, provenance labels, disputes, responses, supersession, withdrawal,
and deletion records. Proposed labels describe the evidence path, not a quality
rank or certification. A submitter cannot self-award Registry-derived trust.

Candidate ingest uses authenticated bounded quarantine, exact schema and digest
verification, provenance and rights checks, secret policy, deterministic
reevaluation, preview of the public projection, affirmative consent, and an
append-only audit record. A project runner would never accept arbitrary public
targets.

## Why deferred

The project operates no hosted Registry, verifier, runner, upload service,
public dataset, or Matrix. The source-only SQLite service and static Matrix are
development assets and do not have production identity, authorization,
privacy, abuse, legal, backup, recovery, or penetration-test evidence.

The supported Doctor CLI remains independent of all Registry availability.

## Compatibility and security

All Registry HTTP APIs, schemas, labels, attestations, storage layouts, Matrix
views, and operations documents are experimental. No repository document is a
service term, privacy notice, publication consent, or project trust grant.

## Promotion criteria

Acceptance requires a named operator, effective terms and privacy
documentation, an enumerated public projection, authentication and ownership
verification, quarantine and content-security controls, retention and deletion
rules, dispute and appeal handling, backup/restore drills, incident and abuse
response, independent security and legal review, external penetration testing,
and an explicit service release.
