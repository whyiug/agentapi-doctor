# Architecture Decision Records

This directory now contains the exact twelve ADR topics required by
[Plan section 32.1](../agentapi-doctor-Plan.md). Every ADR remains **proposed**:
no decider, independent review, acceptance, or freeze is recorded. Candidate
implementations and tests may inform a later decision but do not accept an ADR.

1. [ADR-0001: Core language and binary distribution](ADR-0001-core-language-and-binary-distribution.md)
2. [ADR-0002: Canonical JSON and digest boundaries](ADR-0002-canonical-json-and-digest-boundaries.md)
3. [ADR-0003: Raw wire vs provider-neutral IR](ADR-0003-raw-wire-vs-provider-neutral-ir.md)
4. [ADR-0004: Scenario DSL and CEL sandbox](ADR-0004-scenario-dsl-and-cel-sandbox.md)
5. [ADR-0005: Driver process and isolation](ADR-0005-driver-process-and-isolation.md)
6. [ADR-0006: Secret references and write-before-redact prohibition](ADR-0006-secret-references-and-write-before-redact-prohibition.md)
7. [ADR-0007: Local CAS and evidence manifest](ADR-0007-local-cas-and-evidence-manifest.md)
8. [ADR-0008: Pack/Profile versioning](ADR-0008-pack-profile-versioning.md)
9. [ADR-0009: Result dimension and no-single-score](ADR-0009-result-dimension-and-no-single-score.md)
10. [ADR-0010: Registry trust and attestation](ADR-0010-registry-trust-and-attestation.md)
11. [ADR-0011: Source snapshot and copyright policy](ADR-0011-source-snapshot-and-copyright-policy.md)
12. [ADR-0012: Goal phase gate and evidence format](ADR-0012-goal-phase-gate-and-evidence-format.md)

ADR-0007 retains the useful local SQLite/future PostgreSQL storage boundary
from the earlier provisional ADR set while making local CAS and its evidence
manifest the primary decision required by the Plan.

Acceptance must record the applicable context, decision, alternatives,
consequences, validation evidence, deciders, review, and date through the
governance process. Reversal creates a superseding ADR; it does not rewrite
history. Before Genesis, these files remain design candidates and create no
phase state or approval.
