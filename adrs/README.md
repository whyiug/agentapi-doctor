# Architecture Decision Records

Architecture Decision Records capture product and engineering decisions with
their scope, tradeoffs, and validation basis. `accepted` means the narrowed
decision is implemented and release-reviewed; it does not promote an
experimental surface named in the same document. `deferred` means no public
contract or support claim exists yet.

## Accepted for the Doctor product

1. [ADR-0001: Core language and binary distribution](ADR-0001-core-language-and-binary-distribution.md)
2. [ADR-0002: Canonical JSON and digest boundaries](ADR-0002-canonical-json-and-digest-boundaries.md)
3. [ADR-0003: Raw wire evidence and derived observations](ADR-0003-raw-wire-vs-provider-neutral-ir.md)
4. [ADR-0006: Secret references and write-before-redact prohibition](ADR-0006-secret-references-and-write-before-redact-prohibition.md)
5. [ADR-0007: Local CAS and evidence records](ADR-0007-local-cas-and-evidence-manifest.md)
6. [ADR-0008: Pack/Profile identity and versioning](ADR-0008-pack-profile-versioning.md)
7. [ADR-0009: Result states and no single score](ADR-0009-result-dimension-and-no-single-score.md)
8. [ADR-0011: Source snapshot and copyright policy](ADR-0011-source-snapshot-and-copyright-policy.md)

## Deferred ecosystem decisions

1. [ADR-0004: Scenario DSL and CEL sandbox](ADR-0004-scenario-dsl-and-cel-sandbox.md)
2. [ADR-0005: Driver process and isolation](ADR-0005-driver-process-and-isolation.md)
3. [ADR-0010: Registry trust and attestation](ADR-0010-registry-trust-and-attestation.md)

New ADRs record context, alternatives, the decision or candidate direction,
consequences, validation evidence, decider, and date. Reversing an accepted
decision creates a superseding ADR instead of silently rewriting history.
