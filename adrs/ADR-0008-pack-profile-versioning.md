# ADR-0008: Pack/Profile identity and versioning

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

An observation is interpretable only against the exact check definitions,
requirements, capability rules, and denominator that produced it. A mutable
alias must not silently change a historical result.

## Decision

- Give pack-like protocol definitions CalVer plus an independent protocol
  revision; give consumer profiles SemVer.
- Bind every referenced pack, profile, source lock, scenario denominator,
  support lock, evaluator, and core definition to an immutable digest.
- Treat names and tags as discovery pointers, not sufficient evidence identity.
- Never overwrite a published digest.
- Publish a new artifact for any change that can alter selection, expected
  behavior, evidence, denominator, or verdict.
- Compare trends only when the relevant denominator identity is compatible;
  otherwise explain the mismatch and show observations separately.
- Treat promotion status independently from identity and version.

## Release boundary

This ADR accepts the identity and comparison policy used by Doctor. It does not
promote the repository's candidate packs, profiles, support matrix, authoring
format, or Registry distribution. The v0.1.0 built-in interpretations remain
candidate material pending their own review.

## Consequences

Evidence carries longer identifiers, but historical interpretation remains
reproducible. A friendly name can move without changing old evidence, while a
candidate artifact does not become supported merely because it has a version
and digest.

## Validation basis

Acceptance is based on digest-bound built-in definitions, baseline comparison
guards, immutable candidate artifacts, and release review. Ecosystem promotion
requires separate authoring, migration, and support evidence.
