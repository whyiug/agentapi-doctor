# ADR-0002: Canonical JSON and digest boundaries

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Doctor artifacts need byte-stable identity across platforms. Ordinary JSON
encoders may differ in key order, escaping, and number rendering, while
permissive parsers may accept duplicate keys or trailing values.

## Decision

- Parse digest-bound JSON strictly, rejecting duplicate keys, invalid UTF-8,
  trailing values, non-finite or out-of-contract numbers, and excessive
  nesting before hashing.
- Define a versioned immutable projection for each promoted object kind.
- Encode the projection as RFC 8785 JCS UTF-8 and calculate SHA-256 over those
  bytes.
- Exclude self-digests, signatures, convenience locations, and mutable derived
  state from content identity.
- Keep object, manifest, artifact-byte, and source-snapshot digest domains
  distinct.
- Verify schema and digest on supported reads; a digest does not replace
  authorization, provenance, or semantic validation.

## Release boundary

This decision covers canonicalization and digest boundaries exercised by the
local Doctor and its promoted artifacts. Experimental Registry attestation and
import contracts are not accepted by this ADR.

## Consequences

Pretty-printed JSON may differ from hashed bytes. Tooling therefore identifies
the subject kind, projection version, and digest. An identity projection change
is a public contract change for any artifact included in the migration floor.

## Validation basis

The implementation includes strict parsing, JCS canonicalization, sealed
projections, digest verification, and targeted malformed-input tests. Stable
reader promises remain limited to the declared migration floor.
