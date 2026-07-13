# ADR-0003: Raw wire evidence and derived observations

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Raw protocol observations are required to diagnose framing, ordering,
provider-native types, cancellation, and client parser failures. A derived or
client-observed view must not overwrite the evidence that produced it.

## Decision

- Preserve bounded, sanitized capture-layer evidence with direction, sequence,
  media type, digest, redaction records, and explicit unavailable reasons.
- Store a pinned client observation separately from the raw evidence and link
  the two by stable references.
- Treat every normalization or interpretation as a typed, versioned derived
  operation, never as repair of the original observation.
- Preserve unknown and lossy states instead of inventing normalized values.
- Keep wire, client, provider, and harness failures distinguishable.
- Apply the sanitize-before-store boundary from
  [ADR-0006](ADR-0006-secret-references-and-write-before-redact-prohibition.md)
  before persistence.

## Release boundary

The v0.1.0 Doctor supports raw Quick Check evidence and one pinned OpenAI
Python SDK reproduction case. A general provider-neutral IR, reusable
cross-protocol oracle API, and generic client-driver correlation contract are
experimental and are not accepted public APIs.

## Consequences

Reports carry explicit evidence relations and can identify the layer where a
failure was observed. Derived behavior can evolve without rewriting the
original capture, but any promoted transform needs its own version and
migration policy.

## Validation basis

Acceptance is limited to the raw evidence and pinned-client paths exercised by
the Doctor release. Experimental normalizer packages do not broaden this
decision.
