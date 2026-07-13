# RFC-0002: Local Evidence and Result Contracts

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Problem

Evidence loses value when object identity can be rebound, derived values hide
raw input, or result fields mix selection, execution, verdict, and attribution.
Local artifacts also need explicit reader compatibility instead of an implied
promise for every development schema in the repository.

## Accepted v0.1.0 contract

### Identity

Promoted digest-bound objects use a versioned kind and an explicit immutable
projection. SHA-256 is calculated over RFC 8785 JCS UTF-8. Readers reject
duplicate keys, invalid UTF-8, trailing values, invalid numbers, excessive
nesting, schema errors, and digest mismatch before treating an object as valid.

Instance identity, content identity, producer identity, and convenience
locations remain separate. Mutable aliases such as `latest` are not durable
evidence references.

### Evidence

Persisted evidence records the run and attempt relation, ordered observation,
capture layer, direction, media type, payload reference and digest, redaction
records, and explicit unavailable reason. Only sanitized values may cross the
persistence boundary.

Raw evidence is not overwritten by a report, client observation, or derived
interpretation. Experimental normalized IR may reference raw evidence, but its
current package and schema are not a stable v0.1.0 third-party API.

### Results

Run and case results keep selection disposition, execution status, assertion
verdict, evidence references, and finding attribution separate. They preserve
the executed denominator and exact built-in definition identities. Unknown,
inconclusive, skipped, errored, cancelled, and budget-exhausted states remain
explicit.

### Reader compatibility

Only artifact kinds and versions listed in
[`schemas/migration-floor.yaml`](../schemas/migration-floor.yaml) receive a
stable read promise. Removing or reinterpreting their fields, weakening
privacy defaults, changing a bound denominator, or making a declared artifact
unreadable is breaking within the supported v0.1.x line.

## Excluded contracts

Registry trust, attestations, disputes, hosted observations, generic driver
frames, authored pack schemas, support matrices, and public normalized-IR APIs
remain experimental. Checked-in schemas for those areas are development
contracts, not stable release promises.

## Security considerations

Canonicalization does not establish semantic validity or signer authority.
Readers still enforce size, depth, count, schema, digest, redaction, and path
limits. Signatures, where present in release artifacts, bind exact bytes but do
not certify endpoint behavior.

## Validation basis

Acceptance is based on the implemented strict decoder, canonicalization and
digest tests, local evidence/run/report readers, explicit result states, and
release review. Migration fixtures define the exact historical floor; no
fictional pre-v0 contract is implied.
