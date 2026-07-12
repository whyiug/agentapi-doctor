# RFC-0002: Evidence and Result Schema

- **Status:** provisional
- **Review:** none recorded
- **Target phase:** P01 contract input

## Problem

Evidence loses value when object identity can be rebound, normalized values
hide raw input, registry metadata changes submitted facts, or result fields mix
planning, execution, verdict, and attribution. A cross-platform system also
needs byte-stable digests and readers that tolerate allowed additive fields.

## Goals

- content-address immutable public objects;
- preserve raw-to-normalized traceability and known loss;
- bind results to exact plans, producers, sources, and evaluators;
- distinguish instance identity from content identity;
- support additive evolution and explicit migration; and
- make denominators and uncertainty machine-readable.

## Proposed envelope

Immutable public objects use a versioned envelope containing `schema_version`,
`kind`, optional instance ID, `content_digest`, a matching object reference,
producer identity/digest, creation time, and namespaced extensions. Public JSON
uses `snake_case`; authored resource YAML may use Kubernetes-style
`apiVersion`/`kind`. The P00 bootstrap format remains separately versioned.

Content digests use SHA-256 over an explicit immutable projection encoded with
RFC 8785 JSON Canonicalization Scheme. Duplicate keys, invalid UTF-8,
non-finite/ambiguous numbers, trailing values, and unbounded nesting are
rejected before signing or hashing.

## Evidence model

An evidence event identifies run, invocation, attempt, monotonic sequence,
capture layer, instrumentation mode, direction, byte/event offset, payload
reference/digest, redaction records, and relations. A missing payload has a
machine reason; it is not an empty object.

Normalized IR retains source protocol/type, provider-native JSON type,
interaction/item/call links, raw evidence refs, normalization transform and
version, loss markers, and unavailable fields. A transform cannot silently
repair invalid input.

## Result model

- Attempt records execution and resource consumption.
- Assertion results bind requirement, oracle/evaluator digest, expected and
  observed values, evidence, determinism/statistics, verdict, and reason.
- Findings add fault domain/family, calibrated confidence, alternatives,
  fingerprint, remediation, and repro references.
- Case results keep plan disposition, execution, verdict, assertions, and
  findings separate.
- Profile results publish candidate/applicable/executed denominator digests and
  counts plus independent dimensions.

Registry-derived trust, freshness, disputes, supersede, and tombstone fields
are excluded from the submitted observation identity. Provenance references
are verified separately and do not rewrite the observation's immutable facts.

## Compatibility

Unknown optional fields are preserved or safely ignored according to the
schema contract. Removing/reinterpreting fields, reducing privacy defaults,
changing denominators, or making old artifacts unreadable is breaking. P01
creates an explicit pre-1.0 migration floor; no fictional previous major is
invented.

## Security considerations

Canonicalization does not establish semantic validity. Decoders still enforce
size/depth/count limits, exact duplicate-key rejection, digest verification,
extension namespace policy, and write-before-redact. Signatures bind exact
subjects and authorized identities but are not correctness votes.

## Alternatives considered

- **Hash ordinary encoder output:** language/order dependent and ambiguous;
  rejected.
- **Store only normalized data:** prevents byte-level diagnosis and hides
  transformation loss; rejected.
- **Put mutable Registry status in observation ID:** changes fact identity when
  administration changes; rejected.

## Unresolved questions

- final object list and immutable projection for each schema;
- precision rules for statistical estimates and timestamps; and
- extension preservation requirements across every reader language.

## Acceptance evidence

Cross-platform canonical vectors, digest sensitivity tests, duplicate-key and
number mutants, additive-old-reader fixtures, migration fixtures, privacy
review, and independent schema review are required. They are not supplied by
this draft alone.
