# ADR-0002: Canonical JSON and digest boundaries

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Results, evidence, plans, observations, and attestations need byte-stable
identity across languages and platforms. Ordinary JSON encoders can differ in
object ordering, escaping, and number rendering. Parsers may also accept
duplicate keys or trailing values, which makes the bytes a signer reviewed
different from the object another reader uses.

The proposed envelope and result model are described in
[RFC-0002](../rfcs/0002-evidence-and-result-schema.md). The P00 bootstrap
control plane uses a separately named provisional canonicalization and must not
be silently reinterpreted as this production contract.

## Proposed decision

- Parse immutable public JSON strictly, rejecting duplicate object keys,
  invalid UTF-8, trailing values, non-finite or out-of-contract numbers,
  excessive nesting, and schema-invalid values before hashing or signature
  verification.
- Define a versioned immutable projection for each object kind. The projection
  explicitly lists included fields and explicitly excludes self-digests,
  signatures, convenience locations, and mutable Registry-derived state.
- Encode that projection as RFC 8785 JSON Canonicalization Scheme (JCS) UTF-8
  bytes, then calculate SHA-256 over those bytes.
- Keep public JSON field names `snake_case`. Human-authored YAML resources may
  use `apiVersion` and `kind`, but YAML source bytes are never the public
  identity; schema-resolved data is projected to JSON first.
- Treat field names as case-sensitive. An alternate casing is not an alias
  unless an explicit migration defines it.
- Keep distinct digest domains for immutable object content, manifests,
  artifact bytes, source snapshots, and aggregate control-plane inputs. A
  reference names both the digest algorithm and exact subject type/version.
- Verify an artifact's digest again on import and read. A matching digest does
  not replace schema, authorization, provenance, or rights validation.
- Preserve the P00 bootstrap canonicalization and its historical digests under
  their own version rather than recanonicalizing them in place.

## Consequences

Every supported language needs the same canonical vectors and projection
fixtures. Pretty-printed JSON differs from hashed bytes, so tooling must show
the subject kind, projection version, and digest and support offline
verification. Adding a mutable convenience field need not change object
identity; changing an included field or projection is a public contract change.

JCS narrows representation ambiguity but does not establish semantic validity,
signer authority, or correctness. Those checks remain separate.

## Alternatives

- Encoder-specific sorted JSON is not a cross-language standard and may differ
  on numbers or escaping.
- Hashing author-written YAML preserves comments and spelling but also preserves
  non-semantic formatting and parser ambiguity.
- Canonical CBOR could provide a compact identity format but would add a second
  primary representation to a JSON-oriented ecosystem.
- Including signatures or Registry trust in the content identity creates
  circular or mutable identifiers.

## Validation before acceptance

Use independent JCS vectors and targeted duplicate-key, number, escaping,
Unicode, depth, ordering, casing, and projection-sensitivity mutants in every
supported language. Cross-platform tests must produce identical bytes and
digests, and old bootstrap fixtures must remain verifiable without migration.
Independent schema and security review are still required; implementation
tests do not accept this ADR.
