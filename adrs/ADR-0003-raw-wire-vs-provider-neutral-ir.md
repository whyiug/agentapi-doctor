# ADR-0003: Raw wire vs provider-neutral IR

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Raw protocol observations are needed to diagnose framing, ordering,
provider-native types, cancellation, and client parser failures. A
provider-neutral internal representation is needed for reusable oracles and
cross-protocol reports. Keeping only one view either makes every oracle
protocol-specific or destroys source fidelity.

The four observation planes and fault domains are proposed in
[RFC-0001](../rfcs/0001-compatibility-layers.md); the linked evidence fields are
proposed in [RFC-0002](../rfcs/0002-evidence-and-result-schema.md).

## Proposed decision

Maintain separate, digest-linked views:

- capture-layer evidence records bounded observed bytes or events, offsets,
  direction, layer, instrumentation, digest, redaction records, and explicit
  unavailable reasons;
- provider-neutral IR records provider-native type and value, normalized value,
  interaction/item/call relations, source evidence references, transform ID
  and version, loss markers, and unavailable fields; and
- client observations record what the named SDK or agent accepted, rejected,
  retried, reordered, or surfaced without overwriting either earlier view.

Normalization is a typed, versioned transformation, never a repair. Unknown or
lossy input stays unknown or lossy. An assertion over IR points to the capture
evidence and transform that justify it. Wire, normalization, client, provider,
and harness failures remain distinguishable.

Only sanitized capture-layer content may enter a persistent evidence view; the
write boundary is governed by
[ADR-0006](ADR-0006-secret-references-and-write-before-redact-prohibition.md).

## Consequences

Evidence and reports carry more identifiers and relations, and transforms need
versioning and recomputation support. In return, maintainers can determine
whether an error arose at the wire, normalizer, client, provider, or harness
boundary. A transform change can create a derived evaluation but cannot rewrite
the original observation.

## Alternatives

- Raw-only evidence preserves fidelity but makes reusable semantic oracles and
  comparisons impractical.
- IR-only evidence hides framing, native types, ordering failures, and
  transformation loss.
- Repairing adapters can make reports look consistent but create false
  conformance and destroy fault attribution.
- Treating the client view as ground truth conflates client bugs with provider
  behavior.

## Validation before acceptance

Exercise correlated capture, IR, and client fixtures; unknown and unavailable
cases; native JSON type preservation; lossy-transform mutants; rechunking;
client parser divergence; and secret canaries. Every claimed assertion needs a
reference-pass and targeted-mutant-fail path with precise evidence links.
Passing candidate fixtures do not constitute design acceptance.
