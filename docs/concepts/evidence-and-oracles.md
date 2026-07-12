# Evidence and Oracles

Evidence explains a verdict; it does not merely decorate one.

## Raw and normalized views

The capture-layer view preserves what the authorized test actually observed:
bytes, framing, event order, offsets, and transport metadata. A normalized
internal representation makes cross-protocol reasoning possible while keeping
references to the raw source, provider-native type, normalization transform,
and any known loss.

A normalizer must never silently repair invalid behavior. If data is
unavailable, the evidence record states why rather than manufacturing an empty
success.

## Evidence identity

Evidence and result objects bind to their source commit, producer artifact,
immutable inputs, and content digest. Instance IDs do not replace content
digests. Registry-derived fields such as freshness or dispute status remain
outside the submitted immutable observation projection.

## Oracle classes

- deterministic structural and state-machine assertions;
- source-linked protocol requirements;
- metamorphic relations such as stream/non-stream equivalence;
- differential checks against a controlled reference and targeted mutants;
- statistical assertions with explicit samples and intervals; and
- human or external review where a machine cannot establish the fact.

An LLM or scanner may suggest a hypothesis, but it is not a normative protocol
oracle. Every normative assertion needs a Requirement Catalog source, a
reference-pass case, and a targeted-mutant-fail case.

## Failure evidence

A useful failure has a stable failure ID, the assertion and requirement IDs,
minimal evidence references, an explicit fault family/domain with calibrated
confidence, alternatives when ambiguous, and an executable next step. Secrets
and private payloads are redacted before persistence; see
[Redaction](../security-and-privacy/redaction.md).
