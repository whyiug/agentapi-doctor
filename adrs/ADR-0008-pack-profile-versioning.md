# ADR-0008: Pack/Profile versioning

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

An observation is interpretable only against the exact scenarios,
requirements, capability rules, and denominators that produced it. A mutable
`latest` pack or an unversioned profile could silently turn a previous result
into a different claim. Pack cadence follows upstream protocol revisions,
whereas profiles describe consumer expectations and capability/denominator
selection; they need separate version axes.

The artifact model is proposed in
[RFC-0003](../rfcs/0003-scenario-and-pack-model.md) and explained in
[profiles and packs](../docs/concepts/profiles-and-packs.md).

## Proposed decision

- Version packs with CalVer `YYYY.MM.patch`, keep an independent explicit
  `protocolRevision`, and bind every published pack to an immutable artifact
  digest. A published digest is never overwritten.
- Version profiles with SemVer and bind them to an immutable artifact digest.
  A capability or denominator change is at least a minor profile change; a
  removal, reinterpretation, or incompatible default is breaking.
- Give each scenario its own versioned identity. Every normative assertion
  references a source revision and Requirement Catalog record.
- Bind results to exact pack, profile, source-lock, scenario denominator,
  driver/support-lock, core, and evaluator digests. A tag or friendly name is a
  pointer, never sufficient identity.
- Treat normative, additive, breaking, clarification, metadata-only, and
  source-only changes explicitly. Any change that can alter selection,
  expected behavior, evidence, or verdict publishes a new artifact.
- Compare trends only when the relevant denominator digest is identical.
  Otherwise present results side by side with the incompatibility explained.
- Retain old artifacts and readers according to the declared migration floor;
  do not invent a prior stable major that was never published. See
  [migration guidance](../docs/migration/README.md).
- Promotion from candidate to a supported artifact requires the applicable
  independent review and acceptance evidence; versioning alone grants no
  support tier.

## Consequences

Users see longer identities and registries retain more immutable artifacts,
but a historical result stays reproducible and its denominator cannot drift.
CalVer communicates pack publication cadence while `protocolRevision` records
the upstream semantic snapshot; neither substitutes for the digest.

Profile authors must classify changes carefully and supply old-reader and
denominator compatibility fixtures. Mutable aliases remain useful for discovery
but cannot appear alone in evidence.

## Alternatives

- SemVer for packs hides time-based upstream snapshots and still needs a
  separate protocol revision.
- CalVer for profiles obscures consumer-facing compatibility semantics.
- One version shared by pack and profile couples independent artifacts and
  forces unrelated releases.
- Mutable `latest` content makes evidence and comparisons non-reproducible.
- Encoding protocol revisions in build metadata makes behavior changes appear
  equivalent under SemVer precedence.

## Validation before acceptance

Test immutable publication, digest verification, source and denominator
sensitivity, tag retargeting, old-reader behavior, migration-floor fixtures,
and change-classification examples. Reference and mutant results must remain
bound to the original artifacts after newer versions appear. A real pack and
profile maintainer review is required; candidate catalogs do not accept this
policy.
