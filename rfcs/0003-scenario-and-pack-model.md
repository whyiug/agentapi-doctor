# RFC-0003: Scenario and Pack Model

- **Status:** provisional
- **Review:** none recorded
- **Target phase:** P01/P03 contract input

## Problem

A conformance suite becomes unreviewable when tests execute arbitrary code,
requirements are detached from sources, scenario selection changes silently,
or published content is overwritten. Packs need a bounded authoring model that
compiles to an exact plan and preserves their denominator.

## Proposal

### Source-linked requirements

Each normative assertion references a Requirement Catalog record with source
type, original/resolved URL, retrieval time, revision, content digest,
license/reuse status, summarized requirement, and revalidation trigger.
Ambiguity is a first-class record and blocks a normative interpretation until
review.

### Bounded Scenario DSL

Authored YAML/JSON may declare:

- capability prerequisites and dependencies;
- request/stream/client operations from an approved step catalog;
- deterministic CEL assertions using typed, budgeted, no-I/O built-ins;
- expected evidence classes and failure IDs;
- hard request/byte/token/process/time/artifact budgets;
- leases and finalizers with separate cleanup budget; and
- reference, mutant, negative, and historical fixtures.

Packs cannot execute arbitrary Python, JavaScript, shell, filesystem, or
network code. Those behaviors belong behind reviewed drivers or harness
capabilities with explicit permissions.

### Compilation

The compiler validates schemas and requirement links, resolves dependencies and
capabilities, freezes candidate/applicable denominators, selects immutable
artifact digests, checks budgets/finalizers, and emits an IntentPlan and then a
ResolvedRunPlan. Resolution may remove unauthorized/unavailable branches but
cannot add a scenario not authorized by intent.

### Identity and evolution

Packs use CalVer plus independent `protocolRevision` and immutable OCI digest.
Profiles and drivers are separate artifacts. A published digest is never
modified; normative/additive/breaking source change creates a new pack.
Registry observations retain the original pack digest.

## Contribution gate

Every normative assertion has a primary source and explanation, a conforming
reference fixture, at least one minimal targeted mutant, precise evidence
pointers, deterministic behavior, and migration/support impact. Historical
bugs additionally record public provenance and affected/fixed versions.

## Security considerations

The compiler rejects unbounded loops, dynamic I/O, unknown capabilities,
unsafe paths, missing cleanup, and budget expansion. Fixture provenance and
licenses are reviewed. Secrets are references, never authored literal values.
Public-target access is not a pack capability.

## Alternatives considered

- **General-purpose scripting:** flexible but destroys deterministic sandbox
  and review boundaries; rejected.
- **Hard-code every scenario in Go:** safe but prevents reviewed ecosystem
  contribution and immutable distribution; rejected.
- **Mutable “latest” pack:** convenient but breaks evidence replay; rejected.

## Unresolved questions

- final DSL and CEL type system;
- capability promotion and denominator-change review;
- OCI media types and offline bundle closure; and
- source snapshot handling for specifications with restrictive reuse terms.

## Acceptance evidence

Positive/negative/additive fixtures, precise path errors, compiler determinism,
reference/mutant coverage, budget and sandbox mutants, source-drift workflow,
and independent protocol review are required before acceptance.
