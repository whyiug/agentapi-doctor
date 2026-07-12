# ADR-0011: Source snapshot and copyright policy

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Normative assertions must be traceable to an exact source revision, but
protocol specifications, SDK tests, issue reports, user logs, and examples have
different licenses and reuse permissions. Copying an upstream test or whole
specification can create a copyright or confidentiality problem; keeping only a
live URL makes later review and drift detection unreliable.

The Requirement Catalog model is proposed in
[RFC-0003](../rfcs/0003-scenario-and-pack-model.md). Contribution rights and
independent fixture expectations are documented in
[CONTRIBUTING.md](../CONTRIBUTING.md), while repository code and notice terms
remain in [LICENSE](../LICENSE) and [NOTICE](../NOTICE).

## Proposed decision

- Record each external fact in a source lock with source type, original and
  resolved URL, retrieval time, exact revision/tag/API date, content digest,
  license and reuse status, affected Requirement/RFC/ADR, and
  revalidation trigger. The current machine-readable shape is
  [source-lock.schema.json](../schemas/pack/source-lock.schema.json).
- Store only a concise original requirement summary and the minimum quotation
  necessary for review. Link to the primary source; do not mirror an entire
  copyrighted specification merely for convenience.
- Preserve a byte snapshot only when license, terms, and repository policy
  clearly permit it. Bind the snapshot digest, retain required notices and
  attribution, and state its allowed scope. Otherwise retain metadata and an
  independently written summary, not restricted bytes.
- Independently implement synthetic fixtures from the documented behavior. Do
  not copy upstream SDK tests, issue text, user logs, payloads, or examples with
  uncertain rights. A historical public bug may motivate a new minimal fixture
  but the fixture records provenance and is not represented as upstream code.
- Treat unknown or incompatible reuse status as a block on distributing the
  source-derived artifact, not as permission inferred from public visibility.
- On source drift, add a new lock revision and a human-readable diff. Do not
  automatically change a normative assertion, denominator, or verdict.
- Keep DCO contribution rights distinct from future Registry upload rights.
  A commit sign-off does not license private traces, model output, identities,
  or public-observation facts on someone else's behalf.
- Preserve provenance for generated and transformed artifacts, including the
  transform/tool version and source inputs. Scanner or LLM assistance is not a
  substitute for source and rights review.

## Consequences

Some source material cannot be vendored for offline review, and maintainers may
need to reacquire it from the authoritative publisher. Short summaries and
independent fixtures take more work but reduce copying risk and make assertions
reviewable on their own merits.

Source locks become durable contract inputs. Updating a URL, revision, digest,
or reuse determination can invalidate affected candidate assertions and needs
the applicable review rather than a silent metadata edit.

## Alternatives

- Mirror every source for reproducibility: maximizes availability but ignores
  license, terms, and takedown obligations.
- Store URLs only: loses exact revision, digest, redirect, and reuse context.
- Copy upstream tests as fixtures: may import incompatible licenses and hidden
  assumptions and does not prove independent understanding.
- Treat all public facts as CC0: facts, expressive text, raw artifacts,
  signatures, and personal data have different rights and policy boundaries.

## Validation before acceptance

Audit every candidate Requirement and fixture back to a source-lock record;
test source-drift and missing-license failures; verify permitted snapshots and
required notices; and review independently implemented fixtures for accidental
substantial copying. A qualified legal review is required before hosted
publication or any public data-license claim. Repository presence and automated
license scans are not acceptance.
