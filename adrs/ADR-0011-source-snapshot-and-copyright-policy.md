# ADR-0011: Source snapshot and copyright policy

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Normative assertions need an exact source revision, but specifications, SDK
tests, issue reports, user logs, and examples have different licenses and
reuse permissions. Public visibility alone does not grant copying rights.

## Decision

- Record external facts in source locks with source type, resolved location,
  retrieval time, revision, digest, reuse status, affected requirement, and
  revalidation trigger.
- Keep a concise independently written requirement summary and only the
  minimum quotation necessary for review.
- Preserve source bytes only when license, terms, and repository policy permit
  it, with the required notices and a digest-bound scope.
- Independently implement synthetic fixtures. Do not copy upstream tests,
  issue text, user logs, payloads, or examples with uncertain rights.
- Treat unknown or incompatible reuse status as a distribution block.
- Record source drift as a new lock revision; never silently change a
  normative assertion, denominator, or verdict.
- Keep DCO contribution rights distinct from rights to traces, model output,
  identities, or other third-party material.

## Release boundary

This decision governs repository sources, fixtures, and contributions. It does
not authorize hosted uploads, a public observation dataset, or a public-data
license. Those require separate effective policy and legal review.

## Consequences

Some sources cannot be vendored for offline use, and maintainers may need to
reacquire them. Independent summaries and fixtures take more work but preserve
reviewability without importing uncertain rights.

## Validation basis

Acceptance is based on the source-lock schema, checked-in provenance records,
independently authored synthetic fixtures, contribution policy, DCO, and
release review. Candidate protocol interpretations still require source review
before promotion.
