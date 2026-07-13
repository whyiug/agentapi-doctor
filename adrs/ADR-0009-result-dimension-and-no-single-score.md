# ADR-0009: Result states and no single score

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Collapsing observations into one compatibility score hides denominators,
unknowns, execution failures, and fault domains. It can also turn a harness
failure or missing check into a misleading endpoint verdict.

## Decision

- Keep selection disposition, execution status, assertion verdict, and finding
  attribution as distinct fields.
- Represent unknown, inconclusive, unsupported, not run, skipped, errored,
  cancelled, and budget-exhausted states explicitly.
- Preserve candidate, applicable, selected, executed, and verdict
  denominators, bound to the exact built-in definition identities.
- Never turn missing evidence, driver failure, or harness failure into PASS or
  protocol FAIL.
- Do not publish a normative universal score, official compatibility rank,
  default winner ordering, or certification badge.
- Keep any future derived visualization transparent and non-normative.

## Release boundary

The v0.1.0 Quick Check reports the implemented protocol dimension and its
separate result states. Transport, model-behavior, generic client,
operational-reliability, Matrix UI, and multi-dimensional support claims remain
deferred until they have executable denominators and promoted contracts.

## Consequences

Users must inspect the observation and its denominator instead of relying on a
marketing number. In return, unavailable checks cannot inflate compatibility,
and failures remain attributable to the layer where they were observed.

## Validation basis

Acceptance is based on the Doctor result/report model, explicit inconclusive
and execution states, denominator-aware comparison, and release review. It
does not accept a five-dimension UI or Registry ranking model.
