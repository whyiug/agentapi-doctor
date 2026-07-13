# ADR-0004: Scenario DSL and CEL sandbox

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

A community scenario format could make compatibility checks reviewable and
source-linked, but arbitrary code inside a pack would make permissions,
budgets, evidence, and repeatability difficult to enforce.

## Candidate direction

The repository explores schema-validated YAML/JSON, deterministic typed
compilation, a finite operation catalog, and CEL-Go expressions with a closed
typed environment and no ambient I/O. Assertions would bind to exact source,
evaluator, schema, pack, and built-in digests.

## Why deferred

The v0.1.0 Quick Check executes built-in Go descriptors; it does not execute
authored scenario packs through the candidate DSL/compiler. Candidate pack and
CEL code therefore does not establish a stable authoring format, sandbox, or
third-party execution contract.

## Promotion criteria

Acceptance requires a versioned public contract, deterministic compile
fixtures, precise schema/type/cost failures, capability and budget mutants,
reference-pass and targeted-mutant-fail coverage, source review for every
normative assertion, and a declared migration floor. Until then, authoring
documentation and pack artifacts remain experimental.
