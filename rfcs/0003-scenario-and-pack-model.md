# RFC-0003: Scenario and Pack Model

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Problem

A community conformance suite becomes unreviewable when tests execute
arbitrary code, requirements are detached from sources, scenario selection
changes silently, or published content is overwritten.

## Candidate design

The repository explores:

- source-locked Requirement Catalog records;
- schema-validated YAML/JSON scenarios;
- deterministic typed compilation;
- a finite operation catalog and bounded no-I/O CEL assertions;
- explicit capability, request, byte, token, process, time, and artifact
  budgets;
- immutable pack, profile, source, evaluator, and denominator digests; and
- independently authored reference and targeted-mutant fixtures.

Arbitrary Python, JavaScript, shell, filesystem, or network code is not a pack
operation. A candidate pack cannot expand the caller's target or permissions.

## Why deferred

The v0.1.0 Doctor Quick Check uses built-in Go descriptors. It does not execute
third-party authored packs through the candidate compiler, and no pack/profile
artifact has been promoted to a stable support tier. Repository catalog counts
therefore do not represent supported executable coverage.

## Compatibility and security

Candidate packs use immutable digest-bound identities, but identity does not
grant support. The authoring schema, CEL environment, compiler IR, OCI layout,
capability model, and external distribution may change before acceptance.
Public-target access is never an implicit pack capability, and secrets are
references rather than authored values.

## Promotion criteria

Acceptance requires a versioned public authoring and execution contract,
deterministic compile goldens, precise negative fixtures, bounded-expression
tests, reference-pass and targeted-mutant-fail coverage, source and rights
review for every normative assertion, migration fixtures, and at least one
release-promoted pack/profile pair.
