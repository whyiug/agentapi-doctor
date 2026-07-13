# RFC-0004: Driver Process and Isolation

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Problem

Real SDKs and agent clients may read the environment and filesystem, spawn
processes, access networks, retry, or crash. In-process plugins would expand
Doctor's trusted computing base and make multi-language version isolation
difficult.

## Candidate design

The repository explores an out-of-process protocol with JSON-RPC 2.0 semantics
over bounded NDJSON stdio. The candidate contract includes capability
negotiation, ordered observations, result/error separation, cancellation,
cleanup, deadlines, message limits, and explicit invocation identity.

A generic driver would receive a temporary home and work directory,
allowlisted environment, task-scoped late-bound secret, bounded process tree,
and target-only or no-network policy. Driver, client, wire, provider, timeout,
and harness errors would remain distinct. Driver output could not create a
trusted evidence reference without core sanitization and commit.

## Why deferred

The protocol package has contract tests but is not integrated as the Doctor
execution path. The pinned OpenAI Python reproduction uses a dedicated helper
and proves only that exact case. No generic Driver ABI, plugin ecosystem, or
client support matrix is part of v0.1.0.

## Compatibility and security

The wire shape, version negotiation, large-evidence transport, secret channel,
and platform sandbox rules may change before acceptance. Consumers must not
ship integrations that assume the candidate package is stable.

## Promotion criteria

Acceptance requires an integrated runner, an exact ABI compatibility window,
locked client/runtime artifacts, cross-platform lifecycle and cleanup tests,
malformed and oversized frame mutants, secret canaries, network/path isolation
evidence, and a release-promoted client support cell.
