# ADR-0005: Driver process and isolation

- **Status:** deferred
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Real SDKs and agent clients may read files and environment variables, spawn
processes, access networks, retry, or crash. A generic client-driver ecosystem
would therefore need a narrow process protocol and explicit isolation.

## Candidate direction

The repository explores JSON-RPC 2.0 semantics over bounded NDJSON stdio,
capability negotiation, ordered observations, cancellation, cleanup, resource
limits, temporary homes, allowlisted environments, task-scoped secrets, and
separate driver/client/provider/harness errors.

Drivers would run out of process. They would not write trusted CAS objects or
expand the caller's target, operation, or network authorization.

## Why deferred

`pkg/driverprotocol` is a tested development library, not a production Doctor
orchestration path. The pinned OpenAI Python reproduction case uses a dedicated
helper and does not establish a generic Driver ABI or support claim.

## Promotion criteria

Acceptance requires an integrated runner; locked real-client artifacts;
cross-platform lifecycle, cancellation, and cleanup tests; malformed and
oversized protocol mutants; secret canaries; network/path isolation evidence;
and an explicit ABI compatibility window. Candidate contract tests alone do
not promote a client or driver.
