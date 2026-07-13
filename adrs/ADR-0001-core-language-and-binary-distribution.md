# ADR-0001: Core language and binary distribution

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

The local Doctor needs deterministic cross-platform schemas, run preparation,
evidence handling, reporting, and a small installation surface. Loading
language-specific SDKs or arbitrary extensions in process would expand the
dependency and crash boundary.

## Decision

- Implement the supported Doctor CLI and its core runtime in Go.
- Pin the Go language and toolchain in `go.mod` and CI.
- Keep business logic independent of CLI parsing and injectable for tests.
- Publish self-contained Doctor binaries for the declared Linux, macOS, and
  Windows architecture matrix.
- Exclude Go plugins, shared objects, and dynamically loaded arbitrary code
  from the supported core.

## Release boundary

This decision covers only the `doctor` binary and libraries used inside that
binary. The reference server, Registry, generic out-of-process driver ABI, and
language-specific driver distribution remain experimental. Their presence in
the repository does not make them supported binaries or public extension APIs.

## Consequences

A single core language simplifies reproducible releases and local operation.
Platform-specific filesystem, process, network, and console behavior still
requires explicit tests. Future client integrations may need separate locked
runtimes, but they require their own accepted contract and support matrix.

## Validation basis

Acceptance is based on the implemented Doctor build and release path, pinned
toolchain, cross-platform release configuration, and release review. It does
not accept the deferred driver or Registry designs.
