# ADR-0001: Core language and binary distribution

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

The core needs deterministic cross-platform schemas, planning, evidence,
budgets, replay, a local CLI, and a future Registry. It must be distributable
on Linux, macOS, and Windows on `amd64` and `arm64`, while client drivers may
need native Python, Node, or other ecosystem-specific runtimes. In-process
language plugins would expand both the dependency graph and the trusted crash
boundary.

This proposal follows the default in
[Plan section 32](../agentapi-doctor-Plan.md) and the driver boundary in
[RFC-0004](../rfcs/0004-driver-isolation.md). Neither document records an
accepted implementation decision.

## Proposed decision

- Implement the core CLI, engine, schemas, recorder, redactor, local CAS, and
  Registry service in Go.
- Pin the selected Go language and toolchain in `go.mod` and CI after checking
  a stable release. Do not use a floating `latest` toolchain.
- Keep the Make entrypoint thin: it invokes versioned Go commands or checked-in
  scripts so local and CI behavior can be compared.
- Keep business logic independent of CLI parsing and injectable for tests.
- Build self-contained binaries for the declared OS and architecture matrix.
- Run ecosystem-specific SDK and client drivers out of process in locked
  environments or immutable images.
- Exclude Go in-process plugins, shared objects, and dynamically loaded
  arbitrary extension code from the core contract.

## Consequences

One core language simplifies the release train, deterministic builds, and
bounded concurrency. It does not eliminate platform-specific filesystem,
process, network, console, or sandbox behavior, so those remain explicit test
dimensions.

Polyglot drivers preserve real-client behavior but add lockfiles, images,
runtime support matrices, and supply-chain review. Release provenance and SBOMs
must cover those artifacts, not only the Go binary.

## Alternatives

- A Python core improves proximity to Python SDKs but complicates
  self-contained cross-platform distribution and dependency isolation.
- A Node core helps JavaScript clients but does not solve other client
  ecosystems or native distribution.
- A polyglot in-process core offers flexibility at the cost of a larger trusted
  dependency, ABI, and crash surface.
- A service-only core avoids local binaries but violates local-first and
  offline operation.

## Validation before acceptance

Run cross-platform package and clean-install tests, race and static analysis,
binary size and startup measurements, offline/proxy behavior, and process
isolation experiments. Reproducible release and provenance checks must cover
every shipped runtime. Candidate code and passing local tests are inputs to
review, not acceptance evidence.
