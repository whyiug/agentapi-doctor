# ADR-0005: Driver process and isolation

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Real SDKs and agent clients are necessary for client-observed compatibility,
but their dependencies may read files and environment variables, spawn
processes, access networks, retry, or crash. Loading those dependencies into
the core would expand its trusted computing base and make multi-language and
multi-version support unsafe.

This proposal specializes [RFC-0004](../rfcs/0004-driver-isolation.md) and the
[runner and network boundary](../docs/security-and-privacy/runner-and-network.md).

## Proposed decision

- Run every ecosystem driver out of process. Do not use Go plugins, shared
  objects, or in-process SDK extension points.
- Use JSON-RPC 2.0 semantics over bounded NDJSON stdio for initialization,
  capability negotiation, invocation, ordered observation, result/error,
  cancellation, cleanup, and shutdown.
- Carry invocation and attempt identity on relevant frames and enforce message
  size, total byte, ordering, deadline, and outstanding-request limits.
- Negotiate protocol version, operations, capture modes, runtime/client/package
  identity, and artifact digest before invocation. Negotiation cannot broaden
  the parent plan or permissions.
- Give a driver an isolated working directory and temporary home, an allowlisted
  environment, task-scoped secret delivery, bounded resources and process tree,
  explicit target-only or no-network policy, and no undeclared helper or path
  access.
- Keep stdout protocol-only. Bound and sanitize diagnostics before persistence.
- Separate RPC/codec, driver lifecycle, client parser, network/wire,
  provider/model, cancellation, budget, and harness errors. A broken driver is
  never a provider compatibility FAIL.
- Stop and clean only task-owned processes and resources.

## Consequences

The process boundary contains dependency crashes and permits independent
runtime locks, but it adds lifecycle, cancellation, framing, and platform
sandbox complexity. Sandbox strength differs by operating system and must be
reported rather than overstated. Large evidence needs a bounded data-frame
path without granting drivers CAS authority.

## Alternatives

- In-process SDKs are simpler to call but cannot safely isolate versions,
  crashes, environment access, or dependency state.
- A container-only contract offers strong packaging on some hosts but is not a
  universal local interface; it can implement the same process protocol.
- An HTTP driver daemon adds listener authentication and lifecycle exposure
  without improving the local stdio trust boundary.
- Letting drivers write CAS objects allows them to claim evidence that the core
  did not sanitize or receive.

## Validation before acceptance

Test valid lifecycle plus unsupported capability, duplicate/unknown IDs,
malformed/trailing/oversized JSON, ordering violations, cancellation, deadline,
hidden retry, child cleanup, forbidden environment/path/network access, and
secret canaries on all supported platforms. Support claims additionally need
the exact named client and runtime lock. Candidate contract tests do not record
acceptance or client support.
