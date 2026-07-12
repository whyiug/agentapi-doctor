# RFC-0004: Driver Process and Isolation

- **Status:** draft
- **Review:** none recorded
- **Target phase:** P01/P04 contract input

## Problem

Real SDKs and agent clients are required to prove client-observed behavior, but
their dependencies can read environment/files, spawn processes, access the
network, retry unexpectedly, and conflate client errors with provider failures.
In-process plugins expand the trusted computing base and make multi-language
version isolation difficult.

## Proposal

### Process boundary

Drivers run out of process. The proposed RPC uses JSON-RPC 2.0 semantics over
bounded NDJSON stdio with initialization, capability negotiation, invocation,
ordered observations, result/error, cancellation, cleanup, and shutdown. Every
message carries the appropriate invocation/attempt identity and obeys size and
sequence limits.

Go in-process plugins/shared objects are excluded. Python and Node drivers use
locked environments or immutable images and expose the same contract.

### Error taxonomy

RPC/codec, driver lifecycle, client validation/parser, network/wire,
provider/model, cancellation/timeout, and harness errors remain distinct.
Malformed or out-of-order driver output is a driver/harness failure, not a
protocol verdict.

### Capabilities and identity

Initialization returns protocol version, supported operations, capture modes,
client/package/runtime identity, and artifact digest. A support manifest pins
all versions and cells. Negotiation cannot expand the parent's authorized
scenario or permissions.

### Isolation

Each process receives an isolated work directory and temporary home, allowlisted
environment, scoped late-bound secret material, bounded process tree and
resources, explicit target-only/no-network policy, and no undeclared path or
helper access. Fixture services bind loopback. Tool side effects default to
none. Cancellation and finalizers stop only task-owned resources.

## Secret handling

Configuration contains secret references, not values. The parent resolves only
the required reference as late as possible and transmits it through an
approved channel without logging. Driver stdout is protocol-only; diagnostic
stderr is bounded and sanitized before persistence.

## Testing

Contract tests include valid lifecycle, unsupported capability, duplicate and
unknown IDs, malformed/trailing/oversized JSON, invalid sequence, cancellation,
deadline, retry observation, child-process cleanup, forbidden env/path/network,
and secret canaries. Support claims additionally run the real named client.

## Alternatives considered

- **In-process SDKs/plugins:** simpler calls but dependency and crash isolation
  are unacceptable; rejected.
- **Container-only API:** useful for distribution but not portable enough as
  the sole local contract; process RPC remains fundamental.
- **HTTP driver daemon:** adds ports/auth/lifecycle exposure; NDJSON stdio is
  preferred for the first version.

## Unresolved questions

- platform-specific sandbox strength and required fallbacks;
- transport for very large evidence while keeping stdout bounded;
- secret delivery on Windows; and
- version-negotiation compatibility window.

No driver ABI or client support claim is approved by this draft.
