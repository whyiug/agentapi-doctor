# Runner and Network Isolation

## Local runner

A local user may authorize a loopback fixture or a specific endpoint origin.
Authorization is explicit and narrow: it does not extend to redirect targets,
private address ranges, metadata services, adjacent hosts, helper subprocesses,
or tool side effects.

Each run needs:

- an isolated working directory and temporary `HOME`;
- an allowlisted environment with secret references resolved only for the
  intended driver;
- bounded child processes, descriptors, memory, time, requests, bytes, and
  artifacts;
- target-only or no-network policy;
- same-origin redirect validation and DNS/address checks; and
- a finalizer that terminates only task-owned processes and cleans task-owned
  resources.

## Driver boundary

Drivers communicate over a versioned framed protocol. They do not receive the
entire parent environment or arbitrary filesystem access by default. Capability
negotiation precedes invocation; malformed, out-of-order, oversized, or unknown
messages fail with a driver/protocol error rather than a provider verdict.

## Project-operated runner

A future public runner has a different threat model from a user's local
machine. It requires target ownership/allowlisting, isolated workers, default
deny egress, DNS rebinding defenses, short-lived credentials, quotas, audit,
artifact quarantine, and emergency disable controls. It must not accept an
arbitrary URL simply because the URL is syntactically valid.

No project-operated public runner exists today.
