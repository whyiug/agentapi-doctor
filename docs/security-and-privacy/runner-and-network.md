# Runner and Network Isolation

## Local runner

A local user may authorize one exact local, private-network, or remote endpoint
origin. Authorization is explicit and narrow: it does not extend to redirect
targets, other addresses in the same range, metadata services, adjacent hosts,
helper subprocesses, or tool side effects.

Each run needs:

- an isolated working directory and temporary `HOME`;
- an allowlisted environment with secret references resolved only for the
  intended driver;
- bounded child processes, descriptors, memory, time, requests, bytes, and
  artifacts;
- target-only or no-network policy;
- no redirects, plus exact-origin DNS/address checks; and
- a finalizer that terminates only task-owned processes and cleans task-owned
  resources.

Every runner mode rejects invalid, unspecified, multicast, and link-local
addresses before dialing. It also always rejects the metadata-service
destinations `169.254.169.254`, `100.100.100.200`, and `fd00:ec2::254`, whether
they appear as URL literals or DNS answers. Local-target mode does not override
this hard deny. Public-runner mode additionally rejects loopback, private, and
other special-use address space.

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
