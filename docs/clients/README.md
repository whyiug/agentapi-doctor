# Clients and Drivers

Client compatibility is version-specific. A result names the exact SDK or
agent, version, runtime, driver artifact digest, profile digest, protocol pack,
and support-lock matrix cell.

The planned Tier 1 matrix includes raw transport plus selected Python/Node SDK
and real agent/client profiles. A mock that resembles a client does not prove
that the real client works. Candidate dependency versions may run in nightly
jobs but do not silently replace release-gated previous/current cells.

Before claiming support, each driver/profile needs:

- capability negotiation and contract tests;
- a real client process with bounded environment and network access;
- capture-layer/client-observation correlation;
- version-locked fixtures and expected errors;
- Linux/macOS/Windows coverage appropriate to the tier; and
- a support manifest with explicit gaps and denominator.

No stable client support matrix is published today.
