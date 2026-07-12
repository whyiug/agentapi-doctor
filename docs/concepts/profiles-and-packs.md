# Profiles, Packs, and Drivers

These objects answer different questions and must not be merged into one
“compatibility mode.”

## Protocol Pack

A Protocol Pack is an immutable, source-linked set of scenarios and assertions
for a named protocol revision. Its identity includes its content digest and
version. Publishing a new pack creates a new digest; an old digest is never
overwritten.

## Client or Consumer Profile

A Profile describes the expectations and denominator observed by a named SDK,
agent, or consumer integration. It may select protocol-pack capabilities but
does not redefine the protocol. A change to capability expectations or the
denominator requires at least a profile minor version.

## Driver

A Driver executes a version-pinned client or transport implementation behind a
bounded RPC contract. It reports observations and errors without deciding the
normative verdict. Driver identity includes ecosystem, package, version,
artifact digest, runtime, and negotiated capabilities.

## Support manifest

The support manifest locks the exact pack, profile, driver, SDK, runtime, and
matrix cells tested. “Latest” is not a reproducible identity. Tier 1 release
gates cover locked previous/current cells; candidate versions remain explicit
and cannot silently change the stable denominator.

No stable pack, profile, driver, or support manifest is published by the
project yet.
