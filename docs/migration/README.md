# Migration and Compatibility

AgentAPI Doctor has no published stable schema or CLI release yet. Development
objects are not retroactively described as stable merely to populate a
migration matrix.

## Version surfaces

Migration is tracked independently for CLI/Core, config, Result/Observation
schemas, Protocol Packs, Profiles, Driver RPC, Registry API, and Requirement
Catalog sources. A change to one surface does not silently change another.

## Pre-1.0 floor

Before the first stable release, `schemas/migration-floor.yaml` must enumerate
each pre-1.0 object the project explicitly promises to read or migrate, with
schema ID, version, content digest, fixture, and target migration. If no 0.x
artifact received such a public promise, the list is empty. Arbitrary
development files do not become a fictional previous major.

## Migration contract

A breaking change requires:

1. an approved RFC and compatibility classification;
2. old/new positive, negative, and additive-unknown fixtures;
3. an offline reader or migration tool with deterministic output;
4. preserved immutable source artifacts;
5. upgrade, downgrade where supported, rollback, and old-report tests;
6. machine-readable warnings and user-facing notes; and
7. generated schema/reference updates in the same change.

Published pack digests and tags are never rewritten. A new pack or schema gets
a new identity, and Registry observations continue to display the identity
under which they were produced.

Stable deprecation policy is defined in [RELEASE.md](../../RELEASE.md). Exact
commands will be added only after a public CLI contract exists.
