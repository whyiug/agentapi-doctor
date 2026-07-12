# Authoring Protocol Packs

A pack is a source-linked, immutable protocol test artifact. No stable pack is
published yet; this guide describes the contribution contract.

## Minimum contents

- pack identity, CalVer, protocol revision, and immutable content digest;
- Requirement Catalog entries with primary source revision and reuse status;
- capability declarations and scenario denominator;
- bounded steps, dependencies, budgets, leases, and finalizers;
- deterministic assertions and evidence requirements;
- reference-pass fixtures and one targeted mutant per normative assertion;
- unknown-field/event and negative cases;
- migration/support implications; and
- author, provenance, license, and review metadata.

## Authoring rules

Pack steps may use only the versioned DSL and approved built-ins. They may not
execute arbitrary Python, JavaScript, shell, network, or filesystem code. CEL
expressions must be typed, budgeted, deterministic, and unable to perform I/O.

An assertion without a cited requirement remains non-normative. A source drift
bot may propose a diff, but a Pack Maintainer classifies the change and an
ambiguity remains explicit until review. Scenario, reference, mutant, and
migration changes travel together.

## Publication

Builds normalize authored input, validate the dependency graph and budgets,
compile a manifest, and compute the immutable digest. A published digest is
never overwritten. Dialect or external adapters cannot convert a core strict
failure into a core pass.

Use [Synthetic fixtures](../getting-started/synthetic-fixtures.md) for fixture
rights and safety and [Profiles and packs](../concepts/profiles-and-packs.md) for
identity boundaries.
