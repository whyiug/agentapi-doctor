# ADR-0010: Registry trust and attestation

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

A future public Registry could mislead users if self-reports, owner statements,
independent reproductions, project runs, stale results, and disputes appear
equivalent. A signature proves control of a signing identity over bytes; it
does not prove correctness, ownership, independence, or authorization. Upload
also creates secret, SSRF, privacy, rights, abuse, and recovery boundaries.

The broader proposal is [RFC-0005](../rfcs/0005-registry-trust.md), with user
semantics in [trust and attestations](../docs/registry/trust-and-attestations.md).
No hosted Registry or issued project trust label exists.

## Proposed decision

- Keep immutable submitted observations separate from mutable Registry-derived
  trust, freshness, dispute, supersession, tombstone, and withdrawal records.
  Derived records never change the observation identity.
- Use provenance labels Local, Self-reported, Owner-verified, Independently
  reproduced, and Project-operated-run. They describe evidence path, not a
  quality rank, certification, or increasing numeric score.
- Bind an attestation to the exact observation, subject, pack/profile/config,
  support lock, runner, producer, source, and artifact digests. Verify signer
  authorization, subject bytes, freshness/replay policy, and identity scope.
- Require an ownership challenge before an owner label. Independence requires
  distinct authorized identities and runner instances under a published
  equivalence policy; forwarding a signature or rerunning the same observation
  does not create independence.
- Ingest through bounded private quarantine: authenticate and authorize,
  verify schema/digests/signatures/provenance/rights/secret policy,
  deterministically reevaluate, preview the exact public projection and terms,
  obtain affirmative consent, then append immutable facts and audit records.
- Never let a submitter self-award Registry-derived labels. Disputes and appeals
  require role separation and visible, auditable outcomes.
- Keep local CLI operation independent of hosted availability. A
  project-operated runner must use target ownership/allowlisting, isolated
  workers, default-deny egress, quotas, and emergency disable controls; it
  never accepts arbitrary public targets.

## Consequences

Trust is more verbose than a verified check mark, but users can distinguish who
observed what and under which controls. Immutable observations survive
administrative changes while sensitive deletion can remove physical content
and retain only lawful minimal audit facts.

Hosted operation requires identity, quarantine, object integrity, migration,
backup, dispute, moderation, incident, privacy, and legal programs. Describing
those requirements does not claim they exist.

## Alternatives

- Treat every signature as equally trusted: ignores signer role, ownership,
  replay, and independence.
- Store labels inside observation identity: administrative changes would
  rewrite technical facts.
- Use a Git repository as the entire Registry: transparent but weak for
  quarantine, auth, withdrawal, and scale.
- Make the public service mandatory for local tests: harms privacy,
  reliability, and offline use.

## Validation before acceptance

Test subject substitution, unauthorized signer, replay, expiry, label
self-award, ownership rotation, duplicate independence, quarantine leakage,
deterministic reevaluation, disputes, withdrawal, hard deletion, backup/restore,
SSRF/DNS/redirect/archive/XSS defenses, and audit integrity. Acceptance also
requires actual external security, privacy, legal, and penetration review; no
candidate code or self-host test can replace it.
