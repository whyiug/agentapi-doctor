# RFC-0005: Registry Trust and Attestation

- **Status:** draft
- **Review:** none recorded
- **Target phase:** P07 contract input
- **Deployment status:** no hosted Registry exists

## Problem

A public compatibility matrix can mislead users if self-reported observations,
owner statements, project-run runs, stale results, disputes, and mutable
configuration are displayed as equivalent. Upload also creates substantial
secret, SSRF, identity, privacy, legal, abuse, and recovery risk.

## Goals

- preserve immutable submitted observations;
- display provenance, trust, freshness, identity, and denominators explicitly;
- support owner response, dispute, supersede, withdrawal, and deletion;
- make hosted failure irrelevant to local CLI operation; and
- prevent sponsorship or payment from changing technical truth.

## Trust labels

The proposed labels are Local, Self-reported, Owner-verified, Independently
reproduced, and Project-operated-run. They identify the evidence path, not a
quality rank or certification. A label requires an authorized attestation bound
to exact observation, target, pack/profile/config/support-lock digests, runner,
and source.

## Ingest

1. Authenticate the submitter and authorize target/ownership claims.
2. Receive into a bounded quarantine with no public visibility.
3. Verify schema, digest, signature, provenance, rights, and secret policy.
4. Deterministically reevaluate against the pinned oracle/pack.
5. Show the exact public fact projection and applicable terms.
6. Require affirmative publication consent.
7. Commit immutable objects idempotently and append audit events.

Arbitrary URLs are not accepted by a project runner. Ownership challenge,
allowlist, egress isolation, redirect/DNS policy, quota, and abuse controls are
required.

## Mutable lifecycle around immutable facts

Freshness, trust labels, disputes, owner responses, supersede links, tombstone,
and withdrawal are Registry-derived records outside the observation identity.
They are visible and auditable. A vendor cannot decide its own dispute alone;
appeals use an unconflicted reviewer. Physical deletion observes effective
policy while retaining only lawful minimal audit facts.

## Privacy and rights

Only an enumerated non-sensitive fact projection may be dedicated under the
future data license with explicit rights and consent. Raw artifacts, identities,
signatures, comments, model text, and private configuration do not automatically
become public. Effective terms, privacy notice, retention, operator identity,
and legal review are launch prerequisites.

## Operations and security

The service uses PostgreSQL for system-of-record state and content-addressed
object storage; derived indexes are rebuildable. Requirements include
two-phase upload, secret quarantine, auth/ownership, signature replay policy,
SSRF/DNS/redirect/archive/XSS tests, rate/size quotas, audit, backup/restore,
RPO/RTO drills, incident response, and external penetration testing.

## Alternatives considered

- **Git repository as Registry:** transparent but weak for quarantine,
  withdrawal, auth, and volume; useful for exports, not the hosted authority.
- **Single score/ranking:** easy to browse but obscures dimensions and invites
  gaming; rejected.
- **Trust self-report equally:** fails provenance and owner boundaries;
  rejected.
- **Make local CLI depend on hosted service:** harms privacy and reliability;
  rejected.

## Unresolved questions

- operator/legal entity, jurisdictions, retention, and subprocessors;
- ownership challenge methods and rotation;
- independent-runner admission and revocation;
- public projection schema and consent record; and
- measured capacity needed for safe hosted operations.

Acceptance requires real security/privacy/legal review, self-host tests,
recovery and dispute drills, external penetration testing, and the quantitative
P07 evidence gates. None is claimed here.
