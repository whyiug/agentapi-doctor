# Execution control plane (P00 bootstrap candidate)

This directory contains the **unapproved P00.B00-R3 candidate** control plane.
It does not prove that P00 is active, approved, machine-converged, or complete.
The immutable P00.B00 and P00.B00-R2 requests remain historical inputs; R3 is
their proposed successor.

All `*.yaml` files here are deliberately JSON-compatible YAML (valid JSON).
The request generator binds every candidate `controlPlaneDigest` to the
computed aggregate. This binding is not an approval and does not create
Genesis or execution state.

## Fail-closed rules

- All P00 MACHINE evaluators have an implemented candidate, offline handler and
  protected adversarial tests. Unknown, future, unapproved, or digest-mismatched
  evaluators return an error and can never PASS.
- P00 record evaluators recompute results from strict raw records and require
  exact A/B, source, control-plane, evaluator, dataset, and freeze bindings.
  They reject caller-supplied counts, ratios, verdicts, duplicate keys,
  non-finite values, missing fields, and extra fields.
- A null dataset digest is not a sample. Dataset-dependent criteria remain
  `insufficient_samples` until an independent `SignedProtectedInputFreeze`
  binds the final records, contract, criteria, source, and control plane.
- EXTERNAL and TIME statements require an independent fact verifier in
  addition to signature provenance. HUMAN results require an authorized
  SSHSIG principal, a reason, and an explicit conflict-of-interest statement.
- Transition proofs and approvals consume identity-sealed verifier results;
  callers cannot supply a dictionary registry or reconstruct an equivalent
  dataclass to authorize a transition.
- The protected outer executor owns both clean checkouts, uses fixed commands
  without a shell, bounds time and output, and runs each command in a fresh
  Linux user/network namespace. Missing namespace isolation fails closed; a
  stripped environment alone is never reported as offline execution.
- Reviewer delegation is criterion-scoped. A delegated reviewer cannot approve
  the control plane, sign state, or delegate again. The final P00 go/no-go
  requires two cryptographic approvals from different principals and
  organizations, including one independent external reviewer.

## R3 trust and protected writer

R3 uses two deliberately separate signature domains:

1. Human decisions use dependency-free OpenSSH SSHSIG v1 verification with an
   exact Ed25519 principal, namespace, role, validity window, policy digest,
   source commit, request digest, and workflow-execution commit.
2. StateEvents use a canonical-statement-digest audience and GitHub Actions
   OIDC RS256 token. Replay is offline against the independently approved JWK
   snapshot; an unknown key ID never triggers online trust discovery.

The proposed Genesis writer can run only for the exact approved workflow on
public, protected `main`, first run attempt, GitHub-hosted runner, and exact
repository/owner IDs. It observes public repository and active ruleset facts,
binds the canonical API projection into the event, self-verifies the token,
and uploads an artifact. It has no repository write permission and never
executes candidate or approval content. Importing an event and derived state
requires a separate reviewed change.

Read-only GitHub API responses cannot reveal every ruleset bypass actor. R3
therefore records that limitation and does not claim administrator/no-bypass
enforcement. The compensating authorization boundary is the independent
SSHSIG approval of the exact candidate and exact protected-main workflow
commit plus the OIDC `ref_protected=true` claim. Any missing observable rule,
weaker status check, private visibility, source mismatch, or missing external
pin fails closed.

The candidate verifier also implements post-Genesis work-unit lifecycle,
phase-aggregate, evidence-attachment, and append-only replay semantics. A
post-Genesis event builder consumes only an identity-sealed current chain, an
identity-sealed transition or attachment, and a currently valid signed
chain-head witness. It derives the next event and state projection, obtains a
digest-bound OIDC token, and incrementally self-verifies before returning an
artifact. Product-only descendant commits are permitted only while every
approved control-plane component remains byte-identical at the executing
protected-main commit.

These are candidate verifier components, not proof that any artifact import or
`make gate-unit` execution has occurred. The checked-in protected workflow has
strictly separate Genesis and append modes. Append mode replays a raw chain
from Genesis and can consume identity-sealed raw authorization bundles for P00
work-unit readiness, activation, convergence, evidence attachment, and the P00
phase aggregate. It reads chain and bundle inputs only by same-repository
immutable artifact ID/run ID, writes artifacts only, and never writes repository
state. Lifecycle resume evidence has a witness-bound library verifier, but no
protected-workflow write path in this revision; impact/control invalidation and
control-plane supersession fail closed until batch/state-revision semantics are
separately designed and approved.

This repository snapshot is a pre-Genesis review candidate and cannot
authoritatively create Genesis by code presence alone. Public visibility, exact
protected-main facts, an independent signature over the exact R3 decision, and
a separately authorized writer dispatch remain distinct activation inputs.

## Digests and state boundary

`control-plane-inputs.yaml` is the explicit digest input list. Before hashing,
every `controlPlaneDigest` field is normalized to a fixed placeholder; JSON
documents then use the dependency-free `bootstrap-canonical-json-v1`
projection. P01 must replace this provisional projection with the production
RFC 8785 contract.

Approval requests, approvals, StateEvents, generated state, run evidence, and
completion evidence are intentionally excluded from the control-plane digest.
Their own signatures and digests bind them to the approved control plane.

Before protected Genesis, the repository must contain no `phase-state.yaml`,
`transitions/`, `approvals/`, waiver, gate evidence, or P00 activation. The R3
candidate contains writer and verifier code only; code presence is not state
and is not a completion claim.
