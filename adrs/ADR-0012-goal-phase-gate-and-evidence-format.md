# ADR-0012: Goal phase gate and evidence format

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

The project spans contracts, implementation, external reviews, adoption,
release windows, and human decisions. A green local test or long-running agent
must not approve its own gate, invent external evidence, activate future work,
or turn editable status into execution authority.

The full proposed lifecycle is in
[Plan section 29](../agentapi-doctor-Plan.md). The current
[execution README](../execution/README.md) explicitly describes a pre-Genesis
bootstrap candidate, not active phase state.

## Proposed decision

- Organize the implementation into P00-P08 phases with ordered bounded work
  units. After Genesis, at most one work unit is authoritative and active; an
  agent never selects a merely ready or pending unit.
- Require each Goal Contract to name objective, scope and exclusions,
  deliverables, prerequisites, protected acceptance inputs, verification,
  convergence criteria, budgets, network policy, and stop conditions.
- Classify every criterion as MACHINE, EXTERNAL, TIME, or HUMAN and bind it to
  an evaluator, threshold, evidence schema, source commit, control-plane
  digest, and protected input/dataset digest. Machine success never grants a
  human or external approval.
- Make gate evidence recomputable from strict raw records. Each result records
  exact commands/evaluator version, inputs and digests, attempt/run-pair
  identity where applicable, exit/outcome, bounded logs or artifact references,
  measurements with numerator/denominator, and failure or insufficient reason.
  Hand-entered metrics and file-existence-only PASS are invalid.
- Fail closed for a missing evaluator, capability, dataset, source binding,
  approval, signature, or evidence. A waiver cannot silently lower a threshold
  or convert a missing criterion to PASS.
- After an independently authorized Genesis, represent authoritative state as
  append-only, signed, hash-chained Genesis, StateTransition, and
  EvidenceAttachment events. Generate the readable phase-state view by replay;
  direct edits are not authority.
- Bind approvals and transitions to the exact source commit, contract,
  control-plane and evidence digests, actor role/identity, conflict statement,
  time, and signature. Authors and agents cannot create independent approval
  for their own work.
- Treat protected contract, evaluator, threshold, denominator, or acceptance
  input changes as evidence invalidation requiring the defined transition and
  new authorization.
- Before Genesis, permit only the phase-external P00.B00 candidate artifacts,
  real gate runner and anti-placeholder tests, and a pending approval request.
  Do not create phase state, transitions, completion evidence, or activation by
  implementing this proposal.

## Consequences

Work can remain blocked on real reviewers, adoption, elapsed time, security
assessment, or governance even when local code is complete. This is intended:
those facts cannot be synthesized by an implementation agent. Digest closure,
protected inputs, append-only replay, and evidence recomputation add machinery
but make silent gate weakening and retroactive status edits detectable.

The bootstrap boundary requires a separate independently authorized Genesis
before ordinary phase execution. Candidate manifests and passing meta-tests do
not cross that boundary.

## Alternatives

- Editable YAML status is simple but permits approval history to be rewritten.
- Treating CI status as authority conflates code execution with governance and
  external facts.
- One unlimited goal obscures scope, protected inputs, denominators, and
  convergence.
- File-presence gates and hand-entered metrics are easy to satisfy without
  exercising a real code path.
- Self-approval removes the independent control the evidence model is designed
  to provide.

## Validation before acceptance

Run anti-placeholder, unknown-evaluator, digest substitution, metric
recomputation, protected-input mutation, signature/identity, replay, ordering,
double-activation, and state-tamper tests in two clean checkouts. Separately
exercise real independent approval and protected workflow identity without
granting candidate code write authority. No Genesis, phase transition, or
acceptance is asserted by these documents or tests.
