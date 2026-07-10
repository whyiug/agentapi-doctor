# Execution control plane (P00 bootstrap candidate)

This directory contains the **unapproved P00.B00 candidate** control plane. It
does not prove that P00 is active, approved, machine-converged, or complete.

All `*.yaml` files in this directory are deliberately JSON-compatible YAML
(valid JSON). The request generator binds every candidate `controlPlaneDigest`
to the computed aggregate. This binding is still unapproved and does not create
Genesis or execution state.

## Fail-closed rules

- Only `evaluator://bootstrap/control-plane/v1` and
  `evaluator://bootstrap/anti-placeholder/v1` are implemented in B00.
- Every planned machine evaluator must return `missing_evaluator`; it can never
  produce PASS merely because a file exists, is non-empty, or contains a
  hand-written number.
- EXTERNAL and HUMAN criteria require independently signed attestations. The
  local gate runner cannot create them.
- Pending corpus and experiment datasets are not samples. Their digest remains
  null and their metrics return `insufficient_samples` until the protected
input is independently frozen.

`state-verify` currently proves only the required `PRE_GENESIS` absence state.
It does not accept or replay approval/state artifacts. The trusted signature,
identity, transition-replay, activation, and evidence workflow must be supplied
and independently approved before Genesis; until then every protected gate
continues to fail closed.

`control-plane-inputs.yaml` is the explicit digest input list. Before hashing,
all `controlPlaneDigest` values are normalized to a fixed placeholder,
then each JSON document uses the dependency-free
`bootstrap-canonical-json-v1` projection. P01 must replace this provisional
projection with the production RFC 8785 contract. Approval requests,
approvals, state transitions, generated state, and completion evidence are not
control-plane inputs.

## Genesis boundary

This candidate intentionally contains no `phase-state.yaml`, `transitions/`,
`approvals/`, completion evidence, or P00 activation. Those artifacts may only
be produced after independent approval through the protected Genesis workflow.
