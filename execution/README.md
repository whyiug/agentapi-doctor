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

`state-verify` proves only the required `PRE_GENESIS` absence state. The R2
candidate adds separate, read-only `approval-verify` and `state-chain-verify`
commands. They verify strict canonical envelopes, OpenSSH SSHSIG namespaces,
externally pinned trust/subject digests, a continuous signed StateEvent chain,
the Section 29.2 transition table, evidence-index bindings, and an optional
exact derived-state view. Neither command signs, appends, repairs, or creates
files.

R2 intentionally defines no caller-supplied “verified evidence” or transition
approval registry. Any StateTransition carrying an evidence or approval digest
returns `unverified_transition_evidence` or
`unverified_transition_approval`; a later independently approved evaluator must
introduce a provenance-bearing result type before convergence transitions can
replay. A signed workflow event or matching dictionary alone is not evidence.

The committed trust policy is deliberately `pending_trust_roots` with an empty
principal roster. Therefore a real invocation cannot pass yet: an independent
process must provision and externally pin the policy digest, exact candidate
commit, request/control-plane digests, and (for state replay) chain head. A
repository-controlled replacement policy is insufficient. The workflow
candidate is likewise read-only and non-authoritative; private-repository
environment protection and runtime/toolchain evidence remain unproved.

`control-plane-inputs.yaml` is the explicit digest input list. Before hashing,
all `controlPlaneDigest` values are normalized to a fixed placeholder,
then each JSON document uses the dependency-free
`bootstrap-canonical-json-v1` projection. P01 must replace this provisional
projection with the production RFC 8785 contract. Approval requests,
approvals, state transitions, generated state, and completion evidence are not
control-plane inputs.

## Genesis boundary

This candidate intentionally contains no `phase-state.yaml`, `transitions/`,
`approvals/`, completion evidence, signer key, or P00 activation. It includes no
Genesis writer. Those artifacts and capabilities require another independently
reviewed revision after the trust and workflow prerequisites are proven.
