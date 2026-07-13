# Migration and Compatibility

`v0.1.0` is the first supported AgentAPI Doctor distribution. The project is
still pre-1.0: the documented command workflow is supported within `0.1.x`,
while versioned JSON/YAML formats retain their own alpha, beta, or v1 labels.

The machine-readable floor is
[`schemas/migration-floor.yaml`](../../schemas/migration-floor.yaml). It states
which release-candidate artifacts the current reader accepts; it does not turn
candidate protocol interpretations into stable conformance standards.

## Configuration

New configurations use `urn:agentapi-doctor:config:v1beta2`. The rc1-rc3
`v1beta1` shape exposed a top-level `defaults` block whose budget, retry, and
capture values were not execution controls. Doctor now rejects that format
with an actionable message instead of silently ignoring those settings.

To migrate:

1. delete the top-level `defaults` block;
2. change `apiVersion` to `urn:agentapi-doctor:config:v1beta2`; and
3. run `doctor self-check` before contacting a target.

Target names and definitions otherwise keep the same shape.

## Runs and reports

Doctor reads local run records and report bundles from both `v1alpha1` and
`v1alpha2`. Legacy report-only records remain inspectable, but they cannot
invent the persisted plan introduced by `v1alpha2`; `--include-plan` therefore
fails clearly for those records. New writes use `v1alpha2`.

Persisted plan snapshots use
`urn:agentapi-doctor:local-plan-snapshot:v1alpha1`. Report and plan readers are
strict, bounded, and offline. Unknown future schema versions fail closed.

## Baselines and CLI results

New baselines use `urn:agentapi-doctor:baseline:v1`. Doctor still reads the
exact unversioned baseline shape written by rc1-rc3 and upgrades it in memory;
the source file is never rewritten implicitly. Baselines remain comparable
only when all immutable profile, pack, support-lock, and denominator digests
match.

Machine-readable command envelopes use
`urn:agentapi-doctor:cli-result:v1alpha1`. That envelope and the documented
exit-code meanings are supported within `0.1.x`; command-specific `data`
objects may add fields while the envelope schema stays unchanged.

## Change policy

A breaking stored-format change requires a new schema identity, old/new
fixtures, an offline reader or explicit migration, release notes, and tests for
the supported read floor. Published pack/profile digests, tags, and release
assets are never rewritten. Downgrade writing is not promised.

See [Release Policy](../../RELEASE.md) for version channels and
[Known Limitations](../known-limitations/README.md) for the supported product
boundary.
