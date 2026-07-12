# Trust and Attestations

Trust describes evidence provenance, not a universal quality score. The planned
labels are:

1. **Local** — result remains on the user's machine.
2. **Self-reported** — a submitter signed the immutable observation.
3. **Owner-verified** — the target owner completed the ownership challenge and
   endorsed the named observation/configuration.
4. **Independently reproduced** — an authorized independent runner reproduced
   the immutable target and test identity.
5. **Project-operated-run** — a project runner produced the observation under
   its published isolation and freshness policy.

Higher labels do not rewrite lower-level evidence or mean “officially
compatible.” Every display includes pack/profile/config/support-lock digests,
denominators, freshness, source, and material limitations.

Signatures bind bytes and identity; they do not prove the assertion is correct.
A future hosted verifier must verify signer authority, subject digests, source
commit, provenance, replay/freshness window, and immutable projection before a
Registry can issue a project trust label. The current self-hosted Registry
candidate does not perform that verification: its commit endpoint fails closed
with `hosted_verifier_unavailable`. In the planned design, Registry-derived
freshness, trust labels, disputes, and tombstones remain outside the observation
identity and are auditable.

No trust label has been issued by a hosted project service today.
