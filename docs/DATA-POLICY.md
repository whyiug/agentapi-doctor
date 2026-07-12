# P00 Data Policy Design Note

**Status:** provisional design note.

The public current policy is [DATA_POLICY.md](../DATA_POLICY.md). This P00 note
records design invariants needed by later contracts:

- local-first and no telemetry/upload by default;
- write-before-redact for every persistent sink;
- raw artifacts, identities, signatures, comments, model text, and public fact
  projections are distinct data classes;
- public projection requires rights, exact preview, consent, provenance, and
  digest binding;
- hosted retention, subprocessors, jurisdictions, deletion, and contacts must
  be resolved before launch; and
- changing privacy defaults or public projection semantics requires RFC review.

The source policy and this note are original project content under Apache-2.0.
Relevant public engineering references must be recorded in the future
`sources.lock.yaml`; no legal review is claimed here.
