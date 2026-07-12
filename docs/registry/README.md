# Registry

The repository currently provides a runnable, single-node SQLite **self-host
candidate**: the `registry serve -database ...` command, Registry HTTP API,
static Matrix, consistent SQLite backup command, Dockerfile target, and local
Compose wiring can be exercised from source.

It does **not** provide a hosted AgentAPI Doctor service, production support,
a managed image, a public runner, or a hosted verifier. In particular, a
durable upload commit ends with `501 hosted_verifier_unavailable`; it is not
published or assigned a project trust label. The local Doctor remains
independent of the Registry.

## Operator documentation

- [Self-hosting candidate](self-hosting.md) — direct and Compose startup,
  listener and token boundaries, persistence scope, and limitations.
- [Backup and recovery](../operations/backup-and-recovery.md) — consistent
  backup, offline restore, permissions, integrity checks, upgrade, and
  rollback.

## Design and policy context

- [Trust and attestations](trust-and-attestations.md)
- [Disputes, supersede, and withdrawal](disputes.md)
- [Registry terms](../../REGISTRY_TERMS.md)
- [Privacy notice](../../PRIVACY.md)
- [Acceptable use policy](../../ACCEPTABLE_USE.md)

The terms, privacy notice, and acceptable-use text remain drafts for a future
hosted service; running the local candidate does not make them project-operated
service terms. Operators are responsible for their own authorization, data
handling, access controls, retention, and legal review.
