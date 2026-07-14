# Registry (Experimental)

Registry and Matrix code in this repository is a source-only development
candidate. It is not part of the supported v0.1.x Doctor product, and the
project does not operate a hosted Registry, public runner, upload service,
managed image, verifier, or compatibility matrix.

Contributors can exercise the single-node SQLite command, HTTP API, static
Matrix, backup command, Dockerfile target, and local Compose wiring against
synthetic data. These interfaces may change without a v0.1.x compatibility or
operations promise. A durable upload commit currently ends with
`501 hosted_verifier_unavailable` and receives no project trust label.

The local Doctor CLI remains independent of Registry availability.

## Development documentation

- [Self-hosting candidate](self-hosting.md)
- [Trust and attestation design](trust-and-attestations.md)
- [Dispute, supersede, and withdrawal design](disputes.md)
- [Backup and recovery experiments](../operations/backup-and-recovery.md)

These documents describe candidate implementation and design boundaries, not
service terms or production guidance. Anyone running the code is responsible
for authorization, authentication, data handling, retention, incident
response, and legal review in their own environment.

A future project-operated service would require a separate accepted RFC,
effective terms and privacy documentation, independent security and legal
review, recovery evidence, abuse controls, and an explicit release
announcement. None is claimed here.
