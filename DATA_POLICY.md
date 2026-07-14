# Data Policy

## Scope

The supported AgentAPI Doctor v0.1.x product is a local CLI. The project does
not operate telemetry, an upload service, a public runner, a hosted Registry,
or a public observation dataset. Experimental Registry and Matrix source in
this repository does not create a project-operated service.

## Local processing

Doctor sends requests only to the exact endpoint a user configures for an
authorized check. Local runs do not opt users into telemetry or publication.
Until a versioned feature explicitly says otherwise:

- data remains in locations selected by the user;
- users control local retention and deletion;
- the CLI works without a Registry or project-operated network service;
- tests do not read ambient credentials, keychains, real `.env` files, or the
  user's home directory; and
- offline fixtures use synthetic data and an isolated temporary `HOME`.

Users are responsible for authorization to test an endpoint and for access to
their local output directory.

## Data handled by Doctor

A run may process configuration and secret references; requests, responses,
stream events, and tool data; capture-layer evidence; result and report data;
and local logs or crash information. These classes are kept distinct so a
report does not silently expose a raw artifact or credential.

## Collection minimization and redaction

Doctor collects only data needed for the selected checks and their evidence.
Persistent evidence must cross the sanitize-before-store boundary: secrets are
redacted before content enters the run store, reports, logs, archives, or
content-addressed storage. If content cannot be safely classified or
sanitized, the operation must omit it or fail closed.

Redaction covers credentials and authorization headers, cookies, secret
references, private keys, configured private URLs, and user-defined patterns.
Reports prefer digests, bounded excerpts, and synthetic reproductions.
Redaction is not anonymization, so users should review an artifact before
sharing it.

## Sharing artifacts

Doctor does not upload run artifacts. A user who chooses to share a report or
reproduction bundle controls that transfer and should verify that the target
recipient is authorized to receive it. Public issues must not contain secrets,
private endpoint data, production content, or unredacted credentials.

If sensitive data is found in repository content or a shared artifact, stop
further publication and report it privately under [SECURITY.md](SECURITY.md).
Do not copy the sensitive value into a public removal request.

## Future services

A future hosted or public-data feature would be a separate product surface. It
requires explicit opt-in, reviewed effective terms and privacy documentation,
purpose-limited collection, access controls, retention and deletion rules,
quarantine, incident response, and independent security and legal review.
Repository design documents do not authorize collection or publication.

Changes that reduce privacy defaults, add telemetry or upload, alter retention,
or change publication semantics require the RFC and review process in
[GOVERNANCE.md](GOVERNANCE.md).
