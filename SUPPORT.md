# Support

AgentAPI Doctor is a community project. Support is best-effort and has no
guaranteed response or resolution time.

## Choose a channel

- Use [GitHub Discussions](https://github.com/whyiug/agentapi-doctor/discussions)
  for usage questions, ideas, and general help.
- Use [GitHub Issues](https://github.com/whyiug/agentapi-doctor/issues) for a
  reproducible bug, scoped feature proposal, fixture contribution, or verified
  specification drift. Choose the closest issue form.
- Use the private process in [SECURITY.md](SECURITY.md) for suspected
  vulnerabilities, secrets, private traces, or sensitive data. Never post
  those details publicly.

## What to include

For a technical question or bug, include the exact source commit or version,
operating system and architecture, redacted configuration, smallest
deterministic local reproduction, expected and observed behavior, and relevant
failure/evidence IDs. Replace credentials and private payloads with synthetic
values.

Do not send production keys, customer data, full private logs, or a payload
that targets a public service. A maintainer may close or redact content that is
unsafe, non-reproducible, or outside the project's authorization boundary.

## Supported versions

`v0.1.0` is the first supported Doctor distribution. The latest `0.1.x`
receives best-effort security and critical defect fixes; release candidates and
older patch releases are superseded. Because the project is still pre-1.0,
documented breaking changes may occur in a later minor release. Versioned
stored formats follow the read-compatibility floor in
[Migration](docs/migration/README.md).

The project does not operate a hosted Registry or managed compatibility
service. Questions about a third-party endpoint remain the responsibility of
that system's operator unless a reproducible AgentAPI Doctor defect is shown.
