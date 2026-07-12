# Security Policy

AgentAPI Doctor handles protocol payloads, execution evidence, and potentially
sensitive configuration. Security reports must be kept out of public issues,
pull requests, discussions, logs, and test fixtures.

## Supported versions

There is no stable release or hosted Registry today.

| Surface | Status |
|---|---|
| Default branch and unreleased development code | Evaluated for security fixes; no long-term support commitment |
| Tagged stable releases | None published |
| Hosted Registry or public runner | Not deployed |

This table will be replaced with explicit version support windows when stable
releases exist. It is not a response-time promise.

## Report a vulnerability privately

Use the repository's
[GitHub private vulnerability reporting form](https://github.com/whyiug/agentapi-doctor/security/advisories/new).

Do not open a public issue with vulnerability details. If GitHub does not make
the private form available to your account, a public issue may request that the
maintainer enable a private channel, but it must contain no exploit details,
secrets, affected payloads, or other sensitive information.

A useful private report contains:

- the affected commit, version, component, and configuration;
- the security boundary and realistic attacker prerequisites;
- a source-to-sink explanation and concrete confidentiality, integrity, or
  availability impact;
- a minimal, non-destructive local reproduction using synthetic data;
- whether the issue is already public; and
- a suggested remediation or regression assertion, if known.

Do not include production keys, private user data, or a weaponized exploit.
Redact request/response payloads before attaching them.

## Coordinated handling

The project will evaluate reports according to available maintainer capacity
and will keep necessary discussion private while a report is under review. No
fixed acknowledgement, remediation, or disclosure deadline is promised here.
When a report is valid, maintainers should coordinate a minimal fix, regression
test, affected-version analysis, advisory, and release evidence before public
technical detail is added.

Security work does not bypass provenance or release-signing rules. Emergency
fixes may be applied first when needed, with public rationale added after
coordinated disclosure when it is safe to do so.

## Research boundary

We welcome good-faith research against source, fixtures, and systems you own or
are explicitly authorized to test. Keep testing local and non-destructive. Do
not scan, probe, fuzz, or exploit public targets; exfiltrate data; disrupt other
users; or retain secrets. This policy does not grant authorization to test any
third-party system.
