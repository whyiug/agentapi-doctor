# ADR-0006: Secret references and write-before-redact prohibition

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Context

Credentials and private content can appear in headers, URLs, JSON, stream
events, errors, logs, temporary files, reports, archives, or crash output.
Redacting after a write cannot recall data from a filesystem, backup, or log
collector.

## Decision

- Configuration and persisted run inputs contain typed secret references, not
  literal secret values.
- Resolve only the secret required by an authorized execution, as late as
  possible. Offline and `--plan-only` paths do not resolve secrets.
- Do not pass secrets on command lines or copy ambient credentials into child
  environments.
- Keep untrusted bytes bounded in memory until classification and redaction
  complete. Persistent writers accept only sanitized values.
- Redact authorization data, cookies, private keys, sensitive URLs, secret
  references, user literals, and configured patterns while retaining only
  non-secret reason/count metadata.
- Omit unsafe content or fail closed when it cannot be classified or
  sanitized.
- Never publish an ordinary digest of a low-entropy secret.

## Release boundary

This decision covers the local Doctor execution, evidence, report, run-store,
and reproduction-bundle paths. Generic driver secret delivery and any future
encrypted full-capture feature require separate accepted security contracts.

## Consequences

Some diagnostic evidence is intentionally incomplete, and a redaction failure
can make a run inconclusive or errored. That is preferable to persisting data
that cannot be reliably removed from copies.

## Validation basis

Acceptance is based on typed secret references, late resolution, redaction and
sanitize-before-store implementation, isolated test homes, and synthetic
secret-canary coverage reviewed for the Doctor release.
