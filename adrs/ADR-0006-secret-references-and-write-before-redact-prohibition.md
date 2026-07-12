# ADR-0006: Secret references and write-before-redact prohibition

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Credentials and private content can appear in headers, URLs, JSON, stream
events, driver exceptions, logs, temporary files, reports, archives, or crash
output. Redacting after a write cannot undo disclosure to a filesystem,
backup, artifact store, or log collector. Tests must also remain independent of
the user's real home, keychain, `.env`, and ambient credentials.

The governing boundaries are documented in the
[data policy](../DATA_POLICY.md),
[redaction design](../docs/security-and-privacy/redaction.md), and
[threat model](../docs/THREAT-MODEL.md).

## Proposed decision

- Configuration and plans contain typed secret references, never literal
  secret values. A reference identifies the resolver and logical name but is
  excluded from logs and public identity projections where it could disclose
  sensitive structure.
- Resolve only the references required by the final authorized plan, as late as
  possible, with a scoped resolver and minimum lifetime. Plan-only and offline
  validation do not resolve secrets.
- Do not pass secrets on command lines or inherit the parent environment.
  Deliver only the required value through an approved scoped channel to the
  component that needs it.
- Treat untrusted bytes as an in-memory bounded value until classification and
  redaction complete. Every persistent sink accepts only the sanitized type or
  projection; it must be impossible to call the strict CAS, log, report,
  snapshot, artifact, or temporary-file writer with raw bytes.
- Apply structured and unstructured rules to authorization, cookies, private
  keys, URLs, secret references, user literals, and unknown sensitive fields.
  Preserve redaction reason and count without preserving the original value.
- If a value cannot be safely classified or sanitized, omit it or fail closed.
  A recorder/driver crash or incomplete stream never commits its raw temporary
  state.
- Do not publish an ordinary hash of a low-entropy secret. When local
  correlation is essential, use a local keyed fingerprint or retain only
  non-sensitive type/length metadata.
- Keep any future opt-in encrypted full-capture mode outside the strict public
  evidence path. It requires a separate reviewed threat model, retention, key
  lifecycle, and explicit user action and can never be uploaded implicitly.

## Consequences

Debug evidence may be incomplete, and fail-closed handling can turn a run into
an evidence error. This is preferable to persisting a value that cannot be
recalled reliably from copies and backups. Strong API types and streaming
sanitization add memory and implementation constraints, while platform crash
and swap limitations must remain visible residual risks.

## Alternatives

- Write first and scrub later leaves recoverable bytes and races every sink.
- Environment-variable literals are convenient but spread through child
  processes, diagnostics, and process inspection.
- Encrypting all raw data by default still persists sensitive material and
  creates a key-management and accidental-publication boundary.
- Hashing secrets without a key permits dictionary recovery for low-entropy
  values.

## Validation before acceptance

Place one synthetic high-entropy canary in headers, URLs, JSON, text, driver
errors, logs, temporary paths, reports, archives, backups, and crash paths;
scan every sink and require zero occurrence. Add failure-injection tests before,
during, and after sanitizer/CAS commit, plus plan-only tests proving no resolver
call. Independent privacy and security review are required. Existing tests are
candidate evidence only.
