# Redaction Before Persistence

Redaction is a write boundary, not a later cleanup job.

## Required flow

```text
untrusted bytes
  -> bounded classification/parsing
  -> sanitizer with configured rules and canary
  -> sanitized bytes plus redaction records
  -> content-addressed persistence
```

Raw network or client data must not be written to a log, temporary file, CAS,
report, snapshot, crash dump, or artifact before that flow completes. A caller
should be unable to store an unsanitized byte slice through the strict API.

## Field classes

- always secret: authorization, cookies, private keys, secret references;
- conditionally sensitive: URLs, identifiers, headers, prompts, tool arguments;
- safe synthetic metadata: fixture IDs, bounded counters, public spec IDs; and
- unknown: redact or omit by default.

Rules apply to structured JSON and unstructured text. URL sanitization handles
userinfo, query values, fragments, and configured host/path patterns. Replacing
a value records a reason and count without reproducing the original.

## Verification

Use one high-entropy synthetic canary across headers, URL, JSON, text, SDK
errors, logs, temporary files, reports, archives, and crash output. Scan every
sink after the run. Tests must also prove that sanitized payloads retain enough
structure to reproduce the intended failure and that tampering changes the
content digest.

Redaction is not anonymization. Public projection still requires explicit
rights, preview, and consent under [the data policy](../../DATA_POLICY.md).
