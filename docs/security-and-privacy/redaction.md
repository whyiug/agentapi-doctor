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
- unknown: never assume it is anonymous. The raw HTTP driver omits opaque
  response content, while structured values needed for local evidence remain
  local unless a configured field rule, detector, or canary redacts them.

Rules apply to structured JSON and unstructured text. URL sanitization handles
userinfo, query values, fragments, and configured host/path patterns. Replacing
a value records a reason and count without reproducing the original.

Local run records use a dedicated plan snapshot rather than serializing the
runtime target configuration. The snapshot retains the endpoint, protocol,
model, immutable IntentPlan/ResolvedRunPlan envelopes, and their digests, but
omits the secret reference and all free-form target metadata. Those hidden
inputs remain bound only inside the ephemeral frozen execution plan; the
persisted snapshot deliberately exposes no guessable digest of them. Treat
`.agentapi/` as private local state because an endpoint URL can itself be
sensitive.

## Verification

Use one high-entropy synthetic canary across headers, URL, JSON, text, SDK
errors, logs, temporary files, reports, archives, and crash output. Scan every
sink after the run. Tests must also prove that sanitized payloads retain enough
structure to reproduce the intended failure and that tampering changes the
content digest. Report tests additionally resolve every Evidence reference to
its validated canonical envelope and then to its digest-matched sanitized
Payload object.

Redaction is not anonymization. Model content, identifiers, and tool arguments
inside otherwise valid structured responses may remain in the private local
evidence store. Review before export; public projection still requires
explicit rights, preview, and consent under
[the data policy](../../DATA_POLICY.md).
