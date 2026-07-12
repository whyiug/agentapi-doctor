# Data Lifecycle

## Current local lifecycle

1. The user supplies configuration and explicit authorization.
2. Secret references resolve as late as possible and are scoped to the driver.
3. Capture produces bounded in-memory data.
4. Strict redaction runs before persistence.
5. Sanitized evidence receives a digest and declared retention location.
6. Reports refer to evidence by ID/digest and bounded excerpts.
7. The user controls local export and deletion.

Local runs do not opt into upload or telemetry. Tests must not read a real home
directory, keychain, `.env`, or ambient credentials.

When the configured target is remote, it receives bounded synthetic requests
and may retain them under the target operator's own policy. Use authorized test
accounts and synthetic inputs; local redaction cannot control remote retention.

## Future Registry lifecycle

A future hosted path adds quarantine, a public-projection preview, affirmative
terms/rights attestation, validation, trust labeling, publication, dispute,
supersede/tombstone, withdrawal, physical deletion, backup expiry, and durable
audit facts. Retention periods and legal contacts are not defined because the
service is not launched.

The governing current policy is [DATA_POLICY.md](../../DATA_POLICY.md). Draft
hosted privacy and terms files do not authorize upload today.
