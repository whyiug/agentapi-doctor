# Threat Model

**Status:** maintained project threat model; no external security review is
recorded.

This model covers the planned local CLI, drivers, evidence store, reports,
self-hosted components, and future hosted Registry. A future component is not
treated as deployed merely because its risks are described here.

## Security goals

1. Do not persist or publish secrets before redaction.
2. Execute only the authorized target, scenarios, tools, and budgets.
3. Keep untrusted packs, drivers, artifacts, archives, and reports from
   escaping their declared file, process, and network boundaries.
4. Bind results and evidence to exact source, immutable inputs, producer, and
   content digests.
5. Prevent a Registry or sponsor from silently changing trust labels,
   observations, disputes, or denominators.
6. Preserve availability through bounded resources, finalizers, quarantine,
   and tested recovery.

## Assets

- API credentials and secret references;
- request/response content and capture-layer evidence;
- local files, environment, keychains, processes, and network identity;
- pack/profile/driver artifacts and Requirement Catalog sources;
- immutable result, observation, attestation, and release digests;
- ownership, reviewer, signer, and audit identities; and
- Registry availability, dispute history, backups, and deletion records.

## Trust boundaries

| Boundary | Untrusted side | Trusted decision point |
|---|---|---|
| Config and secret resolution | authored config, environment, helper output | typed config validation and scoped secret resolver |
| Target network | endpoint, redirects, DNS, proxies | allowlisted origin, resolved-address policy, redirect policy and budget |
| Protocol input | HTTP/SSE/JSON and model text | bounded parsers, raw evidence capture and typed normalization |
| Pack/profile | contributed YAML/OCI content | schema, source, signature, digest, CEL sandbox and review |
| Driver process | SDK/client dependencies and child process | RPC codec, capability negotiation, sandbox, env/path/network policy |
| Evidence persistence | raw payload and logs | write-before-redact sanitizer and content-addressed store |
| Artifact import | archives, reports, attestations | size/path/type limits, quarantine, signature and digest verification |
| Registry publication | self-reported observation | two-phase preview, ownership/trust labels, deterministic reevaluation |
| Release | source, CI dependencies and build outputs | protected tag/environment, OIDC provenance, SBOM, signatures and verifier |

## Threats and required controls

### Secret and private-content disclosure

Credentials may appear in headers, URLs, JSON, text, environment variables,
SDK exceptions, crash output, archives, or derived reports. Strict capture must
sanitize before every persistent write, use the same canary across all sinks,
and fail closed when a field cannot be safely classified. Full local encrypted
capture, if implemented, remains opt-in and never becomes public automatically.

### SSRF and network pivoting

A target, redirect, DNS rebinding, proxy, driver, or tool could reach loopback,
private networks, cloud metadata, Unix sockets, or a second origin. Resolve and
pin the authorized origin, re-evaluate every redirect and DNS result, deny
metadata/private/loopback ranges unless the exact local fixture is explicitly
authorized, and bound bytes, requests, duration, concurrency, and redirects.
Project-operated runners require stronger allowlists and egress isolation than
local user-owned runs.

### Driver and tool execution

SDKs and drivers can read environment variables, files, paths, helper programs,
or network resources. Start them with an allowlisted environment, isolated
working directory and temporary home, bounded process tree, explicit network
policy, and no inherited credential. Real tool side effects are denied by
default; fixture tools return synthetic results.

### Parser, archive, and report attacks

Hostile JSON/SSE, recursive structures, duplicate keys, decompression bombs,
path traversal, symlinks, HTML/Markdown, and terminal escapes can corrupt state
or execute content. Enforce nesting/size/count limits, reject ambiguous JSON,
extract only into an isolated destination, sanitize terminal output, and render
offline reports with a restrictive CSP and no active remote content.

### Supply-chain compromise

Dependencies, actions, images, drivers, packs, and release tooling can change
between review and use. Lock versions and content digests, pin Actions by full
commit, use minimal build permissions, produce SBOM and provenance, sign exact
subjects, verify after public download, and never overwrite published tags or
artifacts.

### Evidence or Registry forgery

An actor may rebind an ID, omit failing denominator members, replay an old
attestation, self-award a trust label, or alter Registry-derived metadata.
Canonical immutable projections, source and producer binding, explicit
denominators, signer authorization, freshness windows, append-only audit, and
independent replay prevent those shortcuts. A Registry-derived trust or dispute
field never changes the submitted observation identity.

### Resource exhaustion and persistence

Streams, retries, subprocesses, fuzzing, artifacts, uploads, or cleanup can
consume shared resources. Reserve hard budgets before work, meter actual use,
limit queues and artifact size, disallow hidden retries, and give finalizers a
separate cleanup budget. Task-owned services and processes must be stopped.

## Abuse cases

The project must not become a public scanner, exploit launcher, credential
broker, ranking manipulation service, or a way to publish private traces. A
future hosted service needs rate limits, authorization, moderation, ownership
challenge, dispute/withdrawal, and anti-sybil controls. Payment cannot buy a
passing result or erase a valid failure.

## Residual risks and review gates

Redaction can miss unknown secret formats; sandbox strength varies by platform;
provider behavior can be nondeterministic; signatures do not prove correctness;
and a small governance group can be captured. These risks require secret
canaries, platform-specific adversarial tests, explicit statistical uncertainty,
independent review, role separation, incident drills, and conservative public
claims.

Before a hosted Registry launches, an external reviewer must assess this model
and independent security testing must close high-severity findings. No such
review or penetration test is claimed today.
