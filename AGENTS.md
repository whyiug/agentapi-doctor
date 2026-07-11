# Repository instructions

`agentapi-doctor-Plan.md` is the authoritative implementation plan during P00.
Read it before changing a contract, gate, evaluator, schema, security boundary, or
public behavior. After P01 approval, versioned manifests are authoritative for
execution state; the plan, approved RFCs, and ADRs remain authoritative for design
intent. Do not silently resolve a normative ambiguity: record an ambiguity note and
stop the affected work.

## Work and state

- Follow the state, Goal Contract, convergence, evidence, and pause protocol in Plan
  §29. A gate result never grants approval or changes authoritative state by itself.
- Before Genesis, work only on the phase-external P00.B00 bootstrap candidate
  described in Plan §34.2. It may create candidate contracts, manifests, a real gate
  runner, anti-placeholder tests, and `execution/approval-requests/P00.B00`.
- Before Genesis, do not create `execution/phase-state.yaml`, anything under
  `execution/transitions/`, a Genesis/StateTransition/EvidenceAttachment, valid P00
  completion evidence, or an activation for P00.W01. A pending approval request is
  not phase state.
- Never approve your own contract or gate, invent reviewer identity or attestation,
  edit approval/waiver state, lower a threshold, or turn a missing gate into PASS.
- After Genesis, replay and verify state first. Work only on the single
  `activeWorkUnit`; never select a READY/pending unit or activate the next unit.
  `execution/transitions/` is the append-only authority and `phase-state.yaml` is a
  generated read-only view.
- Keep changes inside the active contract's scope and preserve protected acceptance
  inputs. Gates must fail clearly for a missing evaluator or capability; fixed-success
  placeholders, file-existence-only checks, and hand-entered metrics are forbidden.

## Product and test rules (Plan §26.2)

1. Add no normative assertion without a cited Requirement Catalog source.
2. Keep wire, model, client, and harness failures distinct.
3. Every bug fix gets a minimal fixture; every assertion gets a reference-pass and
   targeted-mutant-fail test.
4. Unit, golden, bootstrap, and gate tests are offline. Live providers are limited to
   dedicated canary workflows using synthetic data.
5. Tests must not read the user's HOME, real `.env` files, keychains, or ambient
   credentials. Use an isolated temporary HOME and deterministic local fixtures.
6. Redact provider payloads and secrets before logs, snapshots, artifacts, or PRs.
7. Do not hide flakes with retry; preserve every attempt and its reason.
8. Never modify a published pack/profile digest.
9. Public schema changes require a migration, compatibility tests, and the applicable
   approved RFC/ADR process.
10. Run the narrowest relevant tests first, then `make verify` and applicable gates;
    report exact commands and results.
11. Do not copy tests of uncertain license. Independently reimplement behavior and
    retain source/provenance facts.

## Security and network boundary

Audit and reproduce only explicitly authorized local source or public open-source
repositories. Use non-destructive local fixtures, test clients, or task-owned
containers/services bound to `127.0.0.1`. Do not scan, fuzz, probe, or exploit public
targets; do not expose a reproduction service publicly; do not create weaponized
payloads. Never use, print, commit, or send real secrets or production data. Network
research and locked dependency fetches must stay within the active contract; gate
execution is offline. Remote pushes/PRs, external publication or outreach, registry
creation, live-provider claims, and use of unapproved paid services require explicit
human authorization.

Evidence must exercise a real code path and remain bound to its source commit and
approved control-plane digests. LLM/scanner output and static suspicion are hypotheses,
not confirmation. Preserve source-to-sink evidence, reproducible local validation,
duplicate checks, minimal remediation, and regression coverage for security findings.
