# Roadmap

AgentAPI Doctor uses evidence-based exit gates, not promised calendar dates.
The detailed requirements and phase dependencies are in
[agentapi-doctor-Plan.md](agentapi-doctor-Plan.md). This summary is not a claim
that a phase has passed.

If `execution/phase-state.yaml` is absent, the project is still before
authoritative Genesis and no coding phase or work unit is active.

| Phase | Intended result | Completion evidence |
|---|---|---|
| P00 — Validation and Bootstrap | Differentiation, lawful corpus, risk-retirement experiments, provisional RFC/security/data design | Protected P00 gates plus real external and human review |
| P01 — Contracts and Catalog | Stable candidate schemas, identity, canonicalization, requirements and source lock | Schema, digest, old-reader and independent protocol review evidence |
| P02 — Kernel and Evidence | Planner, budgets, capture, redaction, CAS and replay | Deterministic, cross-platform, privacy and security gates |
| P03 — Core Protocol Conformance | OpenAI Chat/Responses and Anthropic packs with reference/mutant coverage | Scenario, mutation, historical and protocol-review thresholds |
| P04 — Client-observed Runtime | Real SDK/agent drivers, profiles, sandbox and support matrix | Locked client matrix and real adopter validation |
| P05 — Diagnosis and CI Product | Attribution, minimization, reports, baselines and GitHub integration | Ground-truth quality and actual upstream/CI adoption evidence |
| P06 — Protocol Expansion | Google, MCP and explicit external/dialect adapters | Requirement/reference/mutant gates and Pack Maintainer review |
| P07 — Trusted Registry | Signed observations, ownership, ingest, dispute, self-host and operations | Security, privacy, recovery, consistency and external review |
| P08 — GA Hardening | Contract freeze, migration, release chain, documentation and governance | Two RCs over at least six weeks, adopter window and TSC vote |

The project is GA-ready only when P00–P08 are converged and every applicable
Definition-of-Done criterion has real evidence. Code volume, a green bootstrap
test, stars, or closed issues are not substitutes.

Priorities may change only through the scope/RFC process. A pivot that preserves
open schemas, fixtures, and evidence is preferable to maintaining an
unvalidated hosted service.
