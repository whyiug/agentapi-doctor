# RFC-0001: Compatibility Layers

- **Status:** provisional
- **Review:** none recorded
- **Target phase:** P00 design input; later schema/pack contracts require
  separate approval

## Problem

“OpenAI compatible” is often inferred from a successful request or field-name
similarity. That collapses transport, protocol semantics, model behavior, SDK
parsing, and agent task behavior into one result. It produces false attribution
and makes failures difficult for maintainers to reproduce.

## Goals

- preserve the layer at which behavior was observed;
- distinguish execution failure from compatibility verdict;
- report multiple compatibility dimensions without a universal score;
- support controlled attribution experiments; and
- keep insufficient evidence explicitly unknown.

## Proposal

### Four test planes

1. **Endpoint black-box** observes HTTP, JSON, SSE, errors, tools, state, and
   resource behavior at the endpoint boundary.
2. **Controlled backend/provider CI** places a known reference or targeted
   mutant behind the client-facing endpoint.
3. **Client fixture replay** runs the exact SDK/agent driver and correlates its
   observation to capture-layer evidence.
4. **Real agent E2E** evaluates a bounded task loop after lower planes can
   explain transport and client behavior.

The planes may share a scenario intent but do not share an evidence claim. A
later plane cannot repair evidence from an earlier plane.

### Fault domains

Findings distinguish wire/transport, provider/model, client/SDK, and
harness/task domains. Attribution includes confidence, calibrated version,
alternative domains, minimal evidence references, and an ambiguity ID when
needed. Evidence that cannot distinguish domains yields `UNKNOWN_FAULT_DOMAIN`.

### Compatibility dimensions

Results remain separate across:

- protocol conformance;
- semantic/model behavior;
- client-observed compatibility;
- operational behavior; and
- evidence/reproducibility quality.

The UI and Registry must not synthesize a default “official” total score. Every
dimension displays candidate, applicable, and executed denominators.

### Outcome model

Planning disposition (`execute`, `skip`, `not_applicable`), execution status,
assertion verdict (`pass`, `fail`, `inconclusive`, `skip` where contractually
allowed), and finding attribution are distinct fields. Harness failure cannot
become protocol FAIL, and unavailable capability cannot become PASS.

## Security and privacy

E2E and client planes can exercise tools, files, networks, and secrets. They
therefore require explicit side-effect policy, target authorization, hard
budgets, driver isolation, and write-before-redact evidence. Public reports use
bounded excerpts and synthetic repros.

## Alternatives considered

- **One endpoint score:** easy to market but hides denominators and fault
  boundaries; rejected as the normative model.
- **Only raw wire conformance:** valuable but cannot establish real client
  behavior; retained as one plane rather than the whole product.
- **LLM-as-judge attribution:** useful for hypotheses but nondeterministic and
  not source-backed; excluded from normative verdicts.

## Unresolved questions

- exact confidence calibration and display thresholds;
- which E2E tasks are safe and stable enough for a release denominator; and
- how the UI presents five dimensions accessibly without implying ranking.

## Evidence required before acceptance

P00 must reproduce a lawful corpus, demonstrate correlated capture/client views,
show unknown behavior under insufficient evidence, and receive substantive
external review. None of that evidence is asserted by this draft.
