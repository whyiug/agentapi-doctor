# ADR-0009: Result dimension and no-single-score

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

“Compatible” can refer to transport framing, protocol semantics, model
behavior, a particular SDK or agent, operational reliability, or evidence
quality. Collapsing those observations into one score hides denominators,
unknowns, execution failures, and fault domains. It can also create a misleading
ranking that a sponsor or provider can optimize without fixing compatibility.

The layered model comes from
[RFC-0001](../rfcs/0001-compatibility-layers.md), and the result fields from
[RFC-0002](../rfcs/0002-evidence-and-result-schema.md).

## Proposed decision

- Report five independent top-level dimensions: Transport, Protocol, Model
  Behavior, Client Compatibility, and Operational Reliability. Protocol
  separately exposes wire syntax and interaction semantics.
- Keep planning disposition (`execute`, `skip`, `not_applicable`), execution
  status, assertion verdict, and finding attribution as distinct fields. A
  harness or driver error cannot become a protocol FAIL, and missing evidence
  cannot become PASS.
- For every dimension show the candidate, applicable, selected, executed, and
  verdict denominators and their exact pack/profile digest. Statistical claims
  include repetitions, sample size, method, and uncertainty.
- Represent unknown, inconclusive, unsupported, not run, skipped, errored,
  cancelled, and budget-exhausted states explicitly rather than coercing them
  to zero or pass.
- Do not publish a normative universal total score, “official compatibility”
  rank, or default winner ordering. Filters and user-selected comparisons may
  display dimensions but cannot rewrite the underlying result.
- Bind badges and summaries to the named profile and full pack version/digest,
  and keep trust/provenance labels separate from technical verdicts.
- Allow a future derived visualization only if its formula, inputs,
  denominators, uncertainty, and non-normative status are explicit and it
  cannot replace the source dimensions.

## Consequences

Reports and matrices are less reducible to a marketing number, and users must
inspect dimensions relevant to their client and workload. In return, failures
remain attributable and unavailable tests cannot inflate compatibility.

The UI needs accessible multi-dimensional displays and careful comparison
rules. APIs must preserve all source fields so a consumer cannot mistake a
derived presentation for the signed result.

## Alternatives

- A weighted total is easy to sort but embeds disputed values, hides missing
  data, and changes when weights or denominators change.
- A strict all-or-nothing badge is useful for a narrowly named profile but is
  misleading as a universal product result.
- Protocol-only PASS ignores real SDK/client behavior.
- Client-only PASS cannot distinguish a tolerant client from a conforming
  endpoint.

## Validation before acceptance

Use fixtures for every planning, execution, verdict, and attribution state;
prove that errors and missing cases never count as pass. Test denominator
sensitivity, digest-incompatible comparisons, statistical uncertainty, badge
specificity, API round trips, and accessible matrix rendering. Conduct user
research on whether maintainers can interpret failures without inferring a
hidden total. Candidate UI or schema tests are not acceptance.
