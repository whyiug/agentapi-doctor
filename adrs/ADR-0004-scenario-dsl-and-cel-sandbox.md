# ADR-0004: Scenario DSL and CEL sandbox

- **Status:** proposed
- **Deciders:** none recorded
- **Review:** none recorded

## Context

Conformance scenarios must be readable, reviewable, source-linked, and
deterministic while expressing multi-step protocol behavior. Allowing arbitrary
Python, JavaScript, shell, network, or filesystem code inside a pack would make
permissions, budgets, evidence, and repeatability impossible to reason about.

The complete candidate model is in
[RFC-0003](../rfcs/0003-scenario-and-pack-model.md), with contributor guidance
in [authoring packs](../docs/authoring-packs/README.md).

## Proposed decision

- Author scenarios as YAML or JSON validated by JSON Schema 2020-12 with
  unknown fields rejected by default.
- Compile authored scenarios into deterministic typed IR, then into an
  IntentPlan and a capability-resolved plan. Compilation may remove an
  unauthorized or unavailable branch but may not add unrequested work.
- Allow only a reviewed, finite catalog of declarative operations. Arbitrary
  scripts and direct filesystem, process, or network calls are not scenario
  operations; such behavior belongs behind separately reviewed driver or
  harness capabilities.
- Use CEL-Go for composition and assertions with a closed typed environment,
  allowlisted versioned built-ins, deterministic inputs, bounded expression
  size/depth and computation cost, and no I/O, clock, randomness, reflection,
  dynamic loading, or ambient environment access.
- Bind each assertion to a Requirement Catalog entry and the exact evaluator,
  built-in, schema, pack, and source digests used to compile it.
- Reject unknown functions, types, capabilities, unbounded work, unsafe paths,
  missing finalizers, and budget expansion during compilation.
- Keep compile/type/cost/sandbox errors separate from an executed assertion's
  compatibility verdict.

## Consequences

The DSL is less expressive than a general-purpose language and every new
operation or built-in needs contract review and fixtures. In exchange, a pack
can be statically reviewed, planned without contacting a target, bounded before
secret resolution, and replayed against immutable inputs.

Some client or operating-system behavior will require drivers. That does not
grant the pack the driver's permissions; capability negotiation and the
resolved plan remain the upper bound.

## Alternatives

- General-purpose scripts maximize flexibility but defeat deterministic
  compilation, isolation, and review.
- Hard-coding every scenario in Go narrows execution risk but prevents a
  reviewable ecosystem format and immutable pack distribution.
- JSONPath-only assertions are easy to sandbox but insufficient for typed
  state-machine and cross-event checks.
- An LLM judge is nondeterministic and is unsuitable as a normative protocol
  oracle.

## Validation before acceptance

Require deterministic compile goldens, schema and path errors, type and cost
limits, forbidden-function and I/O mutants, capability and budget mutants, and
reference-pass/targeted-mutant-fail coverage for every normative assertion.
Run all gate fixtures offline with an isolated home and no ambient credentials.
An external protocol review is required before any pack is called accepted.
