# RFC-0001: Doctor Compatibility Observations

- **Status:** accepted
- **Date:** 2026-07-13
- **Decider:** @whyiug
- **Review:** implemented behavior and release review

## Problem

"OpenAI compatible" is often inferred from one successful request or similar
field names. That collapses transport, protocol semantics, model behavior, SDK
parsing, and agent behavior into one unsupported claim.

## Accepted v0.1.0 contract

Doctor reports bounded observations at the layer it actually exercised:

1. **Raw endpoint Quick Check** observes HTTP, JSON, SSE, error, tool, and
   lifecycle behavior for one configured OpenAI Chat Completions, OpenAI
   Responses, or Anthropic Messages endpoint shape.
2. **Pinned client reproduction** records one named OpenAI Python SDK behavior
   alongside the correlated raw observation. It proves only that exact case,
   runtime, package version, and fixture.

The two paths do not share or upgrade an evidence claim. A client observation
cannot repair invalid wire evidence, and a raw protocol result cannot establish
general SDK or agent compatibility.

## Outcome and attribution

Selection disposition, execution status, assertion verdict, and finding
attribution remain distinct. Missing evidence is inconclusive, not PASS. A
harness or client failure is not a protocol FAIL. Reports preserve the
candidate, selected, executed, and verdict denominators with the exact built-in
definition identities.

Findings keep wire, provider/model, client/SDK, and harness domains distinct.
When evidence cannot distinguish domains, the result remains unknown rather
than assigning confidence by guesswork.

Doctor does not publish a universal compatibility score, official ranking,
certification, or default winner ordering.

## Security and privacy

Checks require an exact authorized endpoint, hard request and byte bounds,
late secret resolution, and sanitize-before-store evidence. Reports use
bounded excerpts and synthetic reproductions. The loopback demo and release
fixtures do not access public targets.

## Deferred extensions

Generic controlled-provider orchestration, reusable client drivers, real agent
end-to-end tasks, a five-dimension result model, hosted Matrix presentation,
and automated root-cause confidence are not part of v0.1.0. Each needs an
implemented denominator, security boundary, compatibility contract, and
separate review before promotion.

## Compatibility

The accepted contract covers Doctor CLI and report behavior declared by the
v0.1.0 release. It does not stabilize experimental packages, authored packs,
driver protocols, Registry APIs, or hosted-service semantics.
