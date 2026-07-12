# Compatibility Layers

“The request returned 200” is not enough to establish agent compatibility.
AgentAPI Doctor separates both test planes and fault domains so evidence is not
attributed to the wrong component.

## Test planes

1. **Endpoint black-box** checks observable HTTP, JSON, streaming, tool, error,
   and state behavior.
2. **Controlled backend/provider CI** uses a known reference or mutant backend
   to isolate provider behavior from client parsing.
3. **Client fixture replay** runs a real SDK or client against bounded local
   evidence and records the client-observed result.
4. **Real agent end-to-end** validates the full task loop only after lower
   layers can explain failures and side effects are controlled.

No higher plane repairs or hides a lower-plane failure. A browser screenshot,
LLM judgment, or successful task completion is not a substitute for wire and
client evidence.

## Fault domains

- **Wire/transport:** status, headers, framing, SSE, JSON, cancellation, TLS,
  redirects, and byte-level behavior.
- **Provider/model:** emitted content, tool choices, structured-output
  adherence, usage, and model-dependent behavior.
- **Client/SDK:** parsing, validation, buffering, retry, event handling, and
  state transitions observed by the named client version.
- **Harness/task:** fixture, oracle, timeout, environment, or task logic.

When evidence cannot distinguish these domains, the correct attribution is
unknown. The tool must not guess a provider fault from a client exception.

## Outcome separation

Execution status and compatibility verdict are different axes. A scenario can
be planned but skipped, fail to execute because the harness broke, execute and
produce an inconclusive assertion, or execute and yield a supported verdict.
Candidate, applicable, and executed denominators remain explicit so skipped or
unavailable cases cannot inflate a score.

Compatibility is reported across protocol, semantic, client, operational, and
evidence dimensions. There is no single official “winner” score.
