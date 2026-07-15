# Clients and Drivers

Client compatibility is version-specific. A result names the exact SDK or
agent, version, runtime, driver artifact digest, profile digest, protocol pack,
and support-lock matrix cell.

The source tree now has one deliberately narrow real-client baseline: OpenAI
Python 2.38.0 on CPython 3.12.12 runs a high-level Responses stream against
four deterministic loopback fixtures. Doctor correlates the application-layer
SSE and SDK observation in a checksummed bundle. See the
[reproducible null-output case](../cases/openai-python-responses-null-output.md).

The [llama.cpp Responses A/B](../cases/llama-cpp-responses-pr-21174.md) is a
different kind of evidence: it compares exact upstream implementation commits
using a selected upstream test file plus Doctor's independent raw-wire checks.
It is useful implementation feedback, but it is not a promoted client baseline
or a support-matrix entry.

This baseline does not publish a support matrix and does not test an arbitrary
endpoint. A mock that resembles a client does not prove that the real client
works, while one real pinned client does not prove that other versions work.
Candidate dependency versions may run in nightly jobs but do not silently
replace release-gated previous/current cells.

Before claiming support, each driver/profile needs:

- capability negotiation and contract tests;
- a real client process with bounded environment and network access;
- capture-layer/client-observation correlation;
- version-locked fixtures and expected errors;
- Linux/macOS/Windows coverage appropriate to the tier; and
- a support manifest with explicit gaps and denominator.

No stable client support matrix is published today.
