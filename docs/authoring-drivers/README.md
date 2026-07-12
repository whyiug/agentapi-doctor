# Authoring Drivers

A driver is a version-pinned process adapter for a real transport, SDK, or
agent client. It executes and observes; it does not decide normative protocol
truth.

## Contract

The proposed driver protocol uses JSON-RPC 2.0 semantics over bounded NDJSON
stdio with explicit initialization, capability negotiation, invocation,
observation, cancellation, cleanup, and shutdown states. Message size, sequence,
invocation/attempt IDs, and lifecycle are validated. Wire, model, client, and
harness errors remain separate classes.

## Isolation

- launch in an isolated work directory and temporary home;
- pass only allowlisted environment entries and scoped secret material;
- deny undeclared file, path, subprocess, and network access;
- bind local fixtures to loopback;
- meter processes, requests, bytes, tokens, time, and artifacts;
- cancel and clean only task-owned resources; and
- never log a secret or full private provider payload.

## Version and tests

Driver identity includes ecosystem/package, version, runtime, artifact digest,
capabilities, and support-lock matrix cell. Contract tests cover valid flows,
malformed frames, unknown methods, out-of-order observations, duplicate IDs,
cancellation, timeout, cleanup, and redaction. Real client execution is needed
for a support claim; a mock is insufficient.

The in-tree candidate protocol currently lives under `pkg/driverprotocol`; it
is not a stable external ABI.
