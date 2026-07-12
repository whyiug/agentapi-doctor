# OpenAI Responses

The planned Responses pack models typed items and events, item lifecycle,
state/continuation identifiers, function calls and outputs, streaming order,
errors, usage, and unknown-event forward compatibility. It does not reduce a
Responses stream to Chat-style text chunks.

State-machine assertions must point to capture-layer events and preserve the
provider-native event type. Codex-specific consumer expectations belong in a
Profile, not in the protocol core. No stable Responses pack is published yet.
