# OpenAI Chat Completions

The planned pack treats request/response JSON, SSE chunks, tool-call deltas,
finish reasons, usage, errors, and unknown fields as independently testable
surfaces. Streaming assertions preserve chunk order and incremental tool
arguments rather than comparing only the final assembled text.

Chat semantics are not used as an implicit fallback for a client whose wire API
is Responses-only. No stable Chat pack is published yet; source revisions and
support tiers will appear in the Requirement Catalog and generated reference
only after review.
