package catalog

type featureDefinition struct {
	Slug       string
	Taxonomy   string
	SourceRole string
	Locator    string
	Summary    string
	Mutation   string
}

type packDefinition struct {
	Name              string
	Path              string
	Protocol          string
	RequirementPrefix string
	DisplayName       string
	ReleaseTrack      string
	Stability         string
	ScenarioCount     int
	FeatureOffset     int
	SnapshotPath      string
	SnapshotRevision  string
	Sources           []string
	SourceByRole      map[string]string
	Transport         string
	Operation         string
}

// commonFeatures is an independently authored semantic matrix derived from
// Feature selection uses a coprime stride so smaller packs
// sample across the complete taxonomy instead of merely taking a prefix.
var commonFeatures = []featureDefinition{
	{Slug: "endpoint-method", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "endpoint and HTTP method", Summary: "uses the documented endpoint path and HTTP method", Mutation: "replace-endpoint-method"},
	{Slug: "request-content-type", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "request headers", Summary: "sends the documented request content type", Mutation: "drop-request-content-type"},
	{Slug: "stream-accept", Taxonomy: "endpoint-discovery", SourceRole: "streaming", Locator: "streaming request", Summary: "negotiates the documented streaming response media type", Mutation: "replace-stream-accept"},
	{Slug: "reported-model-identity", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "response object", Summary: "preserves the model identity reported by the response", Mutation: "rewrite-reported-model"},
	{Slug: "authentication-header", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "authentication", Summary: "uses the protocol-specific authentication header without logging its value", Mutation: "move-authentication-to-payload"},
	{Slug: "missing-authentication", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "authentication errors", Summary: "keeps a missing-credential response distinct from a successful protocol result", Mutation: "accept-missing-authentication"},
	{Slug: "version-header", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "API versioning", Summary: "preserves an explicitly selected API revision or version header", Mutation: "replace-version-with-floating-value"},
	{Slug: "utf8-roundtrip", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "JSON request and response", Summary: "round-trips UTF-8 text without byte or normalization corruption", Mutation: "truncate-multibyte-codepoint"},
	{Slug: "null-empty-distinction", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "JSON field shapes", Summary: "does not collapse null, empty string, empty array, and empty object", Mutation: "collapse-null-and-empty"},
	{Slug: "unknown-optional-field", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "response extensibility", Summary: "records and safely preserves an unknown optional response field", Mutation: "reject-unknown-optional-field"},
	{Slug: "malformed-json-boundary", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "JSON response", Summary: "classifies malformed or truncated JSON as a wire failure", Mutation: "treat-truncated-json-as-success"},
	{Slug: "response-size-bound", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "response handling", Summary: "enforces the declared response-byte budget before unbounded allocation", Mutation: "disable-response-size-bound"},
	{Slug: "protocol-role-set", Taxonomy: "messages-roles", SourceRole: "general", Locator: "message roles", Summary: "preserves the protocol-specific role vocabulary", Mutation: "coerce-protocol-role"},
	{Slug: "content-part-order", Taxonomy: "messages-roles", SourceRole: "general", Locator: "message content", Summary: "preserves ordered content parts and their native types", Mutation: "sort-content-parts"},
	{Slug: "tool-result-association", Taxonomy: "messages-roles", SourceRole: "tool", Locator: "tool result continuation", Summary: "associates a tool result with the originating call identifier", Mutation: "swap-tool-result-call-id"},
	{Slug: "multi-turn-order", Taxonomy: "messages-roles", SourceRole: "state", Locator: "multi-turn input", Summary: "preserves authored message and item ordering across turns", Mutation: "reverse-multi-turn-order"},
	{Slug: "required-response-envelope", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "response object", Summary: "requires the documented response envelope before evaluating model content", Mutation: "drop-response-envelope"},
	{Slug: "terminal-status", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "completion status", Summary: "maps documented terminal, truncated, refused, and filtered states distinctly", Mutation: "collapse-terminal-status"},
	{Slug: "unique-output-index", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "response output collection", Summary: "requires output indexes and identifiers to remain unambiguous", Mutation: "duplicate-output-index"},
	{Slug: "mixed-output-types", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "response output collection", Summary: "preserves mixed text, tool, refusal, and reasoning output types", Mutation: "drop-nontext-output"},
	{Slug: "stream-media-type", Taxonomy: "streaming", SourceRole: "streaming", Locator: "streaming response", Summary: "validates the documented streaming media type before event parsing", Mutation: "accept-wrong-stream-media-type"},
	{Slug: "arbitrary-rechunk", Taxonomy: "streaming", SourceRole: "streaming", Locator: "stream parsing", Summary: "parses events independently of transport chunk boundaries", Mutation: "bind-parser-to-chunk-boundary"},
	{Slug: "utf8-across-chunks", Taxonomy: "streaming", SourceRole: "streaming", Locator: "stream parsing", Summary: "reassembles UTF-8 code points split across transport chunks", Mutation: "decode-each-chunk-independently"},
	{Slug: "terminal-exactly-once", Taxonomy: "streaming", SourceRole: "streaming", Locator: "stream termination", Summary: "accepts exactly one documented terminal condition", Mutation: "accept-duplicate-terminal"},
	{Slug: "unknown-stream-event", Taxonomy: "streaming", SourceRole: "streaming", Locator: "event extensibility", Summary: "preserves an unknown additive event without crashing the tolerant parser", Mutation: "panic-on-unknown-event"},
	{Slug: "sudden-eof", Taxonomy: "streaming", SourceRole: "streaming", Locator: "stream termination", Summary: "keeps sudden EOF distinct from documented completion", Mutation: "treat-eof-as-completion"},
	{Slug: "post-terminal-data", Taxonomy: "streaming", SourceRole: "streaming", Locator: "stream termination", Summary: "rejects semantic data emitted after the terminal marker", Mutation: "accept-post-terminal-data"},
	{Slug: "single-tool-call", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "function calling flow", Summary: "preserves one declared tool call and its native argument representation", Mutation: "coerce-tool-arguments"},
	{Slug: "tool-choice", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "tool choice", Summary: "preserves none, automatic, required, and named tool-choice modes", Mutation: "collapse-tool-choice"},
	{Slug: "call-id-uniqueness", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "function call identifiers", Summary: "requires tool call identifiers to be unique within the interaction", Mutation: "duplicate-call-id"},
	{Slug: "parallel-tool-order", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "parallel function calling", Summary: "reconstructs parallel calls without cross-wiring indexes or arguments", Mutation: "swap-parallel-call-index"},
	{Slug: "streamed-arguments", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "streaming function calls", Summary: "reassembles streamed function arguments before schema evaluation", Mutation: "drop-argument-delta"},
	{Slug: "tool-error-result", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "tool result", Summary: "preserves an explicit tool-error result separately from transport failure", Mutation: "erase-tool-error-marker"},
	{Slug: "nested-tool-schema", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "function declaration schema", Summary: "preserves nested object, array, required, nullable, and enum constraints", Mutation: "drop-nested-required"},
	{Slug: "tool-loop-bound", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "function calling flow", Summary: "enforces a finite request budget across chained tool calls", Mutation: "disable-tool-loop-bound"},
	{Slug: "json-mode-validity", Taxonomy: "structured-output", SourceRole: "structured", Locator: "JSON mode", Summary: "checks JSON mode for syntactic JSON without overclaiming schema conformance", Mutation: "equate-json-mode-with-schema"},
	{Slug: "schema-required", Taxonomy: "structured-output", SourceRole: "structured", Locator: "structured output schema", Summary: "enforces declared required properties in structured output", Mutation: "ignore-required-property"},
	{Slug: "additional-properties", Taxonomy: "structured-output", SourceRole: "structured", Locator: "structured output schema", Summary: "honors the declared additional-properties policy", Mutation: "allow-forbidden-property"},
	{Slug: "structured-refusal", Taxonomy: "structured-output", SourceRole: "structured", Locator: "structured output refusal", Summary: "keeps refusal handling distinct from schema-valid structured data", Mutation: "validate-refusal-as-schema-output"},
	{Slug: "stateless-continuation", Taxonomy: "state-multiturn", SourceRole: "state", Locator: "conversation state", Summary: "preserves the complete stateless continuation input", Mutation: "drop-continuation-item"},
	{Slug: "previous-id-continuation", Taxonomy: "state-multiturn", SourceRole: "state", Locator: "previous interaction identifier", Summary: "binds continuation to the exact previous interaction identifier", Mutation: "replace-previous-id"},
	{Slug: "storage-mode", Taxonomy: "state-multiturn", SourceRole: "state", Locator: "storage and retention", Summary: "does not conflate explicit stored and stateless modes", Mutation: "force-store-enabled"},
	{Slug: "branching-continuation", Taxonomy: "state-multiturn", SourceRole: "state", Locator: "conversation continuation", Summary: "keeps concurrent branches from one prior interaction distinct", Mutation: "merge-continuation-branches"},
	{Slug: "http-error-status", Taxonomy: "errors-retry", SourceRole: "general", Locator: "error responses", Summary: "preserves authentication, validation, rate-limit, and server status classes", Mutation: "collapse-http-error-status"},
	{Slug: "error-envelope", Taxonomy: "errors-retry", SourceRole: "general", Locator: "error response", Summary: "records the documented error envelope and request identifier", Mutation: "drop-error-envelope"},
	{Slug: "retry-after", Taxonomy: "errors-retry", SourceRole: "general", Locator: "rate limits and retries", Summary: "parses retry guidance without inventing a successful protocol result", Mutation: "ignore-retry-after"},
	{Slug: "nonidempotent-retry", Taxonomy: "errors-retry", SourceRole: "general", Locator: "retry behavior", Summary: "does not unconditionally retry a non-idempotent request", Mutation: "retry-nonidempotent-request"},
	{Slug: "usage-self-consistency", Taxonomy: "usage", SourceRole: "general", Locator: "usage metadata", Summary: "checks documented input, output, and total usage for internal consistency", Mutation: "corrupt-usage-total"},
	{Slug: "streaming-usage-position", Taxonomy: "usage", SourceRole: "streaming", Locator: "streaming usage", Summary: "accepts usage only at protocol-documented stream positions", Mutation: "move-usage-after-terminal"},
	{Slug: "inline-media-canary", Taxonomy: "multimodal", SourceRole: "general", Locator: "multimodal input", Summary: "preserves a tiny inline media canary and its MIME type without network fetch", Mutation: "rewrite-inline-media-mime"},
	{Slug: "opaque-reasoning-continuation", Taxonomy: "reasoning-thinking", SourceRole: "state", Locator: "reasoning continuation", Summary: "round-trips opaque reasoning artifacts without inspecting hidden chain of thought", Mutation: "alter-opaque-reasoning-artifact"},
	{Slug: "public-reasoning-summary", Taxonomy: "reasoning-thinking", SourceRole: "streaming", Locator: "reasoning summary", Summary: "keeps a public reasoning summary separate from hidden reasoning", Mutation: "expose-hidden-reasoning-as-summary"},
	{Slug: "cancel-and-timeout", Taxonomy: "cancellation-resources", SourceRole: "streaming", Locator: "stream cancellation", Summary: "distinguishes client cancellation, timeout, and normal completion within budget", Mutation: "map-cancel-to-completion"},
}

var mcpFeatures = []featureDefinition{
	{Slug: "jsonrpc-version", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "Base Protocol / JSON-RPC Messages", Summary: "preserves the exact JSON-RPC version marker", Mutation: "replace-jsonrpc-version"},
	{Slug: "request-id-correlation", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "Base Protocol / Requests", Summary: "correlates every response or error with its request identifier", Mutation: "swap-jsonrpc-request-id"},
	{Slug: "notification-without-id", Taxonomy: "messages-roles", SourceRole: "general", Locator: "Base Protocol / Notifications", Summary: "keeps notifications identifier-free and response-free", Mutation: "add-notification-id"},
	{Slug: "error-object-shape", Taxonomy: "errors-retry", SourceRole: "general", Locator: "Base Protocol / Errors", Summary: "preserves JSON-RPC error code, message, and optional data", Mutation: "drop-jsonrpc-error-code"},
	{Slug: "initialize-first", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Lifecycle / Initialization", Summary: "requires initialization before ordinary protocol operations", Mutation: "allow-operation-before-initialize"},
	{Slug: "protocol-version-negotiation", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "Lifecycle / Version Negotiation", Summary: "negotiates an exact supported protocol revision", Mutation: "accept-floating-protocol-version"},
	{Slug: "initialized-notification", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Lifecycle / Initialization", Summary: "observes the initialized notification after successful negotiation", Mutation: "drop-initialized-notification"},
	{Slug: "capability-declaration", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Lifecycle / Capability Negotiation", Summary: "gates optional operations on negotiated capabilities", Mutation: "ignore-capability-negotiation"},
	{Slug: "stdio-framing", Taxonomy: "streaming", SourceRole: "general", Locator: "Transports / stdio", Summary: "frames each stdio message without mixing protocol bytes and logs", Mutation: "write-log-to-stdio-protocol"},
	{Slug: "stdio-no-embedded-newline", Taxonomy: "streaming", SourceRole: "general", Locator: "Transports / stdio", Summary: "treats the stdio delimiter independently of JSON string escapes", Mutation: "split-stdio-json-string"},
	{Slug: "streamable-http-methods", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Transports / Streamable HTTP", Summary: "uses the documented Streamable HTTP request methods", Mutation: "replace-streamable-http-method"},
	{Slug: "streamable-http-session", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Transports / Session Management", Summary: "binds requests to the negotiated MCP session identifier", Mutation: "reuse-wrong-mcp-session"},
	{Slug: "protocol-version-header", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "Transports / Protocol Version Header", Summary: "sends the exact MCP protocol version header where required", Mutation: "drop-mcp-version-header"},
	{Slug: "last-event-id", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Transports / Resumability", Summary: "uses an exact last-event identifier for supported stream resumption", Mutation: "replace-last-event-id"},
	{Slug: "origin-validation", Taxonomy: "authentication-versioning", SourceRole: "general", Locator: "Transports / Security Warning", Summary: "validates Origin to mitigate DNS rebinding for local servers", Mutation: "disable-origin-validation"},
	{Slug: "tools-list", Taxonomy: "tool-function-calling", SourceRole: "general", Locator: "Server Features / Tools / Listing Tools", Summary: "preserves tool names, descriptions, and input schemas from tools/list", Mutation: "drop-tool-input-schema"},
	{Slug: "tools-pagination", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Utilities / Pagination", Summary: "advances tool-list pagination with the exact returned cursor", Mutation: "reuse-pagination-cursor"},
	{Slug: "tools-call", Taxonomy: "tool-function-calling", SourceRole: "general", Locator: "Server Features / Tools / Calling Tools", Summary: "passes tool name and arguments without cross-call substitution", Mutation: "swap-mcp-tool-arguments"},
	{Slug: "tool-is-error", Taxonomy: "tool-function-calling", SourceRole: "general", Locator: "Server Features / Tools / Tool Result", Summary: "preserves the tool-level isError marker separately from protocol error", Mutation: "erase-mcp-is-error"},
	{Slug: "tool-structured-content", Taxonomy: "structured-output", SourceRole: "general", Locator: "Server Features / Tools / Structured Content", Summary: "validates structuredContent against the declared output schema", Mutation: "skip-output-schema-validation"},
	{Slug: "resources-list", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Server Features / Resources", Summary: "preserves resource URIs and metadata from resources/list", Mutation: "rewrite-resource-uri"},
	{Slug: "resources-read", Taxonomy: "multimodal", SourceRole: "general", Locator: "Server Features / Resources / Reading Resources", Summary: "preserves text or blob resource content with its MIME type", Mutation: "collapse-resource-content-type"},
	{Slug: "resource-subscription", Taxonomy: "streaming", SourceRole: "general", Locator: "Server Features / Resources / Subscriptions", Summary: "correlates resource update notifications with subscribed URIs", Mutation: "notify-unsubscribed-resource"},
	{Slug: "prompts-list", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Server Features / Prompts", Summary: "preserves prompt names, arguments, and pagination", Mutation: "drop-required-prompt-argument"},
	{Slug: "prompts-get", Taxonomy: "messages-roles", SourceRole: "general", Locator: "Server Features / Prompts / Getting a Prompt", Summary: "preserves ordered prompt messages and content types", Mutation: "reorder-prompt-messages"},
	{Slug: "roots-list", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Client Features / Roots", Summary: "exposes only the client roots negotiated for the session", Mutation: "inject-unnegotiated-root"},
	{Slug: "sampling-create-message", Taxonomy: "messages-roles", SourceRole: "general", Locator: "Client Features / Sampling", Summary: "preserves sampling messages, model preferences, and limits", Mutation: "drop-sampling-token-limit"},
	{Slug: "elicitation-result", Taxonomy: "structured-output", SourceRole: "general", Locator: "Client Features / Elicitation", Summary: "distinguishes accepted, declined, and cancelled elicitation results", Mutation: "collapse-elicitation-action"},
	{Slug: "logging-level", Taxonomy: "errors-retry", SourceRole: "general", Locator: "Server Features / Logging", Summary: "honors the selected logging level without emitting protocol secrets", Mutation: "ignore-logging-level"},
	{Slug: "progress-token", Taxonomy: "streaming", SourceRole: "general", Locator: "Utilities / Progress", Summary: "correlates progress notifications with their exact progress token", Mutation: "swap-progress-token"},
	{Slug: "request-cancellation", Taxonomy: "cancellation-resources", SourceRole: "general", Locator: "Utilities / Cancellation", Summary: "cancels only the request named by the cancellation notification", Mutation: "cancel-wrong-request"},
	{Slug: "task-lifecycle", Taxonomy: "state-multiturn", SourceRole: "general", Locator: "Utilities / Tasks", Summary: "preserves task status and terminal lifecycle transitions", Mutation: "reopen-terminal-task"},
	{Slug: "unknown-method", Taxonomy: "errors-retry", SourceRole: "general", Locator: "Base Protocol / Errors", Summary: "returns the documented method-not-found error for unknown requests", Mutation: "accept-unknown-method"},
	{Slug: "unknown-notification", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "Base Protocol / Notifications", Summary: "ignores an unknown notification without inventing a response", Mutation: "respond-to-unknown-notification"},
	{Slug: "message-size-budget", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "Base Protocol / Messages", Summary: "bounds message size before allocating unbounded parser state", Mutation: "disable-mcp-message-bound"},
	{Slug: "shutdown-cleanup", Taxonomy: "cancellation-resources", SourceRole: "general", Locator: "Lifecycle / Shutdown", Summary: "releases session resources when the transport closes", Mutation: "retain-session-after-close"},
}

var ollamaFeatures = []featureDefinition{
	{Slug: "native-base-url", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Introduction / Base URL", Summary: "uses the native /api base path rather than silently treating /v1 as equivalent", Mutation: "rewrite-native-base-to-v1"},
	{Slug: "generate-endpoint", Taxonomy: "endpoint-discovery", SourceRole: "general", Locator: "Introduction / Example request", Summary: "uses the native generate operation with its documented request shape", Mutation: "replace-generate-request-shape"},
	{Slug: "chat-messages", Taxonomy: "messages-roles", SourceRole: "tool", Locator: "Tool calling / Multi-turn tool calling", Summary: "preserves native chat messages across tool-call turns", Mutation: "drop-tool-turn-message"},
	{Slug: "ndjson-media-type", Taxonomy: "streaming", SourceRole: "streaming", Locator: "Streaming", Summary: "parses native streaming as newline-delimited JSON", Mutation: "parse-ndjson-as-sse"},
	{Slug: "stream-default", Taxonomy: "streaming", SourceRole: "streaming", Locator: "Streaming / Disabling streaming", Summary: "preserves the native default-streaming behavior and explicit stream false override", Mutation: "invert-stream-default"},
	{Slug: "ndjson-rechunk", Taxonomy: "streaming", SourceRole: "streaming", Locator: "Streaming", Summary: "parses NDJSON records independently of network chunk boundaries", Mutation: "bind-ndjson-to-network-chunk"},
	{Slug: "done-terminal", Taxonomy: "streaming", SourceRole: "streaming", Locator: "Streaming", Summary: "requires the native done marker before declaring completion", Mutation: "treat-eof-as-done"},
	{Slug: "done-reason", Taxonomy: "nonstream-output", SourceRole: "streaming", Locator: "Streaming example", Summary: "preserves the native done reason from the terminal record", Mutation: "drop-done-reason"},
	{Slug: "response-content", Taxonomy: "nonstream-output", SourceRole: "general", Locator: "Introduction / Example request", Summary: "preserves native response content without OpenAI envelope coercion", Mutation: "wrap-native-response-as-choice"},
	{Slug: "tool-declarations", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "Tool calling / Passing tools", Summary: "preserves native tool declarations and parameter schemas", Mutation: "drop-native-tool-schema"},
	{Slug: "tool-call-name", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "Tool calling", Summary: "preserves the native function name in each tool call", Mutation: "rewrite-native-tool-name"},
	{Slug: "tool-call-arguments", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "Tool calling", Summary: "preserves native tool arguments as the documented JSON value", Mutation: "stringify-native-tool-arguments"},
	{Slug: "parallel-tools", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "Tool calling / Parallel tool calling", Summary: "keeps parallel native tool calls distinct", Mutation: "merge-parallel-native-tools"},
	{Slug: "tool-result-turn", Taxonomy: "tool-function-calling", SourceRole: "tool", Locator: "Tool calling / Multi-turn tool calling", Summary: "returns tool results in the documented continuation turn", Mutation: "attach-tool-result-to-wrong-turn"},
	{Slug: "streamed-tool-call", Taxonomy: "tool-function-calling", SourceRole: "streaming", Locator: "Streaming / Tool calling", Summary: "accumulates streamed tool call fields before execution", Mutation: "execute-partial-tool-call"},
	{Slug: "thinking-field", Taxonomy: "reasoning-thinking", SourceRole: "streaming", Locator: "Streaming / Thinking", Summary: "keeps the public native thinking field separate from response content", Mutation: "merge-thinking-into-content"},
	{Slug: "thinking-history", Taxonomy: "reasoning-thinking", SourceRole: "tool", Locator: "Tool calling / Multi-turn tool calling", Summary: "preserves documented thinking content needed for native continuation", Mutation: "drop-native-thinking-history"},
	{Slug: "format-json", Taxonomy: "structured-output", SourceRole: "general", Locator: "API request options", Summary: "keeps native structured-output format distinct from plain text", Mutation: "ignore-native-format"},
	{Slug: "usage-duration-fields", Taxonomy: "usage", SourceRole: "general", Locator: "API response metadata", Summary: "preserves native duration and evaluation-count metadata", Mutation: "swap-native-usage-fields"},
	{Slug: "error-envelope", Taxonomy: "errors-retry", SourceRole: "general", Locator: "API errors", Summary: "keeps a native API error distinct from a successful generation record", Mutation: "accept-native-error-as-output"},
	{Slug: "utf8-content", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "API request and response", Summary: "round-trips UTF-8 native content without corruption", Mutation: "truncate-native-utf8"},
	{Slug: "unknown-field", Taxonomy: "http-json-forward-compatibility", SourceRole: "general", Locator: "API response", Summary: "records an unknown additive native response field without crashing", Mutation: "reject-native-unknown-field"},
	{Slug: "inline-image", Taxonomy: "multimodal", SourceRole: "general", Locator: "API request options", Summary: "preserves a tiny inline image canary without external retrieval", Mutation: "corrupt-native-inline-image"},
	{Slug: "client-cancel", Taxonomy: "cancellation-resources", SourceRole: "streaming", Locator: "Streaming", Summary: "stops stream consumption on client cancellation without claiming completion", Mutation: "map-native-cancel-to-done"},
}

var packDefinitions = []packDefinition{
	{
		Name: "openai-chat", Path: "packs/openai-chat", Protocol: "openai-chat", RequirementPrefix: "OAI-CHAT-REQ", DisplayName: "OpenAI Chat Completions HTTP/SSE",
		ReleaseTrack: "core-candidate", Stability: "incubating", ScenarioCount: 42, FeatureOffset: 0,
		SnapshotPath: "specs/protocol-snapshots/openai-chat-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"openai-chat-function-calling", "openai-chat-streaming", "openai-chat-structured-output"},
		SourceByRole: map[string]string{"general": "openai-chat-function-calling", "streaming": "openai-chat-streaming", "tool": "openai-chat-function-calling", "structured": "openai-chat-structured-output", "state": "openai-chat-function-calling"},
		Transport:    "http-sse", Operation: "chat.completions.create",
	},
	{
		Name: "openai-responses-http", Path: "packs/openai-responses-http", Protocol: "openai-responses-http", RequirementPrefix: "OAI-RESP-REQ", DisplayName: "OpenAI Responses HTTP/SSE",
		ReleaseTrack: "core-candidate", Stability: "incubating", ScenarioCount: 48, FeatureOffset: 7,
		SnapshotPath: "specs/protocol-snapshots/openai-responses-http-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"openai-responses-function-calling", "openai-responses-streaming", "openai-responses-migration", "openai-responses-structured-output"},
		SourceByRole: map[string]string{"general": "openai-responses-migration", "streaming": "openai-responses-streaming", "tool": "openai-responses-function-calling", "structured": "openai-responses-structured-output", "state": "openai-responses-migration"},
		Transport:    "http-sse", Operation: "responses.create",
	},
	{
		Name: "anthropic-messages", Path: "packs/anthropic-messages", Protocol: "anthropic-messages", RequirementPrefix: "ANTH-MSG-REQ", DisplayName: "Anthropic Messages HTTP/SSE",
		ReleaseTrack: "core-candidate", Stability: "incubating", ScenarioCount: 42, FeatureOffset: 13,
		SnapshotPath: "specs/protocol-snapshots/anthropic-messages-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"anthropic-api-overview", "anthropic-messages-guide", "anthropic-streaming", "anthropic-tool-use"},
		SourceByRole: map[string]string{"general": "anthropic-messages-guide", "streaming": "anthropic-streaming", "tool": "anthropic-tool-use", "structured": "anthropic-tool-use", "state": "anthropic-messages-guide"},
		Transport:    "http-sse", Operation: "messages.create",
	},
	{
		Name: "google-generate-content", Path: "packs/extensions/google-generate-content", Protocol: "google-generate-content", RequirementPrefix: "GGL-GEN-REQ", DisplayName: "Google generateContent",
		ReleaseTrack: "required-experimental", Stability: "experimental", ScenarioCount: 36, FeatureOffset: 19,
		SnapshotPath: "specs/protocol-snapshots/google-generate-content-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"google-generate-api-overview", "google-generate-api-reference", "google-generate-function-calling", "google-generate-streaming"},
		SourceByRole: map[string]string{"general": "google-generate-api-reference", "streaming": "google-generate-streaming", "tool": "google-generate-function-calling", "structured": "google-generate-api-reference", "state": "google-generate-api-reference"},
		Transport:    "http-sse", Operation: "models.generateContent",
	},
	{
		Name: "google-interactions", Path: "packs/extensions/google-interactions", Protocol: "google-interactions", RequirementPrefix: "GGL-INT-REQ", DisplayName: "Google Interactions",
		ReleaseTrack: "required-experimental", Stability: "experimental", ScenarioCount: 32, FeatureOffset: 23,
		SnapshotPath: "specs/protocol-snapshots/google-interactions-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"google-interactions-api", "google-interactions-function-calling", "google-interactions-overview", "google-interactions-streaming"},
		SourceByRole: map[string]string{"general": "google-interactions-api", "streaming": "google-interactions-streaming", "tool": "google-interactions-function-calling", "structured": "google-interactions-api", "state": "google-interactions-overview"},
		Transport:    "http-sse", Operation: "interactions.create",
	},
	{
		Name: "mcp-2025-11-25", Path: "packs/extensions/mcp-2025-11-25", Protocol: "mcp-2025-11-25", RequirementPrefix: "MCP-20251125-REQ", DisplayName: "Model Context Protocol 2025-11-25",
		ReleaseTrack: "required-experimental", Stability: "experimental", ScenarioCount: 36,
		SnapshotPath: "specs/protocol-snapshots/mcp-2025-11-25.json", SnapshotRevision: "2025-11-25",
		Sources: []string{"mcp-2025-11-25-spec"}, SourceByRole: map[string]string{"general": "mcp-2025-11-25-spec"},
		Transport: "jsonrpc-stdio-streamable-http", Operation: "mcp.request",
	},
	{
		Name: "ollama-native", Path: "packs/extensions/ollama-native", Protocol: "ollama-native", RequirementPrefix: "OLLAMA-REQ", DisplayName: "Ollama native API",
		ReleaseTrack: "required-experimental", Stability: "experimental", ScenarioCount: 24,
		SnapshotPath: "specs/protocol-snapshots/ollama-native-2026-07-11.json", SnapshotRevision: "content-lock-set-2026-07-11",
		Sources:      []string{"ollama-api-introduction", "ollama-api-streaming", "ollama-tool-calling"},
		SourceByRole: map[string]string{"general": "ollama-api-introduction", "streaming": "ollama-api-streaming", "tool": "ollama-tool-calling", "structured": "ollama-api-introduction", "state": "ollama-tool-calling"},
		Transport:    "http-ndjson", Operation: "ollama.native",
	},
}

func featuresForPack(pack packDefinition) []featureDefinition {
	switch pack.Protocol {
	case "mcp-2025-11-25":
		return mcpFeatures
	case "ollama-native":
		return ollamaFeatures
	default:
		selected := make([]featureDefinition, 0, pack.ScenarioCount)
		const stride = 17 // coprime with the current common feature-set size
		for index := 0; index < pack.ScenarioCount; index++ {
			selected = append(selected, commonFeatures[(pack.FeatureOffset+index*stride)%len(commonFeatures)])
		}
		return selected
	}
}
