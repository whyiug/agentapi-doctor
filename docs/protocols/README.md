# Protocol Families

The v0.1.x Doctor Quick Check sends four bounded raw HTTP checks for one of
three endpoint shapes:

- [OpenAI Chat Completions](openai-chat/README.md)
- [OpenAI Responses](openai-responses/README.md)
- [Anthropic Messages](anthropic-messages/README.md)

These checks produce reproducible protocol observations. Their built-in
interpretations remain versioned candidate material pending source review;
they do not certify an endpoint or establish full SDK, model, or agent
compatibility.

The following pages are design research, not v0.1.x support claims:

- [Google APIs](google/README.md)
- [Model Context Protocol](mcp/README.md)

Promoting a protocol pack requires locked primary sources, Requirement Catalog
records, reference-pass tests, targeted-mutant-fail tests, and an explicit
release support declaration.
