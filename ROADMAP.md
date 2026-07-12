# Roadmap

AgentAPI Doctor follows outcome-based priorities rather than fixed delivery
dates. The roadmap may change as users contribute evidence and real integration
needs.

## Available from source

- Local diagnostics for OpenAI Chat Completions, OpenAI Responses, and
  Anthropic Messages protocol slices.
- Deterministic reference and targeted-mutant fixtures.
- Evidence redaction, content-addressed storage, run comparison, baselines, and
  terminal/JSON/JUnit/SARIF/Markdown/HTML reports.
- A single-node self-hosted Registry, static Matrix UI, Docker/Compose setup,
  schemas, OpenAPI, CI integrations, and release packaging automation.

## Near term

- Publish the first signed prerelease and verify clean installation on Linux,
  macOS, and Windows.
- Improve CLI onboarding, diagnostics, and actionable remediation guidance.
- Expand executable protocol cases while keeping metadata and runnable coverage
  clearly separated.
- Exercise the GitHub Action and reusable workflow in real downstream test
  repositories.
- Stabilize configuration, result, and report schemas before a 1.0 release.

## Later

- Add locked SDK and agent-client drivers with explicit version support.
- Add more protocol families through independently versioned packs.
- Strengthen sandboxing and network isolation for untrusted drivers.
- Mature Registry verification, ownership, dispute, privacy, backup, and
  operational controls before any hosted service is offered.
- Build a community-maintained compatibility matrix from consented, verifiable
  observations.

Priorities are discussed through issues, pull requests, and RFCs. A checked box
or large catalog is not a compatibility claim: support is declared only for
behavior covered by executable tests and release documentation.
