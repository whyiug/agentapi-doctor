# Roadmap

AgentAPI Doctor grows from reproducible user failures. The supported v0.1.x
product is the local `doctor` CLI and its release archives; catalog size and
unshipped service infrastructure are not measures of product readiness.

## v0.1.x: strengthen the Doctor workflow

- Keep the bounded raw checks for OpenAI Chat Completions, OpenAI Responses,
  and Anthropic Messages reproducible and safe by default.
- Preserve stable command behavior, exit codes, report formats, baselines, and
  the declared artifact migration floor throughout the v0.1.x line.
- Improve diagnostics and maintainer-ready reproduction bundles from real,
  consented failure reports.
- Expand platform and installation verification for published Doctor release
  archives.

## Evidence required for expansion

New supported surfaces are selected only when external use shows that they
solve a recurring problem and the project can maintain their security and
compatibility boundaries. Candidate work must include versioned contracts,
offline fixtures, migration coverage, and explicit support documentation
before it can become part of the product.

## Deferred and experimental work

The repository contains exploratory code and design documents for generic
drivers, authored scenario packs, a Registry and Matrix, hosted operation, and
additional distribution channels. These are development assets, not v0.1.x
product surfaces or compatibility promises.

Possible future work, contingent on evidence and maintainer capacity, includes:

- a second pinned real-client reproduction case;
- a stable authoring and execution contract for external packs;
- a supported out-of-process driver ABI;
- a GitHub Action, OCI image, or package-manager channel; and
- a separately reviewed Registry or compatibility matrix.

Roadmap items are directional and do not establish support until a release
explicitly includes them.
