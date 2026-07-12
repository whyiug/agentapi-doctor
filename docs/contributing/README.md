# Documentation and Contribution Guide

The repository-wide contribution contract is
[CONTRIBUTING.md](../../CONTRIBUTING.md). Documentation follows the same DCO,
source, privacy, review, and testing rules as code.

## Documentation rules

- English is normative; Chinese core guides identify their English source and
  corresponding commit once one exists.
- Mark a surface current, provisional, or future.
- Do not turn a planned capability into a support claim.
- Commands must be executable in CI and contain only synthetic values.
- Cite primary requirements and record time-sensitive facts in
  `sources.lock.yaml` when that manifest is introduced.
- Use bounded paraphrases; do not mirror specifications or issue bodies.
- Add migration and known-limitations text when a user-visible contract
  changes.
- Links, headings, code blocks, and generated reference drift are CI inputs.

## Accessibility

Do not convey status through color alone. Tables need meaningful headings and a
text alternative when they encode a visual relationship. Images require alt
text; diagrams require a nearby prose explanation. Examples, controls, and
future web views must be keyboard usable, have readable labels, and preserve
adequate contrast.

## Review evidence

Record exact commands and results. A documentation gate verifies content and
links, but external review remains external evidence; authors do not write an
approval into a front matter field.
