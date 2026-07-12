# Governance

AgentAPI Doctor is currently a maintainer-led open-source project. The active
maintainers and their scopes are recorded in [MAINTAINERS.md](MAINTAINERS.md).
This model keeps routine work lightweight while the contributor community
grows.

## Roles

- **Contributors** propose code, tests, fixtures, documentation, and designs.
- **Reviewers** provide informed feedback in areas where they have experience.
- **Maintainers** triage work, merge changes, manage releases, and uphold the
  project's security and compatibility policies.
- **Security maintainers** receive private vulnerability reports and coordinate
  fixes and disclosure. Security access is granted explicitly and kept to the
  minimum necessary.

## Decisions

Routine changes are decided through pull-request review by a maintainer. The
maintainer considers technical quality, compatibility, security, maintenance
cost, and community feedback; consensus is preferred, but unanimity is not
required.

Changes to public schemas, protocol semantics, driver ABI, Registry trust or
privacy, telemetry defaults, licensing, or governance should use an RFC under
[`rfcs/`](rfcs/). The review period and evidence should be proportional to the
impact. Architecture decisions are recorded under [`adrs/`](adrs/).

Urgent security fixes may be prepared privately and merged before the normal
design process when delay would increase harm. Public rationale can follow
after coordinated disclosure without exposing embargoed details.

## Conflicts and independence

Anyone making a decision should disclose a material employment, financial,
authorship, or competitive interest and recuse when it prevents impartial
judgment. Sponsors and vendors do not receive compatibility waivers, ranking
benefits, or the ability to remove valid failures.

## Becoming a maintainer

Maintainer access is based on sustained, constructive contributions and sound
judgment. An existing maintainer records the appointment in
[MAINTAINERS.md](MAINTAINERS.md) after the contributor agrees to the role.
Permissions are reviewed periodically and may be reduced after prolonged
inactivity or immediately after credential compromise.

Removal for conduct or trust reasons should include an unconflicted review and
an appeal path under the [Code of Conduct](CODE_OF_CONDUCT.md), except for
temporary access suspension needed to contain an active security incident.

As the maintainer group grows, the project may adopt a steering committee or
more formal voting rules through a public governance RFC.

## Records and amendments

Public project decisions belong in issues, pull requests, RFCs, ADRs, release
notes, or meeting minutes. Security, personal, and embargoed material remains
private. Changes to this document follow the same pull-request process as other
project policy changes.
