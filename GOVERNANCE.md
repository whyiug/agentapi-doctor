# Governance

## Current status: Bootstrap Charter

AgentAPI Doctor is a pre-release project operating under a temporary Bootstrap
Charter. There is no Technical Steering Committee (TSC), release quorum, or
claim of multi-organization governance today. The only currently recorded role
holder is listed in [MAINTAINERS.md](MAINTAINERS.md).

The Bootstrap Charter exists to establish reviewable contracts without
pretending that one author constitutes an independent community. It expires
only after all of the following are true:

- at least three release-capable maintainers participate;
- those maintainers represent at least three independent organizations or
  employers;
- Core, Pack, and Security responsibilities have real owners; and
- a public formation procedure creates a TSC and re-ratifies provisional RFCs.

Until then, governance documents and RFCs may be useful and public, but a sole
maintainer cannot self-create the independent approvals required by the plan.

## Roles

| Role | Responsibility | Authority source |
|---|---|---|
| Contributor | Issues, fixtures, documentation, code, and review | Accepted contributions and this policy |
| Reviewer | Review in demonstrated areas of expertise | Maintainer nomination recorded in MAINTAINERS.md |
| Pack Maintainer | Requirement sources, scenarios, protocol drift | Named scope and conflict disclosure |
| Driver Maintainer | SDK/client matrix and release compatibility | Named ecosystem scope |
| Core Maintainer | Core merges and release-candidate approval | Sustained cross-module contribution and trust |
| Registry Operator | Hosted operations, privacy, disputes, and audit | Separate least-privilege appointment |
| Security Team | Private vulnerability and incident handling | Explicit confidential appointment |
| TSC | Scope, governance, budget, and major RFC decisions | Future public formation procedure |

Emergency security access is not granted automatically to every maintainer.
Registry, release, security, Core, and Pack duties should be separated as the
team grows.

## Decisions

Routine implementation changes follow CODEOWNERS and required checks. The
following changes require an RFC:

- result or observation schemas and scoring;
- a new protocol family or normative support tier;
- Registry trust, privacy, retention, or dispute policy;
- plugin or driver ABI;
- breaking CLI or configuration behavior;
- telemetry;
- governance, license, trademark, or sponsorship policy.

An RFC remains open for public comment for at least 14 days and normally needs
two maintainer approvals, including one reviewer from an organization other
than the author. Pack normative changes likewise require approval from two
independent parties. Implementation decisions use ADRs that record context,
alternatives, the decision, and consequences.

During bootstrap:

- the Bootstrap Maintainer may mark an RFC only `draft` or `provisional`;
- foundational RFCs should invite review from at least two independent
  upstream maintainers or subject-matter experts;
- a normative, security, or schema RFC needs at least one substantive external
  review before it can freeze a later-phase contract;
- absence of review leaves the relevant gate waiting; silence is not approval;
- no stable badge, hosted-result dispute, or security gate may be self-approved.

A security emergency may be fixed before the normal RFC period when delaying
would increase harm. An ADR or RFC explaining the decision must follow within
seven days, without publishing embargoed exploit detail.

## Conflicts of interest and vendor independence

Anyone deciding a profile, result dispute, exception, sponsorship policy, or
normative change must disclose material employment, financial, authorship, or
competitive interests and recuse when those interests impair independent
judgment.

When a TSC exists:

- one employer may not control more than one third of its seats;
- a vendor may not solely approve its own profile, result dispute, or
  exception;
- sponsors receive no testing waiver, ranking benefit, private passing badge,
  specification veto, or paid removal of failures; and
- income, material infrastructure support, and potential conflicts are
  disclosed in an annual transparency report.

## Appointment, inactivity, and removal

Reviewer or maintainer appointment requires a public nomination describing the
candidate's scope and contributions, confirmation by the candidate, conflict
disclosure, and the approvals required by the then-current governance body.
Permissions are reviewed at least quarterly.

After six months of inactivity, maintainers should first attempt private
contact. Access may then be reduced to the minimum needed, with a public
role-record update that does not disclose private circumstances. Returning
maintainers can be restored through the normal appointment process.

Access may be suspended immediately for credential compromise or credible
security risk. Permanent removal for conduct or trust reasons requires an
unconflicted review and an appeal path under the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Meetings and records

If public maintainer meetings begin, their schedule and non-sensitive minutes
will be published. Security, personal, and embargoed material remains private.
No meeting, vote, organization affiliation, or external endorsement should be
recorded unless it actually occurred and can be verified.

## Amending governance

Changes to this document require the RFC process. During bootstrap they remain
provisional unless they receive the independent review required above. After a
TSC is formed, it must re-ratify this charter and replace bootstrap-only
language through a public decision.
