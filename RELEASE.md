# Release Policy

AgentAPI Doctor currently has no tagged release. Until the first prerelease is
published, build from source as described in the [Quick Start](docs/quick-start.md).

## Versioning and channels

- CLI and service releases use [Semantic Versioning](https://semver.org/).
- Tags are `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N`.
- Release candidates are GitHub prereleases. Stable tags create stable GitHub
  releases.
- Before 1.0, release notes identify the supported configuration, schema, and
  protocol surface; breaking changes may occur in a minor version.

Schemas, protocol packs, profiles, and the Driver RPC carry their own explicit
version fields so stored evidence can be interpreted independently of the CLI
version.

## Preparing a release

1. Start from a commit on protected `main` with all required checks passing.
2. Update [CHANGELOG.md](CHANGELOG.md), compatibility or migration guidance,
   and known limitations.
3. Add `release-notes/vX.Y.Z.md` (or `vX.Y.Z-rc.N.md`) using the checked-in
   template and validator.
4. Create a signed annotated tag for that exact commit and push it once.

The tag-triggered workflow then:

- verifies the tag, its GitHub signature status, SemVer, release notes, and
  ancestry from `main`;
- reruns tests, static analysis, vulnerability checks, race tests, and offline
  container smoke tests;
- builds Linux, macOS, and Windows archives for `amd64` and `arm64`;
- produces SHA-256 checksums, SPDX and CycloneDX SBOMs, provenance, and a
  Sigstore bundle;
- smoke-tests each archive and both multi-architecture OCI images;
- publishes an exact allowlisted asset set through the protected `release`
  environment; and
- downloads the public artifacts and verifies them again.

Release artifacts and tags are immutable. A failed release is fixed with a new
version; published assets and tags are never replaced. GitHub's immutable
release setting and the protected signed-tag ruleset enforce this policy.

## Authorization and credentials

Only maintainers with release permission may create a version tag or approve
the release environment. The workflow uses the scoped GitHub token and OIDC
keyless signing; long-lived signing or registry credentials must not be added
to the repository or exposed to pull requests.

GitHub's `verified` tag result proves signature validity for an identity known
to GitHub. Maintainer authorization, protected `main`, the tag ruleset, and the
release environment determine whether that identity may publish.

OCI identities are recorded as exact `name@sha256:...` subjects in the signed
`oci-images.json` release asset. Temporary `build-<commit>-<run>-<attempt>`
tags are transport handles, not stable release identities.

## Support and security fixes

Before 1.0, each release note states its support window and known limitations.
Once a stable support policy is announced, deprecations will include a public
rationale, replacement, and migration path.

Security fixes normally land on `main` before release. Coordinated disclosure
may use a private preparation branch; see [SECURITY.md](SECURITY.md).

Users can verify downloaded artifacts with the steps in
[Release verification](docs/operations/release-verification.md).
