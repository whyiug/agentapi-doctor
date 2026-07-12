# Release Policy

The first binary channel is `v0.1.0-rc.1`. Until that exact non-draft entry is
visible on GitHub Releases with the complete allowlisted asset set, use the
developer source path in [Installation](docs/installation.md#source-install-for-contributors).

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
4. With a maintainer admin credential, require immutable releases to be enabled:

   ```sh
   test "$(gh api repos/whyiug/agentapi-doctor/immutable-releases --jq .enabled)" = true
   ```

5. Create the exact version tag for that commit and push it once. Repository
   rules determine who may create release tags; the workflow independently
   verifies that the tagged commit belongs to `origin/main`.

The tag-triggered workflow then:

- verifies the tag, SemVer, release notes, and ancestry from `main`;
- reruns Doctor CLI and release-tool regression tests while relying on the
  protected-main checks for unrelated development candidates;
- builds Linux, macOS, and Windows archives for `amd64` and `arm64`;
- produces SHA-256 checksums, one SPDX JSON SBOM, GitHub build provenance, and
  a Sigstore bundle over the checksum manifest;
- verifies the Sigstore certificate identity before any Release is published;
- runs `version --json` and the offline `demo` on representative Linux, macOS,
  and Windows native runners before publication;
- publishes an exact allowlisted asset set through the protected `release`
  environment; and
- anonymously downloads the public native artifacts on the same representative
  platforms, verifies the signature and checksum, repeats the smoke test, and
  exercises the Linux fixed-tag installer.

The first release does not publish Registry or reference-server archives, OCI
images, a Homebrew tap, a Scoop bucket, a composite Action, or a reusable
workflow. Those candidates must earn their own end-to-end distribution checks
before becoming supported channels.

Release artifacts and tags are immutable. A failed release is fixed with a new
version; published assets and tags are never replaced. GitHub's immutable
release setting and tag ruleset enforce this policy.

## Authorization and credentials

Only maintainers with release permission may create a version tag or approve
the release environment. The workflow uses the scoped GitHub token and OIDC
keyless signing; long-lived signing or registry credentials must not be added
to the repository or exposed to pull requests.

Protected `main`, the immutable tag ruleset, the release environment, and the
tag-to-main ancestry check determine what may be published. GitHub provenance
and the keyless checksum signature bind the public files to the release
workflow without requiring a long-lived maintainer signing key.

## Support and security fixes

Before 1.0, each release note states its support window and known limitations.
Once a stable support policy is announced, deprecations will include a public
rationale, replacement, and migration path.

Security fixes normally land on `main` before release. Coordinated disclosure
may use a private preparation branch; see [SECURITY.md](SECURITY.md).

Users can verify downloaded artifacts with the steps in
[Release verification](docs/operations/release-verification.md).
