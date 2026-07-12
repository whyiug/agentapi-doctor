# Release Policy

## Current status

AgentAPI Doctor has no stable or release-candidate release. This policy defines
the evidence required for future releases; it does not announce a version,
date, package, Registry, or support commitment.

## Versioned surfaces

The project uses separate version axes:

- CLI/Core: Semantic Versioning;
- Result and Observation schemas: explicit schema versions;
- Packs: CalVer `YYYY.MM.patch`, with independent protocol revision and
  immutable OCI digest;
- Profiles: Semantic Versioning;
- Driver RPC: protocol Semantic Versioning with capability negotiation;
- Registry API: URL major, additive-first within a major; and
- Requirement Catalog: source revision plus content digest.

No previous stable major is invented for v1.0. Any explicitly supported
pre-1.0 migration floor must be listed by ID, version, digest, and fixture.

## Release gates

A real RC or stable release requires:

1. a protected, immutable source tag pointing to reviewed main history;
2. all required CI, security, compatibility, migration, and clean-install
   checks for the exact commit;
3. Linux, macOS, and Windows artifacts for `amd64` and `arm64`;
4. a non-root OCI image with a minimal base pinned by digest;
5. SHA-256 checksums, SPDX and CycloneDX SBOMs, SLSA provenance, and Sigstore
   signatures bound to the released subjects;
6. changelog, migration notes, known issues, and an explicit support window;
7. a protected release environment approved by two real maintainers;
8. a Release Manager and an independent verifier from a different
   organization; and
9. post-release installation, signature verification, and smoke tests using
   the public download locations.

GitHub's `verified` result proves that a tag object's signature is valid for an
identity known to GitHub; it does not by itself authorize that identity to cut
a release. The no-bypass tag ruleset, protected release environment, exact
review evidence, and Release Manager assignment provide that separate
authorization boundary.

The exact tag must also include a reviewed
`release-notes/<tag>.md` file that passes the offline release-note validator.
The release workflow gives a verified draft its final channel classification
before publication: RC tags remain prereleases and stable tags publish as
stable. It publishes the complete draft once under repository-enforced release
immutability, then re-downloads and verifies it through the public URL. A failed
post-publication check is an incident against an immutable release, never a
reason to rewrite assets or move the tag. Generated Homebrew and Scoop files are
release assets; they do not claim that a tap or bucket exists.

The checked-in workflow is intentionally unavailable for publication today.
RC tags use a separate fail-closed placeholder until an exact post-Genesis RC
gate is independently approved; stable tags require the authoritative GA gate.
GitHub Environment approval is only one control and does not replace the two
real maintainer approvals or independent-organization evidence required above.

OIDC-issued short-lived credentials are preferred for signing and publication.
Long-lived signing or registry credentials must not be committed or exposed to
fork pull requests.

OCI images are release identities only by the exact `name@sha256:...` subjects
in the checksum- and Sigstore-covered `oci-images.json` asset. The workflow's
unique `candidate-<commit>-<run>-<attempt>` tags are mutable transport pointers,
not release identities. It deliberately creates no semantic OCI tag because
GHCR does not provide the atomic create-if-absent guarantee required to call
such a tag immutable.

## Release channels

- Development builds make no compatibility promise.
- RCs are for final contract and migration validation.
- Stable releases begin only after all GA gates and the required RC observation
  window have completed.

Published tags and artifacts are never overwritten. If an artifact is wrong,
maintainers may stop promotion or yank a mutable channel pointer, preserve the
audit evidence, and publish a new patch release. Security fixes enter main
before any supported backport unless coordinated disclosure requires a private
preparation branch.

## Support and deprecation

Before stable v1, support is defined per release note. For future stable
releases, the intended policy is to support the current and previous minor and
provide 12 months of security fixes for the last minor of a major, subject to a
publicly announced capacity review before that commitment takes effect.

A stable deprecation requires a public rationale and replacement, at least two
minor releases and 90 days, machine-readable warnings, and removal only in the
next major. Old artifacts remain readable or receive an offline migration path
according to the published schema policy.

The release checklist cannot be self-certified. Missing people, evidence,
signatures, or time windows leave a release blocked rather than waived.
