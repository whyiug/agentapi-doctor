# Release Verification and Removal

## Publication status

The current supported binary channel is `v0.1.0`. Treat it as published only
when the exact tag has a non-draft, non-prerelease entry on the project's
[GitHub Releases](https://github.com/whyiug/agentapi-doctor/releases) page with
the complete asset set below. If that entry is absent, use the developer source
path in [Installation](../installation.md#source-install-for-contributors).
Never substitute a guessed version or checksum into these commands.

The v0.1.0 release publishes only the `doctor` CLI. Registry,
reference-server, OCI, Homebrew, Scoop, composite Action, and reusable-workflow
files in the repository remain unpublished development candidates.

This is a stable Doctor distribution, not a 1.0 API declaration. Experimental
Go packages, schemas outside the declared migration floor, packs, drivers, and
Registry interfaces remain pre-1.0 contracts.

## Exact release asset set

For one exact version, the immutable GitHub Release contains:

- `agentapi-doctor_VERSION_linux_amd64.tar.gz`;
- `agentapi-doctor_VERSION_linux_arm64.tar.gz`;
- `agentapi-doctor_VERSION_darwin_amd64.tar.gz`;
- `agentapi-doctor_VERSION_darwin_arm64.tar.gz`;
- `agentapi-doctor_VERSION_windows_amd64.zip`;
- `agentapi-doctor_VERSION_windows_arm64.zip`;
- `agentapi-doctor.spdx.json`;
- `checksums.txt`; and
- `checksums.txt.sigstore.json`.

`checksums.txt` covers all six archives and the SPDX SBOM. The Sigstore bundle
authenticates `checksums.txt`, so it cannot recursively checksum itself. GitHub
build-provenance attestations are stored in GitHub's attestation service for
each of the nine files rather than duplicated as an unbound release asset.

## Verification order

1. Select an exact release tag, OS, and architecture.
2. Download the matching archive, `checksums.txt`, and its Sigstore bundle from
   that same tag.
3. Verify the bundle with the exact release-workflow identity and GitHub Actions
   OIDC issuer.
4. Read the selected archive's SHA-256 from the authenticated checksum file and
   compare it locally.
5. Optionally verify GitHub provenance and inspect the SPDX SBOM.
6. Extract the archive and confirm `doctor version --json` reports the selected
   version.

The certificate identity is exact and tag-bound:

```text
https://github.com/whyiug/agentapi-doctor/.github/workflows/release.yml@refs/tags/vVERSION
```

The required issuer is:

```text
https://token.actions.githubusercontent.com
```

## Download and verify

Set explicit values only after the release page exists. Use `tar.gz` for Linux
and macOS and `zip` for Windows.

```bash
VERSION='0.1.0'
TARGET_OS='linux'
TARGET_ARCH='amd64'
EXTENSION='tar.gz'
TAG="v${VERSION}"
ARCHIVE="agentapi-doctor_${VERSION}_${TARGET_OS}_${TARGET_ARCH}.${EXTENSION}"
DESTINATION='./agentapi-doctor-verified-release'

mkdir -m 0700 "$DESTINATION"
gh release download "$TAG" \
  --repo whyiug/agentapi-doctor \
  --dir "$DESTINATION" \
  --pattern "$ARCHIVE" \
  --pattern 'checksums.txt' \
  --pattern 'checksums.txt.sigstore.json'
```

Use a separately trusted `cosign` installation to authenticate the checksum
manifest:

```bash
cosign verify-blob \
  --bundle "$DESTINATION/checksums.txt.sigstore.json" \
  --certificate-identity "https://github.com/whyiug/agentapi-doctor/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$DESTINATION/checksums.txt"
```

Then verify exactly one checksum entry without extracting the archive:

```bash
python3 - "$DESTINATION/checksums.txt" "$DESTINATION/$ARCHIVE" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

manifest = Path(sys.argv[1])
archive = Path(sys.argv[2])
if archive.name != sys.argv[2].replace('\\', '/').rsplit('/', 1)[-1]:
    raise SystemExit('archive path must end in one bounded filename')
if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', archive.name) is None:
    raise SystemExit('unsafe archive filename')
raw = manifest.read_bytes()
if not raw or len(raw) > 4 * 1024 * 1024:
    raise SystemExit('checksum manifest violates size bounds')
matches = []
for line in raw.decode('utf-8').splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,199})', line)
    if match is None:
        raise SystemExit('malformed checksum manifest')
    if match.group(2) == archive.name:
        matches.append(match.group(1))
if len(matches) != 1:
    raise SystemExit('expected exactly one checksum for the selected archive')
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if digest != matches[0]:
    raise SystemExit('archive checksum mismatch')
print(f'verified sha256:{digest}')
PY
```

Any identity, issuer, signature, filename, or digest failure stops the
installation.

## Verify GitHub provenance

After downloading an asset, GitHub CLI can verify its repository-bound
attestation:

```bash
gh attestation verify "$DESTINATION/$ARCHIVE" \
  --repo whyiug/agentapi-doctor
```

Provenance proves which GitHub workflow produced the bytes. It does not expand
the product's compatibility claims.

## Extract, inspect, and remove

After verification, inspect the archive member list before extraction. Reject
absolute paths, `..` components, links, device files, duplicate names, and
unexpected files. The release workflow applies these rules automatically on
native Linux, macOS, and Windows runners.

The expected executable is `doctor` on Linux/macOS and `doctor.exe` on Windows.
Run:

```text
doctor version --json
doctor demo
```

The human-readable demo summary includes both the check outcome and the
candidate interpretation boundary:

```text
Result: CHECKS PASSED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] Candidate raw-wire interpretations; not certification.
```

The demo is credential-free, uses only a temporary loopback listener, and
removes that listener when the process exits.

> [!WARNING]
> Doctor writes redacted local evidence under `.agentapi/` in the current
> directory. Treat it as private local state and add `.agentapi/` to the
> downstream project's `.gitignore`.

To uninstall a manually copied release, remove only the exact executable path
you installed. Inspect or archive `.agentapi/` separately before deleting local
run data. A failed later verification does not revoke already copied bytes;
stop using them and follow the project release-incident process.
