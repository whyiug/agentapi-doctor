# Release Verification and Removal

## Current publication status

AgentAPI Doctor does **not** currently have a published stable or release-candidate
release. The GitHub Action, reusable workflow, Homebrew formula, and Scoop manifest
in this repository are `candidate-unpublished` distribution contracts. Their null
version and checksum fields are intentional. Do not substitute guessed versions,
checksums, tags, or commit IDs, and do not treat the templates as installable
packages.

Use the procedures below only after a release page contains all of the following
for the same immutable tag:

- the exact OS/architecture archive;
- `checksums.txt`;
- `checksums.txt.sigstore.json`;
- SPDX and CycloneDX SBOM assets plus verifiable provenance attestations; and
- release notes naming the supported version and known issues.

There is intentionally no download-piped-to-shell command. A release artifact is
not trusted merely because it was downloaded over HTTPS.

## Verification order

Verify in this order:

1. select an exact version, OS, and architecture—never a moving channel;
2. download the archive, checksum manifest, and Sigstore bundle from that exact
   release tag;
3. verify the Sigstore bundle over the checksum manifest with the expected GitHub
   Actions issuer and exact release-workflow certificate identity;
4. read the selected archive's SHA-256 from the now-authenticated checksum
   manifest;
5. calculate the archive SHA-256 locally and compare it exactly; and
6. inspect provenance/SBOM and safely extract only after all prior checks pass.

The release workflow identity is:

```text
https://github.com/whyiug/agentapi-doctor/.github/workflows/release.yml@refs/tags/v<exact-version>
```

The required OIDC issuer is:

```text
https://token.actions.githubusercontent.com
```

## Manual download and Sigstore verification

Set explicit values after confirming that the release exists. The angle-bracketed
values below are placeholders, not published versions:

```bash
VERSION='<exact-semver-or-rc>'
OS='<linux-or-darwin-or-windows>'
ARCH='<amd64-or-arm64>'
TAG="v${VERSION}"
ARTIFACT="agentapi-doctor_${VERSION}_${OS}_${ARCH}.tar.gz"
DESTINATION='./agentapi-doctor-verified-release'

mkdir -m 0700 "$DESTINATION"
gh release download "$TAG" \
  --repo whyiug/agentapi-doctor \
  --dir "$DESTINATION" \
  --pattern "$ARTIFACT" \
  --pattern 'checksums.txt' \
  --pattern 'checksums.txt.sigstore.json'
```

Use a separately trusted `cosign` installation. Then authenticate the checksum
manifest before trusting any checksum line:

```bash
cosign verify-blob \
  --bundle "$DESTINATION/checksums.txt.sigstore.json" \
  --certificate-identity "https://github.com/whyiug/agentapi-doctor/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$DESTINATION/checksums.txt"
```

Any identity, issuer, transparency, signature, or bundle failure stops the
installation. Do not replace the exact identity with a broad regular expression.

## Manual archive checksum verification

Extract exactly one matching checksum entry and compare it with a locally computed
digest. The following Python snippet is portable, rejects duplicate/malformed
entries and path-like filenames, and does not extract the archive:

```bash
python3 - "$DESTINATION/checksums.txt" "$DESTINATION/$ARTIFACT" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

manifest = Path(sys.argv[1])
artifact = Path(sys.argv[2])
if artifact.name != sys.argv[2].rsplit('/', 1)[-1]:
    raise SystemExit('artifact path must end in one bounded filename')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', artifact.name):
    raise SystemExit('unsafe artifact filename')
raw = manifest.read_bytes()
if not raw or len(raw) > 4 * 1024 * 1024:
    raise SystemExit('checksum manifest violates size bounds')
matches = []
for line in raw.decode('utf-8').splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})[ \t]+([A-Za-z0-9][A-Za-z0-9._-]{0,199})', line)
    if match is None:
        raise SystemExit('malformed checksum manifest')
    if match.group(2) == artifact.name:
        matches.append(match.group(1))
if len(matches) != 1:
    raise SystemExit('expected exactly one checksum entry for selected artifact')
if artifact.stat().st_size > 256 * 1024 * 1024:
    raise SystemExit('archive exceeds the supported download bound')
observed = hashlib.sha256(artifact.read_bytes()).hexdigest()
if observed != matches[0]:
    raise SystemExit('archive checksum mismatch')
print(f'verified sha256:{observed}')
PY
```

Before extracting manually, reject absolute paths, `..` components, links, device
files, excessive member counts, and excessive uncompressed size. The candidate
composite action implements these checks and extracts only `doctor`/`doctor.exe`;
a generic `tar -x` command is deliberately not recommended here.

## GitHub Actions usage after publication

The repository-callable candidate is located at `.github/workflows/doctor.yml`;
`integrations/reusable-workflow/workflow.yml` is its byte-identical reviewed source
template. This placement makes the workflow structurally callable by GitHub, but it
does not make the candidate published or usable without the signed release artifacts
listed above.

Call both the reusable workflow and its `action_commit` using full 40-character
commit SHAs. Supply an exact release version. Branch names, tags, moving major
aliases, and a moving release channel are not acceptable pins. The reusable
workflow grants only `contents: read`, checks out the action implementation at the
provided full SHA, installs a pinned Sigstore verifier, and delegates archive
verification to the composite action.

Until a commit containing these integration files and a signed release both exist,
there is no valid Actions invocation to publish in documentation.

## Homebrew and Scoop after publication

The checked-in package files are templates plus candidate schemas. Release
automation must generate them from the already verified `checksums.txt` and an
exact version. The generators reject missing platform entries, path traversal,
floating versions, symlinked output directories, unknown template tokens, and
overwrites.

After an actual package channel is published, users can remove the package with:

```bash
brew uninstall agentapi-doctor
```

or, on Windows:

```powershell
scoop uninstall agentapi-doctor
```

No Homebrew tap or Scoop bucket is currently claimed to exist.

The candidate release workflow attaches generated formula/manifest files to an
exact release only after both pass their offline validators. Attaching those
files does not publish or update a third-party package channel.

## Manual and CI removal

- The composite action installs beneath the job's `RUNNER_TEMP`; GitHub-hosted jobs
  discard that directory with the runner. It does not modify a system directory.
- For a manual installation, remove only the exact path into which you personally
  copied the verified binary. Do not use wildcards, command substitution, or a
  recursive deletion copied from untrusted output.
- Remove the separate download directory only after retaining any verification
  evidence required by your organization's release policy.

An uninstall does not revoke a compromised artifact. If release verification ever
fails after publication, stop promotion, preserve the evidence, and follow the
security and release incident process; published artifacts and tags are never
silently overwritten.
