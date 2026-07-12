# Installation

[Documentation home](README.md) | [Quick Start](quick-start.md)

`v0.1.0-rc.1` is the first AgentAPI Doctor release candidate. The supported
distribution is the `doctor` CLI archive on GitHub Releases. Registry,
reference-server, OCI, Homebrew, Scoop, and GitHub Action files remain
unpublished candidates and are not installation channels.

## Fast install on Linux or macOS

The pinned installer chooses the current OS/architecture, downloads the exact
release archive and `checksums.txt`, verifies SHA-256, and installs one binary
under `$HOME/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.0-rc.1/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
doctor version
doctor demo
```

The script does not use `sudo`, change shell configuration, or contact an LLM
endpoint. Read it before execution if piping a script is outside your policy:

```sh
curl --proto '=https' --tlsv1.2 -fSLO \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.0-rc.1/install.sh
less install.sh
sh install.sh
```

Override the user-local destination by exporting it before the installer:

```sh
export AGENTAPI_DOCTOR_INSTALL_DIR='/your/path'
sh install.sh
```

## Manual Linux or macOS verification

Choose an exact release, never a moving `latest` URL:

```sh
VERSION='0.1.0-rc.1'
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo 'unsupported architecture' >&2; exit 2 ;;
esac
ASSET="agentapi-doctor_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/whyiug/agentapi-doctor/releases/download/v${VERSION}"

curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ASSET"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/checksums.txt"
EXPECTED="$(awk -v asset="$ASSET" '$2 == asset {print $1}' checksums.txt)"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$ASSET" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$ASSET" | awk '{print $1}')"
fi
test -n "$EXPECTED" && test "$ACTUAL" = "$EXPECTED"

tar -xzf "$ASSET" doctor
install -m 0755 doctor "$HOME/.local/bin/doctor"
"$HOME/.local/bin/doctor" demo
```

The release manifest must contain exactly one entry for the selected archive.
The pinned installer enforces that stricter check automatically.

## Windows PowerShell

Run these commands in a new empty directory. Select `arm64` only on Windows on
ARM; otherwise use `amd64`:

```powershell
$Version = '0.1.0-rc.1'
$Arch = 'amd64'
$Asset = "agentapi-doctor_${Version}_windows_${Arch}.zip"
$Base = "https://github.com/whyiug/agentapi-doctor/releases/download/v${Version}"

Invoke-WebRequest "$Base/$Asset" -OutFile $Asset
Invoke-WebRequest "$Base/checksums.txt" -OutFile checksums.txt
$ChecksumLines = @(Get-Content checksums.txt | Where-Object { $_ -match "^([0-9a-f]{64})\s+$([regex]::Escape($Asset))$" })
if ($ChecksumLines.Count -ne 1) { throw 'Expected exactly one checksum entry' }
$Expected = ($ChecksumLines[0] -split '\s+')[0]
$Actual = (Get-FileHash -Algorithm SHA256 $Asset).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw 'Archive checksum mismatch' }

Expand-Archive $Asset -DestinationPath .\agentapi-doctor
.\agentapi-doctor\doctor.exe version
.\agentapi-doctor\doctor.exe demo
```

Move `doctor.exe` to a user-controlled directory on `PATH` if desired. The
archive also contains license, notice, security, and data-policy files.

## Source install for contributors

Source installation is a developer alternative, not the default user path. It
requires the Go version selected by `go.mod` (Go 1.26.5 for this RC):

```sh
go install github.com/whyiug/agentapi-doctor/cmd/doctor@v0.1.0-rc.1
doctor version
doctor demo
```

To modify the project, build a checkout instead:

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor
git checkout v0.1.0-rc.1
mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
./bin/doctor demo
```

The committed vendor tree keeps checkout builds independent of module downloads
after the repository and required Go toolchain are available.

## Advanced release verification

Every release contains SHA-256 checksums, an SPDX SBOM, and GitHub build
provenance. Teams that need independent identity and provenance verification
should follow [Release Verification](operations/release-verification.md) in
addition to the quick checksum path above.

## Remove AgentAPI Doctor

The installer creates one executable. Remove only that exact file:

```sh
rm "$HOME/.local/bin/doctor"
```

On Windows, remove the exact `doctor.exe` you extracted. Local runs are stored
under the working directory's `.agentapi/` tree; inspect or archive them before
removing that directory. Uninstalling the CLI does not delete run evidence
automatically.
