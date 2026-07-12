#!/usr/bin/env python3
"""Fail-closed installer for an exact AgentAPI Doctor GitHub release.

The installer deliberately has no floating channel and never executes downloaded
scripts.  It verifies the Sigstore bundle over checksums.txt before trusting the
archive digest, then extracts only the expected doctor executable.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import BinaryIO, Callable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request


RELEASE_ROOT = "https://github.com/whyiug/agentapi-doctor/releases/download"
REPOSITORY = "whyiug/agentapi-doctor"
CHECKSUM_NAME = "checksums.txt"
BUNDLE_NAME = "checksums.txt.sigstore.json"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.(?:0|[1-9][0-9]*))?$"
)
COMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})[ \t]+([^\r\n]+)$")
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
MAX_REDIRECTS = 5
MAX_CHECKSUM_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 128
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024


class InstallError(RuntimeError):
    """A bounded, user-safe installation failure."""


def validate_version(value: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise InstallError("version must be an exact SemVer or SemVer-rc.N without a v prefix")
    return value


def platform_identity(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    observed_system = (system or platform.system()).lower()
    observed_machine = (machine or platform.machine()).lower()
    systems = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    architectures = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    if observed_system not in systems or observed_machine not in architectures:
        raise InstallError("runner OS/architecture is not a declared release target")
    return systems[observed_system], architectures[observed_machine]


def artifact_name(version: str, operating_system: str, architecture: str) -> str:
    validate_version(version)
    if operating_system not in {"linux", "darwin", "windows"}:
        raise InstallError("unsupported release operating system")
    if architecture not in {"amd64", "arm64"}:
        raise InstallError("unsupported release architecture")
    return f"agentapi-doctor_{version}_{operating_system}_{architecture}.tar.gz"


def _validate_https_url(value: str, *, initial: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as error:
        raise InstallError("download or redirect URL has an invalid port") from error
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname not in ALLOWED_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise InstallError("download or redirect URL is outside the HTTPS release allowlist")
    if initial and (hostname != "github.com" or parsed.query):
        raise InstallError("initial release URL must be an uncredentialed github.com URL")
    return value


class ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject scheme/host changes outside the bounded GitHub asset allowlist."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        _validate_https_url(absolute, initial=False)
        count = int(getattr(req, "_agentapi_redirect_count", 0)) + 1
        if count > MAX_REDIRECTS:
            raise InstallError("release download exceeded the redirect limit")
        redirected = super().redirect_request(req, fp, code, msg, headers, absolute)
        if redirected is None:
            raise InstallError("release redirect was not accepted")
        setattr(redirected, "_agentapi_redirect_count", count)
        return redirected


def _safe_destination(destination: Path) -> None:
    if not SAFE_FILENAME_RE.fullmatch(destination.name) or destination.name.startswith("-"):
        raise InstallError("download destination is not a bounded filename")
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise InstallError("download destination parent must be a real directory")
    if destination.exists() or destination.is_symlink():
        raise InstallError("download destination already exists")


def _copy_bounded(source: BinaryIO, destination: Path, maximum: int) -> None:
    _safe_destination(destination)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    total = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            while True:
                chunk = source.read(min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise InstallError("download exceeded its byte limit")
                output.write(chunk)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def download_file(url: str, destination: Path, maximum: int) -> None:
    _validate_https_url(url, initial=True)
    if maximum <= 0 or maximum > MAX_ARCHIVE_BYTES:
        raise InstallError("invalid download bound")
    opener = urllib.request.build_opener(ValidatedRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "agentapi-doctor-action-candidate"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    announced = int(content_length)
                except ValueError as error:
                    raise InstallError("release server returned an invalid Content-Length") from error
                if announced < 0 or announced > maximum:
                    raise InstallError("release download exceeds its announced byte limit")
            _copy_bounded(response, destination, maximum)
    except InstallError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise InstallError("bounded HTTPS release download failed") from error


def read_bounded_regular(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise InstallError(f"required local file is unavailable: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise InstallError(f"required local file is not a regular non-symlink: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise InstallError(f"required local file violates its byte limit: {path.name}")
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise InstallError(f"required local file violates its byte limit: {path.name}")
    return data


def parse_checksums(raw: bytes) -> dict[str, str]:
    if not raw or len(raw) > MAX_CHECKSUM_BYTES or b"\x00" in raw:
        raise InstallError("checksum manifest is empty, oversized, or contains NUL")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InstallError("checksum manifest must be UTF-8") from error
    checksums: dict[str, str] = {}
    lines = text.splitlines()
    if not lines or len(lines) > 256:
        raise InstallError("checksum manifest entry count is outside the supported bound")
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise InstallError("checksum manifest contains a malformed entry")
        digest, filename = match.groups()
        if (
            SAFE_FILENAME_RE.fullmatch(filename) is None
            or filename.startswith("-")
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
        ):
            raise InstallError("checksum manifest contains an unsafe filename")
        if filename in checksums:
            raise InstallError("checksum manifest contains a duplicate filename")
        checksums[filename] = digest
    return checksums


def sha256_file(path: Path, maximum: int) -> str:
    read_bounded_regular(path, maximum)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_executable(command: str) -> str:
    if not command or "\x00" in command or "\n" in command or "\r" in command:
        raise InstallError("cosign command is invalid")
    candidate = Path(command)
    if candidate.is_absolute():
        resolved = candidate
    else:
        if "/" in command or "\\" in command or COMMAND_RE.fullmatch(command) is None:
            raise InstallError("cosign must be a command name or absolute path")
        located = shutil.which(command)
        if located is None:
            raise InstallError("cosign verifier is required but was not found")
        resolved = Path(located)
    try:
        target = resolved.resolve(strict=True)
        metadata = target.stat()
    except OSError as error:
        raise InstallError("cosign verifier path is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(target, os.X_OK):
        raise InstallError("cosign verifier must resolve to an executable regular file")
    return str(target)


def certificate_identity(version: str) -> str:
    validate_version(version)
    return (
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml"
        f"@refs/tags/v{version}"
    )


def verify_sigstore(
    checksums: Path,
    bundle: Path,
    version: str,
    cosign: str,
    *,
    runner: Callable[..., object] = subprocess.run,
) -> None:
    read_bounded_regular(checksums, MAX_CHECKSUM_BYTES)
    read_bounded_regular(bundle, MAX_BUNDLE_BYTES)
    executable = resolve_executable(cosign)
    command = [
        executable,
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity",
        certificate_identity(version),
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        str(checksums),
    ]
    try:
        completed = runner(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError("Sigstore verification could not be completed") from error
    if getattr(completed, "returncode", 1) != 0:
        raise InstallError("Sigstore bundle, issuer, or certificate identity verification failed")


def _safe_archive_member(member: tarfile.TarInfo) -> PurePosixPath:
    if "\\" in member.name or "\x00" in member.name:
        raise InstallError("release archive contains an unsafe member path")
    path = PurePosixPath(member.name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise InstallError("release archive contains an unsafe member path")
    if not (member.isdir() or member.isreg()):
        raise InstallError("release archive contains links or unsupported file types")
    return path


def extract_doctor(archive: Path, destination: Path, operating_system: str) -> Path:
    read_bounded_regular(archive, MAX_ARCHIVE_BYTES)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise InstallError("installation parent must be a real directory")
    if destination.exists() or destination.is_symlink():
        raise InstallError("installation directory already exists")
    destination.mkdir(mode=0o755)
    expected_name = "doctor.exe" if operating_system == "windows" else "doctor"
    selected: tarfile.TarInfo | None = None
    total_size = 0
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if not members or len(members) > MAX_ARCHIVE_FILES:
                raise InstallError("release archive member count is outside the supported bound")
            for member in members:
                member_path = _safe_archive_member(member)
                if member.isreg():
                    if member.size < 0:
                        raise InstallError("release archive contains a negative member size")
                    total_size += member.size
                    if total_size > MAX_UNCOMPRESSED_BYTES:
                        raise InstallError("release archive exceeds the uncompressed byte limit")
                    if member_path.name == expected_name:
                        if selected is not None:
                            raise InstallError("release archive contains multiple doctor executables")
                        selected = member
            if selected is None or selected.size <= 0 or selected.size > MAX_BINARY_BYTES:
                raise InstallError("release archive lacks one bounded doctor executable")
            source = bundle.extractfile(selected)
            if source is None:
                raise InstallError("release archive executable cannot be read")
            binary = destination / expected_name
            _copy_bounded(source, binary, MAX_BINARY_BYTES)
            binary.chmod(0o755)
            return binary
    except (tarfile.TarError, OSError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        raise InstallError("release archive could not be safely inspected") from error
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _safe_runner_temp(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise InstallError("RUNNER_TEMP must already exist") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise InstallError("RUNNER_TEMP must be a real non-symlink directory")
    return resolved


def _mkdir_beneath(root: Path, *parts: str) -> Path:
    current = root
    for part in parts:
        if not SAFE_FILENAME_RE.fullmatch(part) or part in {".", ".."}:
            raise InstallError("installation path component is unsafe")
        candidate = current / part
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            candidate.mkdir(mode=0o755)
            metadata = candidate.lstat()
        except OSError as error:
            raise InstallError("installation directory cannot be inspected") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError("installation path contains a symlink or non-directory")
        try:
            candidate.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as error:
            raise InstallError("installation path escaped RUNNER_TEMP") from error
        current = candidate
    return current


def install_release(
    version: str,
    runner_temp: Path,
    cosign: str,
    *,
    system: str | None = None,
    machine: str | None = None,
    downloader: Callable[[str, Path, int], None] = download_file,
    command_runner: Callable[..., object] = subprocess.run,
) -> Mapping[str, str]:
    version = validate_version(version)
    operating_system, architecture = platform_identity(system, machine)
    archive_name = artifact_name(version, operating_system, architecture)
    root = _safe_runner_temp(runner_temp)
    installation_parent = _mkdir_beneath(root, "agentapi-doctor", version)
    install_directory = installation_parent / f"{operating_system}-{architecture}"

    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-download-", dir=root) as temporary:
        download_directory = Path(temporary)
        checksums = download_directory / CHECKSUM_NAME
        bundle = download_directory / BUNDLE_NAME
        archive = download_directory / archive_name
        tag_root = f"{RELEASE_ROOT}/v{version}"
        downloader(f"{tag_root}/{CHECKSUM_NAME}", checksums, MAX_CHECKSUM_BYTES)
        downloader(f"{tag_root}/{BUNDLE_NAME}", bundle, MAX_BUNDLE_BYTES)
        verify_sigstore(checksums, bundle, version, cosign, runner=command_runner)
        manifest = parse_checksums(read_bounded_regular(checksums, MAX_CHECKSUM_BYTES))
        expected = manifest.get(archive_name)
        if expected is None:
            raise InstallError("signed checksum manifest does not name the selected OS/architecture artifact")
        downloader(f"{tag_root}/{archive_name}", archive, MAX_ARCHIVE_BYTES)
        observed = sha256_file(archive, MAX_ARCHIVE_BYTES)
        if observed != expected:
            raise InstallError("release archive SHA-256 does not match the signed checksum manifest")
        binary = extract_doctor(archive, install_directory, operating_system)

    return {
        "doctor-path": str(binary),
        "artifact-name": archive_name,
        "artifact-sha256": observed,
        "install-directory": str(install_directory),
    }


def _append_runner_file(variable: str, line: str) -> None:
    value = os.environ.get(variable)
    if not value:
        raise InstallError(f"{variable} is required in the action environment")
    path = Path(value)
    if "\n" in line or "\r" in line or "\x00" in line:
        raise InstallError("action output contains an invalid control character")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise InstallError(f"{variable} is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
        raise InstallError(f"{variable} must be a bounded regular non-symlink file")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except OSError as error:
        raise InstallError(f"could not write {variable}") from error


def publish_action_outputs(result: Mapping[str, str]) -> None:
    _append_runner_file("GITHUB_PATH", result["install-directory"])
    for name in ("doctor-path", "artifact-name", "artifact-sha256"):
        _append_runner_file("GITHUB_OUTPUT", f"{name}={result[name]}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--cosign", default="cosign")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        print("agentapi-doctor installer: RUNNER_TEMP is required", file=sys.stderr)
        return 2
    try:
        result = install_release(arguments.version, Path(runner_temp), arguments.cosign)
        publish_action_outputs(result)
    except InstallError as error:
        print(f"agentapi-doctor installer: {error}", file=sys.stderr)
        return 2
    print(f"installed verified release artifact {result['artifact-name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
