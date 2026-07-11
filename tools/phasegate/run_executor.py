"""Protected, offline outer executor for fixed P00 MACHINE gates.

The in-memory :mod:`tools.phasegate.gate_runner` intentionally does not touch
the filesystem or start processes.  This module is its protected outer edge:
it verifies one exact clean source commit, creates two isolated temporary
checkouts, runs only the built-in command/evaluator selected by the sealed
criterion, and feeds observed facts directly into ``gate_runner``.

There is deliberately no caller-supplied command, exit code, summary, log
digest, assertion, checkout path, or environment.  Every gate process runs
without a shell inside a fresh Linux user/network namespace.  P00 evaluators
use a fixed strict-JSON subprocess entrypoint in that same isolation boundary;
the protected parent independently recomputes their evidence before sealing it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence

from .execution_artifact import (
    CapturedRunArtifact,
    ExecutionArtifactError,
    serialize_execution_artifact_bundle,
    serialize_phase_execution_artifact_bundle,
)
from .gate_runner import (
    FIXED_COMMANDS,
    GateRunnerError,
    SealedPhaseRunPair,
    SealedRunPair,
    combine_phase_runs,
    combine_runs,
    record_phase_run,
    record_run,
)
from .p00_evaluators import (
    EVALUATORS,
    EvaluationError,
    canonical_digest,
    evaluate_strict,
)
from .protected import ProtectedVerificationError
from .provenance import (
    VerifiedPhaseProtectedInputFreeze,
    VerifiedProtectedInputFreeze,
    _require_verified,
)


DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 1800.0
DEFAULT_OUTPUT_LIMIT_BYTES = 1024 * 1024
MAX_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30.0
TERMINATION_GRACE_SECONDS = 1.0
CONTROL_EVALUATOR = "evaluator://bootstrap/control-plane/v1"
ANTI_PLACEHOLDER_EVALUATOR = "evaluator://bootstrap/anti-placeholder/v1"
BOOTSTRAP_EVALUATORS = {CONTROL_EVALUATOR, ANTI_PLACEHOLDER_EVALUATOR}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UNITTEST_COUNT_RE = re.compile(rb"(?:^|\n)Ran ([1-9][0-9]*) tests? in ")
UNITTEST_OK_RE = re.compile(rb"(?:^|\n)OK(?:\n|$)")
INTERNAL_EVALUATOR_SCHEMA = "urn:agentapi-doctor:isolated-p00-evaluator:v1"
UNSHARE_ARGUMENTS = ("--user", "--map-root-user", "--net", "--")


@dataclass
class ProtectedExecutionError(ValueError):
    """Fail-closed protected-executor error with a stable reason code."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class ExecutionLimits:
    """Hard, caller-tightenable execution ceilings."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES

    def validate(self) -> None:
        timeout = self.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > MAX_TIMEOUT_SECONDS
        ):
            _fail(
                "invalid_execution_limit",
                "limits.timeoutSeconds",
                f"timeout must be within (0, {MAX_TIMEOUT_SECONDS}] seconds",
            )
        output_limit = self.output_limit_bytes
        if (
            isinstance(output_limit, bool)
            or not isinstance(output_limit, int)
            or output_limit <= 0
            or output_limit > MAX_OUTPUT_LIMIT_BYTES
        ):
            _fail(
                "invalid_execution_limit",
                "limits.outputLimitBytes",
                f"output limit must be within [1, {MAX_OUTPUT_LIMIT_BYTES}] bytes",
            )


@dataclass(frozen=True)
class _CapturedProcess:
    return_code: int
    stdout: bytes
    stderr: bytes
    elapsed_ns: int


@dataclass(frozen=True)
class _RunMaterial:
    command_result: dict[str, Any]
    evaluator_evidence: dict[str, Any] | None
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class ExecutionResult:
    """Protected in-memory pair plus its canonical cross-process evidence."""

    run_pair: SealedRunPair
    artifact_bundle: bytes

    @property
    def outcome(self) -> str:
        return self.run_pair.outcome

    @property
    def run_pair_digest(self) -> str:
        return self.run_pair.run_pair_digest

    def __getitem__(self, key: str) -> Any:
        return self.run_pair[key]


@dataclass(frozen=True)
class PhaseExecutionResult:
    """Protected phase-only pair plus its canonical raw artifact."""

    run_pair: SealedPhaseRunPair
    artifact_bundle: bytes

    @property
    def outcome(self) -> str:
        return self.run_pair.outcome

    @property
    def run_pair_digest(self) -> str:
        return self.run_pair.run_pair_digest

    def __getitem__(self, key: str) -> Any:
        return self.run_pair[key]


def _fail(code: str, path: str, message: str) -> None:
    raise ProtectedExecutionError(code, path, message)


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _strict_json_loads(raw: bytes, path: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in items:
            if key in document:
                raise ValueError(f"duplicate key: {key}")
            document[key] = value
        return document

    def constant(value: str) -> None:
        raise ValueError(f"non-finite number: {value}")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("invalid_isolated_result", path, str(exc))


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _strict_real_directory(path: Path, field: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        _fail("unsafe_directory", field, "a real directory is required")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        _fail("unsafe_directory", field, str(exc))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def ensure_distinct_run_roots(run_a_root: Path, run_b_root: Path) -> None:
    """Reject identical, aliased, or nested A/B checkout roots."""

    first = Path(run_a_root).resolve(strict=False)
    second = Path(run_b_root).resolve(strict=False)
    if (
        first == second
        or _is_relative_to(first, second)
        or _is_relative_to(second, first)
    ):
        _fail(
            "run_root_reuse",
            "runRoots",
            "Run A and Run B require non-overlapping checkout roots",
        )
    if first.exists() and second.exists():
        try:
            if first.samefile(second):
                _fail(
                    "run_root_reuse",
                    "runRoots",
                    "Run A and Run B checkout roots alias the same directory",
                )
        except OSError as exc:
            _fail("unsafe_directory", "runRoots", str(exc))


def _destroy_run_environment(*, checkout: Path, home: Path, temporary: Path) -> None:
    """Remove one owned run environment and prove every directory entry is gone."""

    for path, field in (
        (checkout, "checkout"),
        (home, "home"),
        (temporary, "temporary"),
    ):
        try:
            if path.is_symlink():
                _fail(
                    "run_cleanup_failed",
                    f"runEnvironment.{field}",
                    "owned run root became a symlink",
                )
            if os.path.lexists(path):
                shutil.rmtree(path)
        except OSError as exc:
            _fail("run_cleanup_failed", f"runEnvironment.{field}", str(exc))
        if os.path.lexists(path):
            _fail(
                "run_cleanup_failed",
                f"runEnvironment.{field}",
                "owned run root still exists after deletion",
            )


def _resolve_executable(name: str) -> Path:
    fixed = {
        "git": "/usr/bin/git",
        "unshare": "/usr/bin/unshare",
    }
    candidate = sys.executable if name == "python3" else fixed.get(name)
    if candidate is None:
        _fail("missing_executor", f"tools.{name}", "executable is not allowlisted")
    try:
        path = Path(candidate).resolve(strict=True)
    except OSError as exc:
        _fail("missing_executor", f"tools.{name}", str(exc))
    if not path.is_file():
        _fail("missing_executor", f"tools.{name}", "regular executable required")
    return path


def _minimal_environment(
    *, home: Path, temporary: Path, git: Path, python: Path, unshare: Path
) -> dict[str, str]:
    path_parts: list[str] = []
    for parent in (python.parent, git.parent, unshare.parent):
        value = str(parent)
        if value not in path_parts:
            path_parts.append(value)
    return {
        "CI": "true",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": "agentapi-doctor-runner",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(path_parts),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "USER": "agentapi-doctor-runner",
    }


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    else:
        if process.poll() is not None:
            return
        process.terminate()
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    else:
        process.kill()
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _fail("process_cleanup_failed", "executor", "child process did not terminate")


def _run_bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
    input_bytes: bytes | None = None,
) -> _CapturedProcess:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        _fail("invalid_internal_command", "executor.argv", "invalid fixed argv")
    if input_bytes is not None and len(input_bytes) > MAX_OUTPUT_LIMIT_BYTES:
        _fail("input_limit_exceeded", "executor.stdin", "fixed input is too large")
    input_file = None
    if input_bytes is not None:
        try:
            input_file = tempfile.TemporaryFile(dir=environment.get("TMPDIR"))
            input_file.write(input_bytes)
            input_file.seek(0)
        except OSError as exc:
            if input_file is not None:
                input_file.close()
            _fail("executor_input_failed", "executor.stdin", str(exc))
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=input_file if input_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        if input_file is not None:
            input_file.close()
        _fail("executor_start_failed", "executor", str(exc))
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    total = 0
    failure: tuple[str, str] | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = ("run_timeout", "fixed gate command exceeded its timeout")
                _terminate_process(process)
                break
            events = selector.select(timeout=min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(selector.get_map().values())
                ]
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > output_limit_bytes:
                    failure = (
                        "output_limit_exceeded",
                        "fixed gate command exceeded its combined output limit",
                    )
                    _terminate_process(process)
                    break
                streams[key.fd].extend(chunk)
            if failure is not None:
                break
        if failure is None:
            remaining = max(0.001, deadline - time.monotonic())
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                failure = ("run_timeout", "fixed gate command exceeded its timeout")
                _terminate_process(process)
            else:
                elapsed = time.monotonic_ns() - started
                return _CapturedProcess(
                    return_code=return_code,
                    stdout=bytes(streams[process.stdout.fileno()]),
                    stderr=bytes(streams[process.stderr.fileno()]),
                    elapsed_ns=elapsed,
                )
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _terminate_process(process)
        if input_file is not None:
            input_file.close()
    assert failure is not None
    _fail(failure[0], "executor", failure[1])


def _resolve_network_isolator() -> Path:
    if not sys.platform.startswith("linux"):
        _fail(
            "network_isolation_unavailable",
            "tools.unshare",
            "protected gate execution requires Linux user/network namespaces",
        )
    try:
        return _resolve_executable("unshare")
    except ProtectedExecutionError:
        _fail(
            "network_isolation_unavailable",
            "tools.unshare",
            "the fixed unshare network isolator is unavailable",
        )


def _isolated_argv(unshare: Path, argv: Sequence[str]) -> list[str]:
    return [str(unshare), *UNSHARE_ARGUMENTS, *argv]


def _verify_network_isolation(
    *,
    unshare: Path,
    python: Path,
    cwd: Path,
    environment: Mapping[str, str],
) -> None:
    try:
        parent_namespace = os.stat("/proc/self/ns/net").st_ino
    except OSError:
        _fail(
            "network_isolation_unavailable",
            "executor.networkNamespace",
            "cannot inspect the parent Linux network namespace",
        )
    try:
        probe = _run_bounded_process(
            _isolated_argv(
                unshare,
                [
                    str(python),
                    "-c",
                    "import os; print(os.stat('/proc/self/ns/net').st_ino)",
                ],
            ),
            cwd=cwd,
            environment=environment,
            timeout_seconds=GIT_TIMEOUT_SECONDS,
            output_limit_bytes=4096,
        )
    except ProtectedExecutionError:
        _fail(
            "network_isolation_unavailable",
            "executor.networkNamespace",
            "unshare network-namespace capability probe failed",
        )
    try:
        child_namespace = int(probe.stdout.strip())
    except ValueError:
        child_namespace = parent_namespace
    if probe.return_code != 0 or child_namespace == parent_namespace:
        _fail(
            "network_isolation_unavailable",
            "executor.networkNamespace",
            "unshare did not create a distinct network namespace",
        )


def _run_isolated_process(
    argv: Sequence[str],
    *,
    unshare: Path,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
    input_bytes: bytes | None = None,
) -> _CapturedProcess:
    return _run_bounded_process(
        _isolated_argv(unshare, argv),
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
        input_bytes=input_bytes,
    )


def _git(
    git: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    output_limit_bytes: int = 128 * 1024,
) -> bytes:
    captured = _run_bounded_process(
        [str(git), *arguments],
        cwd=cwd,
        environment=environment,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        output_limit_bytes=output_limit_bytes,
    )
    if captured.return_code != 0:
        _fail("git_command_failed", "repository", "fixed git operation failed")
    return captured.stdout


def _validate_checkout(
    root: Path,
    *,
    source_commit: str,
    git: Path,
    environment: Mapping[str, str],
    field: str,
) -> None:
    checkout = _strict_real_directory(root, field)
    top = (
        _git(
            git,
            ["-C", str(checkout), "rev-parse", "--show-toplevel"],
            cwd=checkout,
            environment=environment,
        )
        .decode("utf-8", "strict")
        .strip()
    )
    try:
        actual_top = Path(top).resolve(strict=True)
    except OSError as exc:
        _fail("invalid_repository", field, str(exc))
    if actual_top != checkout:
        _fail("invalid_repository", field, "path is not the repository root")
    head = (
        _git(
            git,
            ["-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=checkout,
            environment=environment,
        )
        .decode("ascii", "strict")
        .strip()
    )
    if head != source_commit:
        _fail(
            "wrong_source_commit",
            field,
            "repository HEAD does not equal the sealed source commit",
        )
    status = _git(
        git,
        [
            "-C",
            str(checkout),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        cwd=checkout,
        environment=environment,
    )
    if status:
        _fail(
            "dirty_source", field, "tracked or untracked source changes are forbidden"
        )


def _clone_checkout(
    *,
    source_root: Path,
    target_root: Path,
    source_commit: str,
    git: Path,
    environment: Mapping[str, str],
    hooks_root: Path,
) -> None:
    target_root.parent.mkdir(parents=True, exist_ok=True)
    _git(
        git,
        [
            "-c",
            f"core.hooksPath={hooks_root}",
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(source_root),
            str(target_root),
        ],
        cwd=target_root.parent,
        environment=environment,
    )
    _git(
        git,
        [
            "-C",
            str(target_root),
            "-c",
            f"core.hooksPath={hooks_root}",
            "checkout",
            "--quiet",
            "--detach",
            source_commit,
        ],
        cwd=target_root,
        environment=environment,
    )
    _validate_checkout(
        target_root,
        source_commit=source_commit,
        git=git,
        environment=environment,
        field="runCheckout",
    )


def _normalized_times(started: datetime, elapsed_ns: int) -> tuple[str, str, int]:
    elapsed_ms = max(1, math.ceil(elapsed_ns / 1_000_000))
    schema_duration_ms = max(1000, math.ceil(elapsed_ms / 1000) * 1000)
    normalized_start = started.astimezone(timezone.utc).replace(microsecond=0)
    normalized_finish = normalized_start + timedelta(milliseconds=schema_duration_ms)
    return (
        normalized_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        normalized_finish.strftime("%Y-%m-%dT%H:%M:%SZ"),
        schema_duration_ms,
    )


def _return_code(value: int) -> int:
    return value if value >= 0 else 128 + abs(value)


def _bootstrap_semantics(
    evaluator: str, captured: _CapturedProcess
) -> tuple[str, str, dict[str, Any]]:
    exit_code = _return_code(captured.return_code)
    if evaluator == CONTROL_EVALUATOR:
        try:
            document = json.loads(captured.stdout.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            facts = {"reasonCode": "invalid_control_plane_result"}
            return "candidate-semantically-valid", "FAIL", facts
        if not isinstance(document, dict):
            facts = {"reasonCode": "invalid_control_plane_result"}
            return "candidate-semantically-valid", "FAIL", facts
        facts = {
            "schemaVersion": document.get("schemaVersion"),
            "status": document.get("status"),
            "reasonCode": document.get("reasonCode"),
            "controlPlaneDigest": document.get("controlPlaneDigest"),
            "componentCount": document.get("componentCount"),
        }
        passed = (
            exit_code == 0
            and facts["schemaVersion"] == "urn:agentapi-doctor:phasegate-result:v1"
            and facts["status"] == "pass"
            and facts["reasonCode"] == "candidate_valid"
            and isinstance(facts["controlPlaneDigest"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", facts["controlPlaneDigest"])
            and isinstance(facts["componentCount"], int)
            and not isinstance(facts["componentCount"], bool)
            and facts["componentCount"] > 0
        )
        return "candidate-semantically-valid", "PASS" if passed else "FAIL", facts
    combined = captured.stdout + b"\n" + captured.stderr
    count_match = UNITTEST_COUNT_RE.search(combined)
    test_count = int(count_match.group(1)) if count_match else 0
    passed = (
        exit_code == 0
        and test_count > 0
        and UNITTEST_OK_RE.search(combined) is not None
    )
    facts = {
        "reasonCode": "anti_placeholder_suite_passed"
        if passed
        else "anti_placeholder_suite_failed",
        "testCount": test_count,
    }
    return "anti-placeholder-suite-passed", "PASS" if passed else "FAIL", facts


def _environment_digest(
    *, label: str, git: Path, python: Path, unshare: Path, output_limit_bytes: int
) -> str:
    return canonical_digest(
        {
            "schemaVersion": "urn:agentapi-doctor:protected-run-environment:v1",
            "label": label,
            "isolation": {
                "distinctTemporaryCheckout": True,
                "temporaryHome": True,
                "minimalEnvironment": True,
                "networkCredentialsInherited": False,
                "networkNamespace": "linux-user-net-unshare",
                "networkNamespaceFailClosed": True,
                "shell": False,
            },
            "gitDigest": _file_digest(git),
            "pythonDigest": _file_digest(python),
            "unshareDigest": _file_digest(unshare),
            "unshareArguments": list(UNSHARE_ARGUMENTS),
            "outputLimitBytes": output_limit_bytes,
        }
    )


def _artifact_digest(
    *,
    label: str,
    evaluator: str,
    log_digest: str,
    output_bytes: int,
    exit_code: int,
) -> str:
    return canonical_digest(
        {
            "schemaVersion": "urn:agentapi-doctor:protected-run-artifacts:v1",
            "label": label,
            "evaluator": evaluator,
            "logDigest": log_digest,
            "capturedOutputBytes": output_bytes,
            "exitCode": exit_code,
            "outputComplete": True,
        }
    )


def _execute_bootstrap(
    *,
    evaluator: str,
    label: str,
    checkout: Path,
    environment: Mapping[str, str],
    python: Path,
    git: Path,
    unshare: Path,
    source_commit: str,
    limits: ExecutionLimits,
) -> _RunMaterial:
    argv = (
        [str(python), "tools/phasegate/main.py", "bootstrap", "--root", "."]
        if evaluator == CONTROL_EVALUATOR
        else [
            str(python),
            "-m",
            "unittest",
            "discover",
            "-s",
            "test/bootstrap",
            "-p",
            "test_phasegate.py",
        ]
    )
    started = datetime.now(timezone.utc)
    captured = _run_isolated_process(
        argv,
        unshare=unshare,
        cwd=checkout,
        environment=environment,
        timeout_seconds=float(limits.timeout_seconds),
        output_limit_bytes=limits.output_limit_bytes,
    )
    assertion_id, assertion_status, assertion_facts = _bootstrap_semantics(
        evaluator, captured
    )
    started_at, finished_at, duration_ms = _normalized_times(
        started, captured.elapsed_ns
    )
    exit_code = _return_code(captured.return_code)
    combined = captured.stdout + b"\x00stderr\x00" + captured.stderr
    log_digest = _sha256_bytes(combined)
    assertion_digest = canonical_digest(
        {
            "schemaVersion": "urn:agentapi-doctor:protected-command-assertion:v1",
            "evaluator": evaluator,
            "assertionId": assertion_id,
            "status": assertion_status,
            "facts": assertion_facts,
        }
    )
    _validate_checkout(
        checkout,
        source_commit=source_commit,
        git=git,
        environment=environment,
        field=f"run{label}CheckoutAfterExecution",
    )
    return _RunMaterial(
        command_result={
            "exitCode": exit_code,
            "durationMs": duration_ms,
            "startedAt": started_at,
            "finishedAt": finished_at,
            "environmentDigest": _environment_digest(
                label=label,
                git=git,
                python=python,
                unshare=unshare,
                output_limit_bytes=limits.output_limit_bytes,
            ),
            "logDigest": log_digest,
            "artifactManifestDigest": _artifact_digest(
                label=label,
                evaluator=evaluator,
                log_digest=log_digest,
                output_bytes=len(captured.stdout) + len(captured.stderr),
                exit_code=exit_code,
            ),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "semanticAssertions": [
                {
                    "id": assertion_id,
                    "status": assertion_status,
                    "evidenceDigest": assertion_digest,
                }
            ],
        },
        evaluator_evidence=None,
        stdout=captured.stdout,
        stderr=captured.stderr,
    )


def _execute_p00_evaluator(
    *,
    evaluator: str,
    evaluator_input: Mapping[str, Any] | None,
    label: str,
    checkout: Path,
    environment: Mapping[str, str],
    python: Path,
    git: Path,
    unshare: Path,
    source_commit: str,
    limits: ExecutionLimits,
) -> _RunMaterial:
    if evaluator_input is None:
        _fail(
            "missing_evaluator_input",
            "evaluatorInput",
            "P00 built-in evaluator input is required",
        )
    try:
        serialized_input = json.dumps(
            evaluator_input,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail("invalid_evaluator_input", "evaluatorInput", str(exc))
    if len(serialized_input) > limits.output_limit_bytes:
        _fail(
            "input_limit_exceeded",
            "evaluatorInput",
            "isolated evaluator input exceeded its fixed limit",
        )
    started_wall = datetime.now(timezone.utc)
    captured = _run_isolated_process(
        [
            str(python),
            "-m",
            "tools.phasegate.run_executor",
            "--internal-evaluate",
            evaluator,
        ],
        unshare=unshare,
        cwd=checkout,
        environment=environment,
        timeout_seconds=float(limits.timeout_seconds),
        output_limit_bytes=limits.output_limit_bytes,
        input_bytes=serialized_input,
    )
    if captured.return_code != 0:
        _fail(
            "isolated_evaluator_failed",
            "evaluator",
            "fixed isolated evaluator process rejected its input",
        )
    result = _strict_json_loads(captured.stdout, "evaluator.stdout")
    if not isinstance(result, dict) or set(result) != {
        "schemaVersion",
        "evaluator",
        "evidence",
    }:
        _fail(
            "invalid_isolated_result",
            "evaluator.stdout",
            "isolated evaluator envelope field set mismatch",
        )
    if (
        result["schemaVersion"] != INTERNAL_EVALUATOR_SCHEMA
        or result["evaluator"] != evaluator
        or not isinstance(result["evidence"], dict)
    ):
        _fail(
            "invalid_isolated_result",
            "evaluator.stdout",
            "isolated evaluator envelope binding mismatch",
        )
    evidence = result["evidence"]
    try:
        recomputed = evaluate_strict(evaluator, evaluator_input)
    except EvaluationError as exc:
        _fail(exc.code, f"evaluatorInput.{exc.path}", exc.message)
    if evidence != recomputed:
        _fail(
            "isolated_evaluator_evidence_mismatch",
            "evaluator.evidence",
            "isolated evidence differs from protected-parent recomputation",
        )
    started_at, finished_at, duration_ms = _normalized_times(
        started_wall, captured.elapsed_ns
    )
    assertion_digest = canonical_digest(
        {
            "schemaVersion": "urn:agentapi-doctor:protected-command-assertion:v1",
            "evaluator": evaluator,
            "assertionId": "protected-evaluator-executed",
            "evidenceDigest": evidence["evidenceDigest"],
        }
    )
    log_digest = _sha256_bytes(captured.stdout + b"\x00stderr\x00" + captured.stderr)
    _validate_checkout(
        checkout,
        source_commit=source_commit,
        git=git,
        environment=environment,
        field=f"run{label}CheckoutAfterExecution",
    )
    return _RunMaterial(
        command_result={
            "exitCode": 0,
            "durationMs": duration_ms,
            "startedAt": started_at,
            "finishedAt": finished_at,
            "environmentDigest": _environment_digest(
                label=label,
                git=git,
                python=python,
                unshare=unshare,
                output_limit_bytes=limits.output_limit_bytes,
            ),
            "logDigest": log_digest,
            "artifactManifestDigest": _artifact_digest(
                label=label,
                evaluator=evaluator,
                log_digest=log_digest,
                output_bytes=len(captured.stdout) + len(captured.stderr),
                exit_code=0,
            ),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "semanticAssertions": [
                {
                    "id": "protected-evaluator-executed",
                    "status": "PASS",
                    "evidenceDigest": assertion_digest,
                }
            ],
        },
        evaluator_evidence=evidence,
        stdout=captured.stdout,
        stderr=captured.stderr,
    )


def _verified_freeze(
    freeze: VerifiedProtectedInputFreeze,
) -> VerifiedProtectedInputFreeze:
    try:
        _require_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return freeze


def _verified_phase_freeze(
    freeze: VerifiedPhaseProtectedInputFreeze,
) -> VerifiedPhaseProtectedInputFreeze:
    try:
        _require_verified(
            freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze"
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return freeze


def _criterion_evaluator(
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
) -> str:
    if not isinstance(criterion_id, str) or not criterion_id:
        _fail("unknown_criterion", "criterionId", "non-empty criterion ID required")
    matches = [item for item in freeze.criteria if item.criterion_id == criterion_id]
    if len(matches) != 1:
        _fail("unknown_criterion", "criterionId", criterion_id)
    criterion = matches[0]
    if criterion.kind != "MACHINE":
        _fail("invalid_criterion_kind", "criterionId", "MACHINE required")
    evaluator = criterion.evaluator
    if evaluator not in FIXED_COMMANDS or evaluator not in (
        BOOTSTRAP_EVALUATORS | set(EVALUATORS)
    ):
        _fail(
            "unknown_evaluator",
            "criterion.evaluator",
            "criterion does not select an allowlisted fixed evaluator",
        )
    if (
        isinstance(freeze, VerifiedPhaseProtectedInputFreeze)
        and evaluator in BOOTSTRAP_EVALUATORS
    ):
        _fail(
            "phase_bootstrap_evaluator_forbidden",
            "criterion.evaluator",
            "phase execution cannot invoke work-unit bootstrap evaluators",
        )
    return evaluator


def _execute_pair(
    *,
    repo_root: Path,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    evaluator_input: Mapping[str, Any] | None = None,
    limits: ExecutionLimits | None = None,
    phase: bool,
) -> ExecutionResult | PhaseExecutionResult:
    """Execute and seal one scope-specific fixed P00 Run A/B pair.

    ``repo_root`` must be a clean repository whose ``HEAD`` exactly equals the
    source commit in ``freeze``.  The function owns both temporary checkout
    roots and their HOME/TMP directories; callers cannot substitute them.
    """

    checked_freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze
    checked_freeze = (
        _verified_phase_freeze(freeze) if phase else _verified_freeze(freeze)
    )
    evaluator = _criterion_evaluator(checked_freeze, criterion_id)
    source_commit = checked_freeze.subject.source_commit
    if not COMMIT_RE.fullmatch(source_commit):
        _fail("invalid_source_commit", "freeze.subject.sourceCommit", source_commit)
    checked_limits = limits or ExecutionLimits()
    if not isinstance(checked_limits, ExecutionLimits):
        _fail("invalid_execution_limit", "limits", "ExecutionLimits required")
    checked_limits.validate()
    git = _resolve_executable("git")
    python = _resolve_executable("python3")
    unshare = _resolve_network_isolator()
    source_root = _strict_real_directory(Path(repo_root), "repoRoot")

    with tempfile.TemporaryDirectory(prefix="agentapi-doctor-protected-run-") as raw:
        workspace = Path(raw)
        audit_home = workspace / "audit-home"
        audit_tmp = workspace / "audit-tmp"
        hooks_root = workspace / "empty-hooks"
        for directory in (audit_home, audit_tmp, hooks_root):
            directory.mkdir(mode=0o700)
        audit_environment = _minimal_environment(
            home=audit_home,
            temporary=audit_tmp,
            git=git,
            python=python,
            unshare=unshare,
        )
        _validate_checkout(
            source_root,
            source_commit=source_commit,
            git=git,
            environment=audit_environment,
            field="repoRoot",
        )
        _verify_network_isolation(
            unshare=unshare,
            python=python,
            cwd=source_root,
            environment=audit_environment,
        )
        roots = {
            "A": workspace / "checkouts" / "run-a",
            "B": workspace / "checkouts" / "run-b",
        }
        ensure_distinct_run_roots(roots["A"], roots["B"])
        homes = {"A": workspace / "homes" / "run-a", "B": workspace / "homes" / "run-b"}
        temporary = {"A": workspace / "tmp" / "run-a", "B": workspace / "tmp" / "run-b"}
        ensure_distinct_run_roots(homes["A"], homes["B"])
        materials: dict[str, _RunMaterial] = {}
        sealed_runs: dict[str, Any] = {}
        for label in ("A", "B"):
            if label == "B":
                for prior in (roots["A"], homes["A"], temporary["A"]):
                    if os.path.lexists(prior):
                        _fail(
                            "run_cleanup_failed",
                            "runEnvironment.A",
                            "Run A must be absent before Run B is created",
                        )
            homes[label].mkdir(parents=True, mode=0o700)
            temporary[label].mkdir(parents=True, mode=0o700)
            environment = _minimal_environment(
                home=homes[label],
                temporary=temporary[label],
                git=git,
                python=python,
                unshare=unshare,
            )
            _clone_checkout(
                source_root=source_root,
                target_root=roots[label],
                source_commit=source_commit,
                git=git,
                environment=environment,
                hooks_root=hooks_root,
            )
            try:
                if evaluator in BOOTSTRAP_EVALUATORS:
                    materials[label] = _execute_bootstrap(
                        evaluator=evaluator,
                        label=label,
                        checkout=roots[label],
                        environment=environment,
                        python=python,
                        git=git,
                        unshare=unshare,
                        source_commit=source_commit,
                        limits=checked_limits,
                    )
                else:
                    materials[label] = _execute_p00_evaluator(
                        evaluator=evaluator,
                        evaluator_input=evaluator_input,
                        label=label,
                        checkout=roots[label],
                        environment=environment,
                        python=python,
                        git=git,
                        unshare=unshare,
                        source_commit=source_commit,
                        limits=checked_limits,
                    )
                if phase:
                    assert isinstance(
                        checked_freeze, VerifiedPhaseProtectedInputFreeze
                    )
                    sealed_runs[label] = record_phase_run(
                        freeze=checked_freeze,
                        criterion_id=criterion_id,
                        label=label,
                        command_result=materials[label].command_result,
                        evaluator_input=evaluator_input,
                        evaluator_evidence=materials[label].evaluator_evidence,
                    )
                else:
                    assert isinstance(checked_freeze, VerifiedProtectedInputFreeze)
                    sealed_runs[label] = record_run(
                        freeze=checked_freeze,
                        criterion_id=criterion_id,
                        label=label,
                        command_result=materials[label].command_result,
                        evaluator_input=evaluator_input,
                        evaluator_evidence=materials[label].evaluator_evidence,
                    )
            except GateRunnerError as exc:
                _fail(exc.code, exc.path, exc.message)
            finally:
                _destroy_run_environment(
                    checkout=roots[label],
                    home=homes[label],
                    temporary=temporary[label],
                )
        try:
            if phase:
                assert isinstance(checked_freeze, VerifiedPhaseProtectedInputFreeze)
                pair = combine_phase_runs(
                    freeze=checked_freeze,
                    criterion_id=criterion_id,
                    run_a=sealed_runs["A"],
                    run_b=sealed_runs["B"],
                )
            else:
                assert isinstance(checked_freeze, VerifiedProtectedInputFreeze)
                pair = combine_runs(
                    freeze=checked_freeze,
                    criterion_id=criterion_id,
                    run_a=sealed_runs["A"],
                    run_b=sealed_runs["B"],
                )
        except GateRunnerError as exc:
            _fail(exc.code, exc.path, exc.message)
        captured_runs = (
            CapturedRunArtifact(
                label="A",
                stdout=materials["A"].stdout,
                stderr=materials["A"].stderr,
                command_result=materials["A"].command_result,
                evaluator_evidence=materials["A"].evaluator_evidence,
                output_limit_bytes=checked_limits.output_limit_bytes,
                git_digest=_file_digest(git),
                python_digest=_file_digest(python),
                unshare_digest=_file_digest(unshare),
            ),
            CapturedRunArtifact(
                label="B",
                stdout=materials["B"].stdout,
                stderr=materials["B"].stderr,
                command_result=materials["B"].command_result,
                evaluator_evidence=materials["B"].evaluator_evidence,
                output_limit_bytes=checked_limits.output_limit_bytes,
                git_digest=_file_digest(git),
                python_digest=_file_digest(python),
                unshare_digest=_file_digest(unshare),
            ),
        )
        try:
            if phase:
                assert isinstance(checked_freeze, VerifiedPhaseProtectedInputFreeze)
                assert isinstance(pair, SealedPhaseRunPair)
                bundle = serialize_phase_execution_artifact_bundle(
                    freeze=checked_freeze,
                    criterion_id=criterion_id,
                    run_pair=pair,
                    evaluator_input=evaluator_input,
                    captured_runs=captured_runs,
                )
            else:
                assert isinstance(checked_freeze, VerifiedProtectedInputFreeze)
                assert isinstance(pair, SealedRunPair) and not isinstance(
                    pair, SealedPhaseRunPair
                )
                bundle = serialize_execution_artifact_bundle(
                    freeze=checked_freeze,
                    criterion_id=criterion_id,
                    run_pair=pair,
                    evaluator_input=evaluator_input,
                    captured_runs=captured_runs,
                )
        except ExecutionArtifactError as exc:
            _fail(exc.code, exc.path, exc.message)
        if phase:
            assert isinstance(pair, SealedPhaseRunPair)
            return PhaseExecutionResult(run_pair=pair, artifact_bundle=bundle)
        assert isinstance(pair, SealedRunPair) and not isinstance(
            pair, SealedPhaseRunPair
        )
        return ExecutionResult(run_pair=pair, artifact_bundle=bundle)


def execute_pair(
    *,
    repo_root: Path,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    evaluator_input: Mapping[str, Any] | None = None,
    limits: ExecutionLimits | None = None,
) -> ExecutionResult:
    """Execute and seal one fixed work-unit Run A/B pair."""

    result = _execute_pair(
        repo_root=repo_root,
        freeze=freeze,
        criterion_id=criterion_id,
        evaluator_input=evaluator_input,
        limits=limits,
        phase=False,
    )
    assert isinstance(result, ExecutionResult)
    return result


def execute_phase_pair(
    *,
    repo_root: Path,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    evaluator_input: Mapping[str, Any] | None = None,
    limits: ExecutionLimits | None = None,
) -> PhaseExecutionResult:
    """Execute and seal one fixed phase aggregate Run A/B pair."""

    result = _execute_pair(
        repo_root=repo_root,
        freeze=freeze,
        criterion_id=criterion_id,
        evaluator_input=evaluator_input,
        limits=limits,
        phase=True,
    )
    assert isinstance(result, PhaseExecutionResult)
    return result


def _internal_evaluator_main(arguments: Sequence[str]) -> int:
    """Fixed child-only strict JSON entrypoint used inside ``unshare``."""

    if (
        len(arguments) != 2
        or arguments[0] != "--internal-evaluate"
        or arguments[1] not in EVALUATORS
    ):
        return 2
    evaluator = arguments[1]
    raw = sys.stdin.buffer.read(MAX_OUTPUT_LIMIT_BYTES + 1)
    if len(raw) > MAX_OUTPUT_LIMIT_BYTES:
        return 2
    try:
        payload = _strict_json_loads(raw, "stdin")
        evidence = evaluate_strict(evaluator, payload)
    except (ProtectedExecutionError, EvaluationError):
        return 2
    envelope = {
        "schemaVersion": INTERNAL_EVALUATOR_SCHEMA,
        "evaluator": evaluator,
        "evidence": evidence,
    }
    try:
        encoded = json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return 2
    sys.stdout.write(encoded)
    return 0


__all__ = [
    "DEFAULT_OUTPUT_LIMIT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ExecutionLimits",
    "ExecutionResult",
    "PhaseExecutionResult",
    "ProtectedExecutionError",
    "ensure_distinct_run_roots",
    "execute_pair",
    "execute_phase_pair",
]


if __name__ == "__main__":
    raise SystemExit(_internal_evaluator_main(sys.argv[1:]))
