#!/usr/bin/env python3
"""Command-line entry point for the dependency-free bootstrap phase gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn, Sequence

# Direct execution does not put the repository root on ``sys.path``.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.phasegate.validation import (  # noqa: E402
    ValidationError,
    ensure_gate_is_executable,
    validate_bootstrap_candidate,
)
from tools.phasegate.chain_artifact import (  # noqa: E402
    ChainArtifactError,
    MAX_CHAIN_ARTIFACT_BYTES,
    parse_chain_artifact,
)
from tools.phasegate.digest import canonical_json_bytes  # noqa: E402
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    compare_state_view,
    document_digest,
    load_event_directory,
    load_strict_document,
    replay_state_events,
    verify_control_plane_approval,
)
from tools.phasegate.protected_v2 import (  # noqa: E402
    validate_trust_policy_v2,
    verify_control_plane_approval_v2,
    verify_genesis_event_v2,
)
from tools.phasegate.serialized_bundle import MAX_BUNDLE_BYTES  # noqa: E402
from tools.phasegate.state_writer import github_actions_token_provider  # noqa: E402
from tools.phasegate.workflow_orchestrator import (  # noqa: E402
    WorkflowOrchestratorError,
    append_post_genesis,
    replay_protected_chain,
    require_verified_protected_chain_replay,
)


RESULT_SCHEMA = "urn:agentapi-doctor:phasegate-result:v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GATE_COMMANDS = {
    "gate-unit",
    "gate",
    "gate-phase",
    "gate-all",
    "evidence-verify",
    "clean-checkout",
    "ga-gate",
}


def _result(status: str, reason_code: str, **details: Any) -> dict[str, Any]:
    return {
        "schemaVersion": RESULT_SCHEMA,
        "status": status,
        "reasonCode": reason_code,
        **details,
    }


def _validation_result(exc: ValidationError) -> dict[str, Any]:
    issues = [issue.as_dict() for issue in exc.issues]
    first = issues[0] if issues else {"code": "validation_failed"}
    return _result("fail", first["code"], issues=issues)


def _extract_root(argv: Sequence[str]) -> tuple[list[str], Path]:
    args = list(argv)
    indexes = [index for index, value in enumerate(args) if value == "--root"]
    if len(indexes) != 1 or indexes[0] + 1 >= len(args):
        raise ValueError("exactly one --root <repo> argument is required")
    index = indexes[0]
    root = Path(args[index + 1]).resolve()
    del args[index : index + 2]
    return args, root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phasegate")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in (
        "bootstrap",
        "state-verify",
        "control-plane-verify",
        "gate-all",
        "ga-gate",
    ):
        command = commands.add_parser(name)
        if name in {"gate-all", "ga-gate"}:
            command.add_argument("--output")
    approval = commands.add_parser("approval-verify")
    approval.add_argument("--request", required=True)
    approval.add_argument("--approval", required=True)
    approval.add_argument("--policy", required=True)
    approval.add_argument("--expected-policy-digest", required=True)
    approval.add_argument("--expected-control-plane-digest", required=True)
    approval.add_argument("--expected-candidate-source-commit", required=True)
    approval.add_argument("--expected-request-digest", required=True)
    approval.add_argument("--expected-ssh-keygen-digest")
    approval.add_argument("--jwks")
    approval.add_argument("--expected-jwks-snapshot-digest")
    approval.add_argument("--expected-workflow-execution-commit")
    state_chain = commands.add_parser("state-chain-verify")
    state_chain.add_argument("--request", required=True)
    state_chain.add_argument("--approval", required=True)
    state_chain.add_argument("--policy", required=True)
    state_chain.add_argument("--events", required=True)
    state_chain.add_argument("--prior-events")
    state_chain.add_argument("--phase-state")
    state_chain.add_argument("--expected-policy-digest", required=True)
    state_chain.add_argument("--expected-control-plane-digest", required=True)
    state_chain.add_argument("--expected-candidate-source-commit", required=True)
    state_chain.add_argument("--expected-request-digest", required=True)
    state_chain.add_argument("--expected-chain-head-digest", required=True)
    state_chain.add_argument("--expected-ssh-keygen-digest")
    state_chain.add_argument("--jwks")
    state_chain.add_argument("--expected-jwks-snapshot-digest")
    state_chain.add_argument("--expected-workflow-execution-commit")
    replay = commands.add_parser("protected-chain-replay")
    replay.add_argument("--chain", required=True)
    replay.add_argument("--bootstrap-request-commit", required=True)
    replay.add_argument("--expected-chain-head-digest", required=True)
    replay.add_argument("--current-workflow-execution-commit", required=True)
    replay.add_argument("--output", required=True)
    append = commands.add_parser("protected-chain-append")
    append.add_argument("--chain", required=True)
    append.add_argument("--bootstrap-request-commit", required=True)
    append.add_argument("--expected-current-chain-head-digest", required=True)
    append.add_argument("--current-workflow-execution-commit", required=True)
    append.add_argument(
        "--operation",
        required=True,
        choices=(
            "work-unit-convergence",
            "work-unit-readiness",
            "work-unit-activation",
            "evidence-attachment",
            "phase-transition",
        ),
    )
    append.add_argument("--to-state", required=True)
    append.add_argument("--phase", choices=("P00",), default="P00")
    append.add_argument("--work-unit")
    append.add_argument("--bundle", required=True)
    append.add_argument("--expected-bundle-digest")
    append.add_argument("--output", required=True)
    unit = commands.add_parser("gate-unit")
    unit.add_argument("unit", nargs="?")
    unit.add_argument("--unit", dest="unit_option")
    unit.add_argument("--output")
    for name in ("gate", "gate-phase", "clean-checkout"):
        command = commands.add_parser(name)
        command.add_argument("phase", nargs="?")
        command.add_argument("--phase", dest="phase_option")
        command.add_argument("--output")
    evidence = commands.add_parser("evidence-verify")
    evidence.add_argument("phase", nargs="?")
    evidence.add_argument("--phase", dest="phase_option")
    evidence.add_argument("--evidence", required=True)
    return parser


def _argument_value(parsed: argparse.Namespace, positional: str, option: str) -> str:
    positional_value = getattr(parsed, positional, None)
    option_value = getattr(parsed, option, None)
    if positional_value and option_value and positional_value != option_value:
        raise ValueError(f"conflicting {positional} values")
    value = option_value or positional_value
    if not value:
        raise ValueError(f"{positional} is required")
    return value


def _required_option(parsed: argparse.Namespace, name: str, *, protocol: str) -> str:
    value = getattr(parsed, name, None)
    if not value:
        raise ProtectedVerificationError(
            "missing_external_pin",
            f"arguments.{name}",
            f"--{name.replace('_', '-')} is required for {protocol}",
        )
    return value


def github_actions_append_token_provider(audience: str) -> str:
    """Testable default for the append command's one OIDC network call."""

    return github_actions_token_provider(audience)


def _chain_error(code: str, path: str, message: str) -> NoReturn:
    raise WorkflowOrchestratorError(code, path, message)


def _cli_commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _chain_error("invalid_git_commit", path, "full lowercase 40-hex commit required")
    return value


def _cli_digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _chain_error("invalid_digest", path, "lowercase sha256:<64 hex> required")
    return value


def _read_regular_file(path_value: str, *, label: str, maximum: int) -> bytes:
    path = Path(path_value)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _chain_error("protected_input_unavailable", label, "input file is unavailable")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _chain_error(
                "unsafe_protected_input",
                label,
                "regular non-symlink file required",
            )
        if before.st_size <= 0 or before.st_size > maximum:
            _chain_error(
                "protected_input_size_invalid",
                label,
                "input file size is outside bounds",
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        _chain_error("protected_input_unavailable", label, "input file cannot be read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if (
        len(raw) != before.st_size
        or len(raw) > maximum
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        _chain_error("protected_input_changed", label, "input changed while being read")
    return raw


def _canonical_bundle_digest(raw: bytes) -> str:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _chain_error("duplicate_bundle_key", "bundle", f"duplicate key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> NoReturn:
        _chain_error("noncanonical_bundle", "bundle", f"non-finite number: {value}")

    try:
        document = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except WorkflowOrchestratorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _chain_error("invalid_bundle_json", "bundle", "canonical JSON object required")
    if not isinstance(document, dict) or canonical_json_bytes(document) != raw:
        _chain_error("noncanonical_bundle", "bundle", "exact canonical JSON bytes required")
    declared = _cli_digest(document.get("bundleDigest"), "bundle.bundleDigest")
    if document_digest(document, omit_field="bundleDigest") != declared:
        _chain_error("bundle_digest_mismatch", "bundle.bundleDigest", "bundle bytes changed")
    return declared


def _verify_current_workflow_commit(root: Path, expected: str) -> str:
    commit = _cli_commit(expected, "currentWorkflowExecutionCommit")
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-c", "core.pager=cat", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            timeout=10,
            env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired):
        _chain_error("git_verifier_unavailable", "repoRoot", "cannot resolve workflow checkout")
    try:
        observed = completed.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        observed = ""
    if completed.returncode != 0 or observed != commit or completed.stderr:
        _chain_error(
            "workflow_execution_commit_mismatch",
            "currentWorkflowExecutionCommit",
            "executed checkout HEAD differs from the external workflow commit pin",
        )
    return commit


def _atomic_output_directory(
    output_value: str,
    files: Mapping[str, bytes],
) -> Path:
    output = Path(output_value)
    if not output.name or output.name in {".", ".."}:
        _chain_error("unsafe_output_directory", "output", "named output directory required")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError:
        _chain_error("output_parent_unavailable", "output", "output parent must exist")
    destination = parent / output.name
    if destination.exists() or destination.is_symlink():
        _chain_error("output_already_exists", "output", "refusing to replace existing output")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=parent))
    try:
        for relative, raw in files.items():
            if "/" in relative or relative in {"", ".", ".."}:
                _chain_error("unsafe_output_name", "output", "flat fixed output names required")
            target = temporary / relative
            with target.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            target.chmod(0o600)
        directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.rename(temporary, destination)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def _canonical_output(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value)


def _gate_evaluator_failure(root: Path, paths: list[str]) -> dict[str, Any] | None:
    issues = []
    for path in paths:
        if not (root / path).is_file():
            return _result("fail", "unknown_gate", gate=path)
        try:
            ensure_gate_is_executable(root, path)
        except ValidationError as exc:
            issues.extend(issue.as_dict() for issue in exc.issues)
    if issues:
        return _result("fail", "missing_evaluator", issues=issues)
    return None


def _protected_artifact_layout(parsed: argparse.Namespace, root: Path) -> None:
    """Reject hidden state or extra approval artifacts in protected input trees."""

    command = parsed.command
    forbidden = ["execution/waivers.yaml"]
    if command == "approval-verify":
        forbidden.extend(
            [
                "execution/phase-state.yaml",
                "execution/transitions",
                "execution/gates/p00/evidence",
                "execution/gates/p00/latest.json",
            ]
        )
    present = [
        relative
        for relative in forbidden
        if (root / relative).exists() or (root / relative).is_symlink()
    ]
    if present:
        raise ProtectedVerificationError(
            "unexpected_protected_artifact",
            "repository",
            "protected input tree contains forbidden artifacts: " + ", ".join(present),
        )

    approvals = root / "execution/approvals"
    if approvals.exists() or approvals.is_symlink():
        if approvals.is_symlink() or not approvals.is_dir():
            raise ProtectedVerificationError(
                "unsafe_approval_directory",
                "execution/approvals",
                "approval directory must be a real directory",
            )
        files = list(approvals.rglob("*"))
        if any(item.is_symlink() or not item.is_file() for item in files):
            raise ProtectedVerificationError(
                "unexpected_approval_artifact",
                "execution/approvals",
                "approval bundle may contain only one regular envelope",
            )
        expected = Path(parsed.approval).resolve()
        if {item.resolve() for item in files} != {expected}:
            raise ProtectedVerificationError(
                "unexpected_approval_artifact",
                "execution/approvals",
                "approval bundle does not exactly match --approval",
            )
    phase_state = root / "execution/phase-state.yaml"
    transitions = root / "execution/transitions"
    if command == "state-chain-verify" and (
        transitions.exists() or transitions.is_symlink()
    ):
        if Path(parsed.events).resolve() != transitions:
            raise ProtectedVerificationError(
                "unverified_transition_directory",
                "execution/transitions",
                "repository transitions must be the exact --events directory",
            )
    if command == "state-chain-verify" and (
        phase_state.exists() or phase_state.is_symlink()
    ):
        if not parsed.phase_state or Path(parsed.phase_state).resolve() != phase_state:
            raise ProtectedVerificationError(
                "unverified_phase_state_view",
                "execution/phase-state.yaml",
                "an existing phase-state view must be supplied for exact comparison",
            )


def run(
    parsed: argparse.Namespace,
    root: Path,
    *,
    token_provider: Callable[[str], str] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[int, dict[str, Any]]:
    command = parsed.command
    protected_chain_command = command in {
        "protected-chain-replay",
        "protected-chain-append",
    }
    if protected_chain_command:
        common: dict[str, Any] = {}
        candidate = None
    else:
        try:
            candidate = validate_bootstrap_candidate(
                root,
                require_pre_genesis=command
                not in {"approval-verify", "state-chain-verify"},
            )
        except ValidationError as exc:
            return 2, _validation_result(exc)
        common = {
            "controlPlaneDigest": candidate["controlPlaneDigest"],
            "componentCount": candidate["componentCount"],
        }
    if protected_chain_command:
        try:
            workflow_commit = _verify_current_workflow_commit(
                root, parsed.current_workflow_execution_commit
            )
            raw_chain = _read_regular_file(
                parsed.chain,
                label="chain",
                maximum=MAX_CHAIN_ARTIFACT_BYTES,
            )
            if command == "protected-chain-replay":
                replay = require_verified_protected_chain_replay(
                    replay_protected_chain(
                        raw_chain,
                        repo_root=root,
                        expected_bootstrap_request_commit=(
                            parsed.bootstrap_request_commit
                        ),
                        expected_chain_head_digest=(
                            parsed.expected_chain_head_digest
                        ),
                    )
                )
                summary = _result(
                    "pass",
                    "protected_chain_replayed",
                    chainArtifactDigest=replay.artifact_digest,
                    bootstrapRequestCommit=replay.bootstrap_request_commit,
                    currentWorkflowExecutionCommit=workflow_commit,
                    candidateSourceCommit=replay.candidate_source_commit,
                    controlPlaneDigest=replay.control_plane_digest,
                    trustPolicyDigest=replay.trust_policy_digest,
                    jwksSnapshotDigest=replay.jwks_snapshot_digest,
                    eventCount=replay.event_count,
                    headSequence=replay.head_sequence,
                    headDigest=replay.head_digest,
                    headSourceCommit=replay.head_source_commit,
                    stateDigest=replay.state_digest,
                    machineEvidenceIndexDigest=(
                        replay.machine_evidence_index_digest
                    ),
                    machineEvidenceCount=len(replay.machine_evidence_index),
                )
                output = _atomic_output_directory(
                    parsed.output,
                    {
                        "phase-state.yaml": _canonical_output(replay.state_view),
                        "verification-result.json": _canonical_output(summary),
                    },
                )
                return 0, {**summary, "outputDirectory": str(output)}

            raw_bundle = _read_regular_file(
                parsed.bundle,
                label="bundle",
                maximum=MAX_BUNDLE_BYTES,
            )
            bundle_digest = _canonical_bundle_digest(raw_bundle)
            if parsed.expected_bundle_digest is not None:
                expected_bundle_digest = _cli_digest(
                    parsed.expected_bundle_digest,
                    "expectedBundleDigest",
                )
                if bundle_digest != expected_bundle_digest:
                    _chain_error(
                        "external_bundle_digest_mismatch",
                        "expectedBundleDigest",
                        "canonical bundle differs from the external digest pin",
                    )
            now = (
                datetime.now(timezone.utc).replace(microsecond=0)
                if clock is None
                else clock()
            )
            if not isinstance(now, datetime) or now.tzinfo is None:
                _chain_error(
                    "invalid_timestamp",
                    "clock",
                    "clock must return a timezone-aware datetime",
                )
            statement_timestamp = now.astimezone(timezone.utc).replace(microsecond=0)
            provider = (
                github_actions_append_token_provider
                if token_provider is None
                else token_provider
            )
            updated_chain, state_view = append_post_genesis(
                raw_chain,
                raw_bundle,
                repo_root=root,
                expected_bootstrap_request_commit=parsed.bootstrap_request_commit,
                expected_current_chain_head_digest=(
                    parsed.expected_current_chain_head_digest
                ),
                expected_operation=parsed.operation,
                expected_to_state=parsed.to_state,
                expected_work_unit=parsed.work_unit,
                expected_phase=parsed.phase,
                current_workflow_execution_commit=workflow_commit,
                statement_timestamp=statement_timestamp,
                token_provider=provider,
            )
            parsed_updated = parse_chain_artifact(updated_chain)
            event = parsed_updated.events[-1]
            state_chain = state_view.get("chain")
            if (
                not isinstance(state_chain, Mapping)
                or state_chain.get("headDigest") != parsed_updated.head_digest
                or state_chain.get("eventCount") != parsed_updated.event_count
            ):
                _chain_error(
                    "post_append_output_mismatch",
                    "stateView",
                    "updated transport and state view differ",
                )
            summary = _result(
                "pass",
                "protected_chain_appended",
                operation=parsed.operation,
                phase=parsed.phase,
                workUnit=parsed.work_unit,
                toState=parsed.to_state,
                bootstrapRequestCommit=parsed.bootstrap_request_commit,
                currentWorkflowExecutionCommit=workflow_commit,
                priorChainHeadDigest=parsed.expected_current_chain_head_digest,
                resultingChainHeadDigest=parsed_updated.head_digest,
                eventDigest=event["eventDigest"],
                eventCount=parsed_updated.event_count,
                stateDigest=state_view["stateDigest"],
                authorizationBundleDigest=bundle_digest,
                chainArtifactDigest=parsed_updated.artifact_digest,
            )
            output = _atomic_output_directory(
                parsed.output,
                {
                    "chain.json": updated_chain,
                    "event.json": _canonical_output(event),
                    "phase-state.yaml": _canonical_output(state_view),
                    "verification-result.json": _canonical_output(summary),
                },
            )
            return 0, {**summary, "outputDirectory": str(output)}
        except (WorkflowOrchestratorError, ChainArtifactError) as exc:
            issue = (
                exc.as_dict()
                if hasattr(exc, "as_dict")
                else {"code": exc.code, "path": exc.path, "message": exc.message}
            )
            return 6, _result("fail", exc.code, issues=[issue], **common)
    if command in {"approval-verify", "state-chain-verify"}:
        try:
            _protected_artifact_layout(parsed, root)
            request = load_strict_document(Path(parsed.request), label="request")
            approval = load_strict_document(Path(parsed.approval), label="approval")
            policy = load_strict_document(Path(parsed.policy), label="policy")
            request_schema = request.get("schemaVersion")
            if request_schema == "urn:agentapi-doctor:bootstrap-request:v1alpha3":
                jwks_path = _required_option(parsed, "jwks", protocol="R3")
                snapshot_digest = _required_option(
                    parsed, "expected_jwks_snapshot_digest", protocol="R3"
                )
                workflow_execution_commit = _required_option(
                    parsed, "expected_workflow_execution_commit", protocol="R3"
                )
                jwks = load_strict_document(Path(jwks_path), label="jwks")
                verified = verify_control_plane_approval_v2(
                    request=request,
                    approval=approval,
                    policy=policy,
                    jwks_snapshot=jwks,
                    expected_policy_digest=parsed.expected_policy_digest,
                    expected_jwks_snapshot_digest=snapshot_digest,
                    expected_control_plane_digest=(
                        parsed.expected_control_plane_digest
                    ),
                    expected_candidate_source_commit=(
                        parsed.expected_candidate_source_commit
                    ),
                    expected_request_digest=parsed.expected_request_digest,
                    expected_workflow_execution_commit=workflow_execution_commit,
                )
                protocol = "R3"
            elif request_schema == "urn:agentapi-doctor:bootstrap-request:v1alpha2":
                ssh_keygen_digest = _required_option(
                    parsed, "expected_ssh_keygen_digest", protocol="R2"
                )
                verified = verify_control_plane_approval(
                    request=request,
                    approval=approval,
                    policy=policy,
                    expected_policy_digest=parsed.expected_policy_digest,
                    expected_control_plane_digest=(
                        parsed.expected_control_plane_digest
                    ),
                    expected_candidate_source_commit=(
                        parsed.expected_candidate_source_commit
                    ),
                    expected_request_digest=parsed.expected_request_digest,
                    expected_ssh_keygen_digest=ssh_keygen_digest,
                )
                protocol = "R2"
            else:
                raise ProtectedVerificationError(
                    "invalid_request",
                    "request.schemaVersion",
                    "unsupported protected-control-plane request revision",
                )
            if candidate["controlPlaneDigest"] != parsed.expected_control_plane_digest:
                raise ProtectedVerificationError(
                    "control_plane_digest_mismatch",
                    "repository",
                    "verified repository control plane differs from external pin",
                )
            if command == "approval-verify":
                return 0, _result(
                    "pass",
                    (
                        "verified_pending_genesis"
                        if verified["decision"] == "APPROVE"
                        else "verified_rejection"
                    ),
                    protocol=protocol,
                    approval=verified,
                    **common,
                )
            events = load_event_directory(Path(parsed.events))
            prior_events = (
                load_event_directory(Path(parsed.prior_events))
                if parsed.prior_events
                else []
            )
            if protocol == "R3":
                if prior_events:
                    raise ProtectedVerificationError(
                        "unexpected_prior_chain",
                        "priorEvents",
                        "R3 Genesis verification must start from an empty chain",
                    )
                if len(events) != 1:
                    raise ProtectedVerificationError(
                        "unsupported_state_chain",
                        "events",
                        "the R3 bootstrap command accepts exactly one Genesis event",
                    )
                policy_result = validate_trust_policy_v2(
                    policy,
                    jwks_snapshot=jwks,
                    expected_policy_digest=parsed.expected_policy_digest,
                    expected_jwks_snapshot_digest=snapshot_digest,
                    expected_control_plane_digest=(
                        parsed.expected_control_plane_digest
                    ),
                )
                state_view = verify_genesis_event_v2(
                    event=events[0],
                    policy_result=policy_result,
                    approval_result=verified,
                    jwks_snapshot=jwks,
                    expected_control_plane_digest=(
                        parsed.expected_control_plane_digest
                    ),
                    expected_chain_head_digest=parsed.expected_chain_head_digest,
                    contract_digests=candidate["componentDigests"],
                    repo_root=root,
                )
            else:
                state_view = replay_state_events(
                    events=events,
                    policy=policy,
                    approval_result=verified,
                    expected_policy_digest=parsed.expected_policy_digest,
                    expected_control_plane_digest=(
                        parsed.expected_control_plane_digest
                    ),
                    expected_chain_head_digest=parsed.expected_chain_head_digest,
                    expected_ssh_keygen_digest=ssh_keygen_digest,
                    contract_digests=candidate["componentDigests"],
                    repo_root=root,
                    prior_events=prior_events,
                )
            if parsed.phase_state:
                compare_state_view(Path(parsed.phase_state), state_view)
            return 0, _result(
                "pass",
                "signed_state_chain_verified",
                protocol=protocol,
                stateView=state_view,
                phaseStateCompared=bool(parsed.phase_state),
                **common,
            )
        except ProtectedVerificationError as exc:
            return 6, _result("fail", exc.code, issues=[exc.as_dict()], **common)
    if command in {"bootstrap", "control-plane-verify"}:
        return 0, _result("pass", "candidate_valid", mode=candidate["mode"], **common)
    if command == "state-verify":
        return 0, _result(
            "pass",
            "pre_genesis",
            state="PRE_GENESIS",
            mode=candidate["mode"],
            **common,
        )
    if command == "gate-unit":
        unit = _argument_value(parsed, "unit", "unit_option")
        path = f"execution/gates/p00/{unit}.yaml"
        evaluator_failure = _gate_evaluator_failure(root, [path])
        if evaluator_failure is not None:
            return 3 if evaluator_failure[
                "reasonCode"
            ] == "missing_evaluator" else 2, evaluator_failure
        return 5, _result(
            "fail",
            "independent_approval_and_genesis_required",
            unit=unit,
            **common,
        )
    if command in {"gate", "gate-phase"}:
        phase = _argument_value(parsed, "phase", "phase_option")
        if phase != "P00":
            return 2, _result("fail", "unknown_gate", phase=phase)
        evaluator_failure = _gate_evaluator_failure(
            root, ["execution/gates/p00/aggregate.yaml"]
        )
        if evaluator_failure is not None:
            return 3, evaluator_failure
        return 5, _result(
            "fail",
            "independent_approval_and_genesis_required",
            phase=phase,
            **common,
        )
    if command == "gate-all":
        evaluator_failure = _gate_evaluator_failure(
            root,
            [
                "execution/gates/p00/P00.W01.yaml",
                "execution/gates/p00/P00.W02.yaml",
                "execution/gates/p00/P00.W03.yaml",
                "execution/gates/p00/P00.W04.yaml",
                "execution/gates/p00/P00.W05.yaml",
                "execution/gates/p00/aggregate.yaml",
            ],
        )
        if evaluator_failure is not None:
            return 3, evaluator_failure
        return 5, _result("fail", "independent_approval_and_genesis_required", **common)
    if command == "evidence-verify":
        return 3, _result("fail", "approved_evidence_verifier_unavailable", **common)
    if command == "clean-checkout":
        phase = _argument_value(parsed, "phase", "phase_option")
        return 3, _result(
            "fail",
            "approved_clean_checkout_orchestrator_unavailable",
            phase=phase,
            **common,
        )
    if command == "ga-gate":
        return 3, _result("fail", "ga_control_plane_unavailable", **common)
    if command in GATE_COMMANDS:
        return 1, _result(
            "fail",
            "independent_approval_and_genesis_required",
            message=(
                "gate execution is unavailable before an independently reviewed "
                "approval attestation and protected-workflow Genesis"
            ),
            **common,
        )
    return 2, _result("fail", "unknown_command", command=command)


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        arguments, root = _extract_root(raw)
        parsed = _parser().parse_args(arguments)
        code, output = run(parsed, root)
    except ValueError as exc:
        code = 2
        output = _result("fail", "invalid_arguments", message=str(exc))
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
