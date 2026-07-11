#!/usr/bin/env python3
"""Command-line entry point for the dependency-free bootstrap phase gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

# Direct execution does not put the repository root on ``sys.path``.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.phasegate.validation import (  # noqa: E402
    ValidationError,
    ensure_gate_is_executable,
    validate_bootstrap_candidate,
)
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    compare_state_view,
    load_event_directory,
    load_strict_document,
    replay_state_events,
    verify_control_plane_approval,
)


RESULT_SCHEMA = "urn:agentapi-doctor:phasegate-result:v1"
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
    approval.add_argument("--expected-ssh-keygen-digest", required=True)
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
    state_chain.add_argument("--expected-ssh-keygen-digest", required=True)
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


def run(parsed: argparse.Namespace, root: Path) -> tuple[int, dict[str, Any]]:
    command = parsed.command
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
    if command in {"approval-verify", "state-chain-verify"}:
        try:
            _protected_artifact_layout(parsed, root)
            request = load_strict_document(Path(parsed.request), label="request")
            approval = load_strict_document(Path(parsed.approval), label="approval")
            policy = load_strict_document(Path(parsed.policy), label="policy")
            verified = verify_control_plane_approval(
                request=request,
                approval=approval,
                policy=policy,
                expected_policy_digest=parsed.expected_policy_digest,
                expected_control_plane_digest=parsed.expected_control_plane_digest,
                expected_candidate_source_commit=(
                    parsed.expected_candidate_source_commit
                ),
                expected_request_digest=parsed.expected_request_digest,
                expected_ssh_keygen_digest=parsed.expected_ssh_keygen_digest,
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
                    approval=verified,
                    **common,
                )
            events = load_event_directory(Path(parsed.events))
            prior_events = (
                load_event_directory(Path(parsed.prior_events))
                if parsed.prior_events
                else []
            )
            state_view = replay_state_events(
                events=events,
                policy=policy,
                approval_result=verified,
                expected_policy_digest=parsed.expected_policy_digest,
                expected_control_plane_digest=parsed.expected_control_plane_digest,
                expected_chain_head_digest=parsed.expected_chain_head_digest,
                expected_ssh_keygen_digest=parsed.expected_ssh_keygen_digest,
                contract_digests=candidate["componentDigests"],
                repo_root=root,
                prior_events=prior_events,
            )
            if parsed.phase_state:
                compare_state_view(Path(parsed.phase_state), state_view)
            return 0, _result(
                "pass",
                "signed_state_chain_verified",
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
