#!/usr/bin/env python3
"""Generate an unapproved, commit-bound P00.B00-R3 review request.

The helper binds an already committed control-plane source tree and drafts a
review request.  It cannot sign an approval, assert repository protection,
create Genesis, write state, or emit completion evidence.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.phasegate.digest import (  # noqa: E402
    approval_digest_groups,
    compute_control_plane_digest,
    read_input_manifest,
)
from tools.phasegate.validation import (  # noqa: E402
    ACTIVE_REQUEST_PATH,
    REQUIRED_ANTI_PLACEHOLDER_TESTS,
    REQUIRED_DECISION_IDS,
    REQUIRED_FORBIDDEN_ABSENCE,
    R2_CANDIDATE_SOURCE_COMMIT,
    R2_CONTROL_PLANE_DIGEST,
    R2_REQUEST_COMMIT,
    R2_REQUEST_DIGEST,
    validate_bootstrap_candidate,
)


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CONTROL_DIGEST_RE = re.compile(r'("controlPlaneDigest"\s*:\s*")sha256:[^"\\]+(")')

TEST_SUITES = {
    "bootstrap": "test/bootstrap/test_phasegate.py",
    "chainArtifact": "test/bootstrap/test_chain_artifact.py",
    "chainWitness": "test/bootstrap/test_chain_witness.py",
    "communityFacts": "test/bootstrap/test_community_facts.py",
    "controlContext": "test/bootstrap/test_control_context.py",
    "delegation": "test/bootstrap/test_delegation.py",
    "executionArtifact": "test/bootstrap/test_execution_artifact.py",
    "externalFacts": "test/bootstrap/test_external_facts.py",
    "gateRunner": "test/bootstrap/test_gate_runner.py",
    "lifecycleEvidence": "test/bootstrap/test_lifecycle_evidence.py",
    "phaseBundle": "test/bootstrap/test_phase_bundle.py",
    "phaseEvidence": "test/bootstrap/test_phase_evidence.py",
    "protectedChainCli": "test/bootstrap/test_protected_chain_cli.py",
    "protectedStateWriterWorkflow": "test/bootstrap/test_protected_state_writer_workflow.py",
    "protectedV1Historical": "test/bootstrap/test_protected_verifier.py",
    "protectedV2": "test/bootstrap/test_protected_v2.py",
    "oidc": "test/bootstrap/test_oidc.py",
    "oidcProvenance": "test/bootstrap/test_oidc_provenance.py",
    "postEventWriter": "test/bootstrap/test_post_event_writer.py",
    "runExecutor": "test/bootstrap/test_run_executor.py",
    "serializedBundle": "test/bootstrap/test_serialized_bundle.py",
    "sshsig": "test/bootstrap/test_sshsig.py",
    "stateChainV2": "test/bootstrap/test_state_chain_v2.py",
    "stateWriter": "test/bootstrap/test_state_writer.py",
    "workflowOrchestrator": "test/bootstrap/test_workflow_orchestrator.py",
    "provenance": "test/bootstrap/test_provenance.py",
    "provenanceWriter": "test/bootstrap/test_provenance_writer.py",
    "p00Evaluators": "test/bootstrap/test_p00_evaluators.py",
}


def _git(
    root: Path, *arguments: str, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        capture_output=capture,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": os.environ.get("HOME", "/nonexistent"),
        },
    )


def _bind_contract_references(root: Path, digest: str) -> int:
    _, inputs = read_input_manifest(root)
    changed = 0
    for entry in inputs:
        if entry["kind"] not in {
            "json",
            "json-yaml",
            "manifest",
            "contract",
            "catalog",
            "gate",
        }:
            continue
        path = root / entry["path"]
        original = path.read_text(encoding="utf-8")
        updated, replacements = CONTROL_DIGEST_RE.subn(
            lambda match: f"{match.group(1)}{digest}{match.group(2)}", original
        )
        if replacements:
            json.loads(updated)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed += 1
    return changed


def _ensure_source_commit_matches_inputs(root: Path, source_commit: str) -> None:
    _git(root, "cat-file", "-e", f"{source_commit}^{{commit}}")
    _, inputs = read_input_manifest(root)
    mismatches: list[str] = []
    for entry in inputs:
        relative = entry["path"]
        try:
            committed = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(root),
                    "show",
                    f"{source_commit}:{relative}",
                ],
                check=True,
                capture_output=True,
                timeout=30,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "HOME": "/nonexistent",
                },
            ).stdout
        except subprocess.CalledProcessError:
            mismatches.append(relative)
            continue
        if committed != (root / relative).read_bytes():
            mismatches.append(relative)
    if mismatches:
        raise RuntimeError(
            "candidateSourceCommit does not exactly contain current control-plane inputs: "
            + ", ".join(mismatches)
        )


def _candidate_diff(root: Path, base_commit: str) -> list[dict[str, str]]:
    tracked = _git(root, "diff", "--name-status", base_commit, "--")
    untracked = _git(root, "ls-files", "--others", "--exclude-standard")
    entries: dict[str, str] = {}
    for line in tracked.stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        entries[fields[-1]] = fields[0]
    for path in untracked.stdout.splitlines():
        if path:
            entries.setdefault(path, "A")
    entries.setdefault(ACTIVE_REQUEST_PATH, "A")
    return [{"status": entries[path], "path": path} for path in sorted(entries)]


def _test_cases(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    cases = sorted(
        {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        },
        key=lambda item: item.encode("utf-8"),
    )
    if not cases:
        raise RuntimeError(f"protected test suite contains no test cases: {path}")
    return cases


def _test_suites(root: Path) -> dict[str, dict[str, Any]]:
    suites: dict[str, dict[str, Any]] = {}
    for suite, relative in TEST_SUITES.items():
        filename = Path(relative).name
        suites[suite] = {
            "command": (
                "python3 -m unittest discover -s test/bootstrap "
                f"-p '{filename}'"
            ),
            "protectedFile": relative,
            "cases": _test_cases(root / relative),
        }
    bootstrap_cases = set(suites["bootstrap"]["cases"])
    missing = sorted(set(REQUIRED_ANTI_PLACEHOLDER_TESTS) - bootstrap_cases)
    if missing:
        raise RuntimeError(f"required anti-placeholder tests are missing: {missing}")
    return suites


def _decisions() -> list[dict[str, str]]:
    decisions = {
        "canonical-plan-path": (
            "Continue to use agentapi-doctor-Plan.md as the canonical P00 plan path."
        ),
        "working-name-and-license-direction": (
            "Continue the AgentAPI Doctor working name and provisional Apache-2.0 plus DCO direction pending P00 governance evidence."
        ),
        "digest-projection": (
            "Approve bootstrap-canonical-json-v1 and controlPlaneDigest-only self-reference normalization for R3."
        ),
        "protected-dataset-freeze": (
            "Approve late-bound SignedProtectedInputFreeze semantics; an unfrozen dataset can never satisfy a criterion."
        ),
        "p00-contracts-and-gates": (
            "Approve the exact P00 contracts, catalogs, thresholds, paired evaluators, provenance objects, and fail-closed gates."
        ),
        "protected-genesis": (
            "Allow one OIDC-signed Genesis artifact only after exact SSHSIG approval and live public protected-main proof; do not write repository state automatically."
        ),
        "post-genesis-verifier": (
            "Approve portable SSHSIG, offline historical-JWKS OIDC verification, protected result provenance, and transition replay semantics."
        ),
        "external-actions": (
            "Keep outreach, public claims, publication, visibility changes, and third-party facts human-authorized and independently attested."
        ),
        "protected-verifier-format": (
            "Approve detached OpenSSH SSHSIG v1 human statements and digest-bound GitHub Actions OIDC StateEvent statements."
        ),
        "externally-pinned-trust-roots": (
            "Approve the exact SSH principal, historical GitHub OIDC JWK snapshot, validity windows, policy digest, source/request/workflow commits, and chain-head pins."
        ),
        "read-only-protected-workflow": (
            "Approve artifact-only protected workflows with contents read, no repository write, no candidate code execution, and separately reviewed import."
        ),
        "request-revision-chain": (
            "Accept P00.B00-R3 as the immutable successor to committed R2 while preserving both earlier request files byte-for-byte."
        ),
    }
    if set(decisions) != set(REQUIRED_DECISION_IDS):
        raise RuntimeError("R3 decision set differs from the protected validator")
    return [{"id": key, "question": decisions[key]} for key in sorted(decisions)]


def _ambiguities(root: Path) -> list[dict[str, str]]:
    register = json.loads(
        (root / "execution/protected-verifier/ambiguities.yaml").read_text(
            encoding="utf-8"
        )
    )
    result = []
    for entry in register["entries"]:
        result.append(
            {
                "id": entry["id"],
                "decisionCandidate": entry["decisionCandidate"],
                "currentEffect": entry["currentEffect"],
            }
        )
    return result


def build_request(
    root: Path,
    *,
    candidate_source_commit: str,
    digest: str,
    components: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "schemaVersion": "urn:agentapi-doctor:bootstrap-request:v1alpha3",
        "kind": "BootstrapControlPlaneReviewRequest",
        "requestId": "P00.B00-R3",
        "revision": 3,
        "previousRequest": {
            "requestId": "P00.B00-R2",
            "revision": 2,
            "requestDigest": R2_REQUEST_DIGEST,
            "controlPlaneDigest": R2_CONTROL_PLANE_DIGEST,
            "candidateSourceCommit": R2_CANDIDATE_SOURCE_COMMIT,
            "requestCommit": R2_REQUEST_COMMIT,
        },
        "requestStatus": "pending_review",
        "candidate": {
            "baseCommit": R2_REQUEST_COMMIT,
            "candidateSourceCommit": candidate_source_commit,
            "gitObjectFormat": "sha1",
            "canonicalPlanPath": "agentapi-doctor-Plan.md",
            "controlPlaneDigest": digest,
        },
        "componentDigests": {item["path"]: item["digest"] for item in components},
        "digestGroups": approval_digest_groups(components),
        "testSuites": _test_suites(root),
        "diff": {
            "baseCommit": R2_REQUEST_COMMIT,
            "entries": _candidate_diff(root, R2_REQUEST_COMMIT),
            "scope": [
                "portable dependency-free OpenSSH SSHSIG verification",
                "offline digest-bound GitHub Actions OIDC verification",
                "public protected-main artifact-only Genesis writer",
                "strict protected input, criterion, transition proof, and approval provenance",
                "implemented paired P00 machine evaluators",
                "fixed-command network-isolated P00 Run A/B executor",
                "chain-witness-bound post-Genesis event projection and replay verifier",
                "late-bound independently signed dataset freeze",
                "versioned P00.B00-R3 review request",
            ],
            "forbiddenArtifactsVerifiedAbsent": list(REQUIRED_FORBIDDEN_ABSENCE),
        },
        "decisionsRequested": _decisions(),
        "ambiguities": _ambiguities(root),
        "limitations": [
            "This request is not an approval, signature, repository-protection fact, state transition, gate result, or completion claim.",
            "The repository is currently private and unprotected; authoritative Genesis remains blocked until an explicitly authorized public protected main exists and live protection is captured.",
            "The committed SSH principal is a candidate trust root; only a matching detached signature over the exact R3 envelope can authorize the reviewed decision.",
            "The historical GitHub OIDC JWK snapshot is approval-bound and replay is offline; online key refresh cannot silently authorize old events.",
            "The GitHub-hosted job retains platform network access; only fixed Run A/B child commands are isolated by a capability-probed Linux user/network namespace.",
            "EXTERNAL, TIME, and HUMAN criteria remain incomplete without their independent fact verifiers and required signatures.",
            "The checked-in state-writer has separate Genesis and append modes. Append mode can replay and append raw authorization bundles for P00 work-unit readiness, activation, convergence, evidence attachment, and the P00 phase aggregate, but this request records no execution result and cannot itself produce convergence evidence.",
            "Witness-bound lifecycle RESUME verification exists only as a library boundary in this revision; the protected workflow does not append it. Impact/control invalidation and control-plane supersession fail closed pending separately approved batch and state-revision semantics.",
            "P01 and later control-plane changes remain blocked until separately approved ControlPlaneRevision replay semantics are implemented.",
        ],
        "nextAuthorizedAction": (
            "independent review and detached SSHSIG decision over the exact R3 request, "
            "candidate source commit, future protected-main workflow execution commit, "
            "control-plane/policy/JWKS digests, all decisions, and all ambiguities; no "
            "Genesis may be created until public branch protection is independently proven"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--candidate-source-commit", required=True)
    args = parser.parse_args()
    for option, value in (
        ("--base-commit", args.base_commit),
        ("--candidate-source-commit", args.candidate_source_commit),
    ):
        if not COMMIT_RE.fullmatch(value):
            parser.error(f"{option} must be a lowercase 40-character Git commit")
    if args.base_commit != R2_REQUEST_COMMIT:
        parser.error("--base-commit must be the committed P00.B00-R2 request commit")
    root = Path(args.root).resolve()
    present = [
        path
        for path in (
            "execution/phase-state.yaml",
            "execution/transitions",
            "execution/approvals",
            "execution/waivers.yaml",
        )
        if (root / path).exists() or (root / path).is_symlink()
    ]
    if present:
        raise RuntimeError(
            "refusing to generate a request with pre-Genesis state present: "
            + ", ".join(present)
        )
    digest, _ = compute_control_plane_digest(root)
    _bind_contract_references(root, digest)
    rebound_digest, components = compute_control_plane_digest(root)
    if rebound_digest != digest:
        raise RuntimeError("binding changed the normalized control-plane digest")
    validate_bootstrap_candidate(
        root,
        require_request=False,
        require_pre_genesis=True,
    )
    _ensure_source_commit_matches_inputs(root, args.candidate_source_commit)
    request = build_request(
        root,
        candidate_source_commit=args.candidate_source_commit,
        digest=rebound_digest,
        components=components,
    )
    output = root / ACTIVE_REQUEST_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(request, ensure_ascii=False, indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output, flags, 0o644)
    except FileExistsError:
        if output.is_symlink() or output.read_text(encoding="utf-8") != serialized:
            raise RuntimeError(
                "refusing to overwrite an existing non-identical P00.B00-R3 request"
            )
    except OSError as exc:
        raise RuntimeError(
            f"cannot create immutable P00.B00-R3 request: {exc}"
        ) from exc
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(serialized)
    print(
        json.dumps(
            {
                "status": "candidate_request_generated",
                "requestId": "P00.B00-R3",
                "candidateSourceCommit": args.candidate_source_commit,
                "controlPlaneDigest": rebound_digest,
                "componentCount": len(components),
                "output": ACTIVE_REQUEST_PATH,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
