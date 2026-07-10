#!/usr/bin/env python3
"""Bind the B00 candidate digest and generate its unapproved review request.

This helper cannot create approval facts, Genesis, transitions, phase state, or
gate evidence.  Its output is only a deterministic request for an independent
reviewer and protected workflow.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.phasegate.digest import (  # noqa: E402
    approval_digest_groups,
    compute_control_plane_digest,
    read_input_manifest,
)
from tools.phasegate.validation import (  # noqa: E402
    REQUIRED_ANTI_PLACEHOLDER_TESTS,
    REQUIRED_FORBIDDEN_ABSENCE,
    validate_bootstrap_candidate,
)


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CONTROL_DIGEST_RE = re.compile(r'("controlPlaneDigest"\s*:\s*")sha256:[^"\\]+(")')


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


def _candidate_diff(root: Path, base_commit: str) -> list[dict[str, str]]:
    tracked = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-status", base_commit, "--"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    untracked = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    entries: dict[str, str] = {}
    for line in tracked.stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        status = fields[0]
        path = fields[-1]
        entries[path] = status
    for path in untracked.stdout.splitlines():
        if path:
            entries.setdefault(path, "A")
    entries.setdefault("execution/approval-requests/P00.B00.yaml", "A")
    return [{"status": entries[path], "path": path} for path in sorted(entries)]


def build_request(
    root: Path, base_commit: str, digest: str, components: list[dict[str, str]]
) -> dict:
    return {
        "schemaVersion": "urn:agentapi-doctor:bootstrap-request:v1alpha1",
        "kind": "BootstrapControlPlaneReviewRequest",
        "requestId": "P00.B00",
        "requestStatus": "pending_review",
        "candidate": {
            "baseCommit": base_commit,
            "canonicalPlanPath": "agentapi-doctor-Plan.md",
            "controlPlaneDigest": digest,
            "sourceCommitBinding": "independent-review-must-bind-the-reviewed-candidate-commit",
        },
        "componentDigests": {item["path"]: item["digest"] for item in components},
        "digestGroups": approval_digest_groups(components),
        "antiPlaceholderTests": {
            "command": "make test-bootstrap",
            "protectedFile": "test/bootstrap/test_phasegate.py",
            "cases": list(REQUIRED_ANTI_PLACEHOLDER_TESTS),
        },
        "diff": {
            "baseCommit": base_commit,
            "entries": _candidate_diff(root, base_commit),
            "scope": [
                "AGENTS.md",
                "Makefile",
                "execution candidate contracts, manifests, catalogs, and gate definitions",
                "tools/phasegate bootstrap verifier",
                "test/bootstrap protected negative tests",
            ],
            "forbiddenArtifactsVerifiedAbsent": list(REQUIRED_FORBIDDEN_ABSENCE),
        },
        "decisionsRequested": [
            {
                "id": "canonical-plan-path",
                "question": "Accept agentapi-doctor-Plan.md as the P00 canonical plan path instead of creating a drifting Plan.md copy.",
            },
            {
                "id": "working-name-and-license-direction",
                "question": "Confirm agentapi-doctor remains a private working name and Apache-2.0 plus DCO remains the provisional P00 direction pending the named governance work.",
            },
            {
                "id": "digest-projection",
                "question": "Approve bootstrap-canonical-json-v1 and normalization of only controlPlaneDigest self-references for this pre-P01 candidate.",
            },
            {
                "id": "protected-dataset-freeze",
                "question": "Approve freezing catalog definitions now while requiring independently frozen non-null dataset and evaluator digests before W03 or W04 activation.",
            },
            {
                "id": "p00-contracts-and-gates",
                "question": "Approve the P00 aggregate, W01-W05 contracts, evaluator/evidence catalogs, thresholds, impact map, and fail-closed gate definitions bound above.",
            },
            {
                "id": "protected-genesis",
                "question": "If the candidate is accepted, create a separate commit-bound review record and let only the protected workflow create Genesis and activate P00.W01.",
            },
            {
                "id": "post-genesis-verifier",
                "question": "Approve and provide the trusted signature, identity, and state-replay mechanism before Genesis; the B00 runner only validates PRE_GENESIS absence and fails closed afterward.",
            },
            {
                "id": "external-actions",
                "question": "Confirm outreach, public claims, registry publication, and later remote pushes remain human-authorized actions rather than machine evidence.",
            },
        ],
        "limitations": [
            "This request is not an approval, state transition, gate result, or P00 completion claim.",
            "Only the two bootstrap evaluators are implemented; every other machine evaluator is planned and fail-closed.",
            "No corpus or experiment dataset digest exists yet; insufficient samples cannot pass.",
            "The production Go toolchain and product contracts remain future approved work.",
            "Post-Genesis approval signature verification, transition replay, activation, and evidence generation are not implemented in B00 and cannot be inferred from this request.",
        ],
        "nextAuthorizedAction": "independent review of the candidate commit and digest; no activation is performed by this request",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--base-commit", required=True)
    args = parser.parse_args()
    if not COMMIT_RE.fullmatch(args.base_commit):
        parser.error("--base-commit must be a lowercase 40-character Git commit")
    root = Path(args.root).resolve()
    forbidden = [
        "execution/phase-state.yaml",
        "execution/transitions",
        "execution/approvals",
        "execution/waivers.yaml",
    ]
    present = [path for path in forbidden if (root / path).exists()]
    if present:
        raise RuntimeError(
            "refusing to generate a B00 request with pre-Genesis state present: "
            + ", ".join(present)
        )
    digest, _ = compute_control_plane_digest(root)
    _bind_contract_references(root, digest)
    rebound_digest, components = compute_control_plane_digest(root)
    if rebound_digest != digest:
        raise RuntimeError("binding changed the normalized control-plane digest")
    validate_bootstrap_candidate(root, require_request=False)
    request = build_request(root, args.base_commit, rebound_digest, components)
    output = root / "execution/approval-requests/P00.B00.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(request, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "candidate_request_generated",
                "controlPlaneDigest": rebound_digest,
                "componentCount": len(components),
                "output": str(output.relative_to(root)),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
