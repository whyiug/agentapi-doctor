#!/usr/bin/env python3
"""Generate an unapproved, commit-bound P00.B00-R2 review request.

The helper may bind candidate inputs and draft a request.  It cannot sign an
approval, configure trust roots, create Genesis, write state, or emit evidence.
"""

from __future__ import annotations

import argparse
import json
import os
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
    ACTIVE_REQUEST_PATH,
    PREVIOUS_CANDIDATE_COMMIT,
    PREVIOUS_CONTROL_PLANE_DIGEST,
    PREVIOUS_REQUEST_DIGEST,
    REQUIRED_ANTI_PLACEHOLDER_TESTS,
    REQUIRED_FORBIDDEN_ABSENCE,
    REQUIRED_PROTECTED_VERIFIER_TESTS,
    validate_bootstrap_candidate,
)


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CONTROL_DIGEST_RE = re.compile(r'("controlPlaneDigest"\s*:\s*")sha256:[^"\\]+(")')


def _git(
    root: Path, *arguments: str, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=capture,
        text=True,
        timeout=30,
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
                ["git", "-C", str(root), "show", f"{source_commit}:{relative}"],
                check=True,
                capture_output=True,
                timeout=30,
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


def _decisions() -> list[dict[str, str]]:
    return [
        {
            "id": "canonical-plan-path",
            "question": "Continue to use agentapi-doctor-Plan.md as the canonical P00 plan path.",
        },
        {
            "id": "working-name-and-license-direction",
            "question": "Continue the private working name and provisional Apache-2.0 plus DCO direction pending P00 governance work.",
        },
        {
            "id": "digest-projection",
            "question": "Approve the bootstrap-canonical-json-v1 projection and controlPlaneDigest-only self-reference normalization for this revision.",
        },
        {
            "id": "protected-dataset-freeze",
            "question": "Keep datasets pending and require independently frozen non-null dataset/evaluator digests before W03 or W04 activation.",
        },
        {
            "id": "p00-contracts-and-gates",
            "question": "Reconfirm the P00 contracts, catalogs, thresholds, impact map, and fail-closed gates under the new aggregate digest.",
        },
        {
            "id": "protected-genesis",
            "question": "Keep Genesis exclusively in a separately authorized protected writer after signature and environment controls are proven.",
        },
        {
            "id": "post-genesis-verifier",
            "question": "Approve the read-only approval and signed StateEvent verification semantics in this candidate.",
        },
        {
            "id": "external-actions",
            "question": "Keep outreach, public claims, publication, and remote mutations human-authorized rather than machine evidence.",
        },
        {
            "id": "protected-verifier-format",
            "question": "Approve detached-domain OpenSSH SSHSIG envelopes, exact canonical payloads, event digests, and Plan section 29.2 replay invariants.",
        },
        {
            "id": "externally-pinned-trust-roots",
            "question": "Provide and independently pin a configured signer roster, policy digest, candidate commit, request/control-plane digests, and chain head before authoritative use.",
        },
        {
            "id": "read-only-protected-workflow",
            "question": "Approve only the fail-closed read-only workflow candidate; no Genesis writer or repository write is included.",
        },
        {
            "id": "request-revision-chain",
            "question": "Accept P00.B00-R2 as a commit-bound successor while preserving the original P00.B00 request unchanged.",
        },
    ]


def build_request(
    root: Path,
    *,
    base_commit: str,
    candidate_source_commit: str,
    digest: str,
    components: list[dict[str, str]],
) -> dict:
    return {
        "schemaVersion": "urn:agentapi-doctor:bootstrap-request:v1alpha2",
        "kind": "BootstrapControlPlaneReviewRequest",
        "requestId": "P00.B00-R2",
        "revision": 2,
        "previousRequest": {
            "requestId": "P00.B00",
            "revision": 1,
            "requestDigest": PREVIOUS_REQUEST_DIGEST,
            "controlPlaneDigest": PREVIOUS_CONTROL_PLANE_DIGEST,
            "candidateSourceCommit": PREVIOUS_CANDIDATE_COMMIT,
        },
        "requestStatus": "pending_review",
        "candidate": {
            "baseCommit": base_commit,
            "candidateSourceCommit": candidate_source_commit,
            "gitObjectFormat": "sha1",
            "canonicalPlanPath": "agentapi-doctor-Plan.md",
            "controlPlaneDigest": digest,
        },
        "componentDigests": {item["path"]: item["digest"] for item in components},
        "digestGroups": approval_digest_groups(components),
        "antiPlaceholderTests": {
            "command": "make test-bootstrap",
            "protectedFile": "test/bootstrap/test_phasegate.py",
            "cases": list(REQUIRED_ANTI_PLACEHOLDER_TESTS),
        },
        "protectedVerifierTests": {
            "command": "make test-protected-verifier",
            "protectedFile": "test/bootstrap/test_protected_verifier.py",
            "cases": list(REQUIRED_PROTECTED_VERIFIER_TESTS),
        },
        "diff": {
            "baseCommit": base_commit,
            "entries": _candidate_diff(root, base_commit),
            "scope": [
                "read-only OpenSSH approval verifier",
                "signed and externally anchored StateEvent replay",
                "pending trust-root policy and protected workflow contract",
                "protected adversarial verifier tests",
                "versioned P00.B00-R2 review request",
            ],
            "forbiddenArtifactsVerifiedAbsent": list(REQUIRED_FORBIDDEN_ABSENCE),
        },
        "decisionsRequested": _decisions(),
        "limitations": [
            "This request is not an approval, signature, state transition, gate result, or completion claim.",
            "The committed trust policy is pending_trust_roots and contains no signer key; real approval verification therefore fails closed.",
            "Every authoritative invocation must receive externally pinned policy, request, control-plane, candidate commit, and chain-head values.",
            "A hash chain without an external head or protected prior-prefix anchor cannot detect a signed tail truncation.",
            "The workflow is read-only, non-authoritative, and cannot create Genesis, transitions, approvals, or phase-state.",
            "Private-repository environment required-reviewer capability and immutable runtime/toolchain evidence remain unproved.",
            "Transition evidence/approval digests are signed by the protected workflow but full production evidence recomputation remains a later approved evaluator concern.",
            "Only the bootstrap evaluators are implemented; planned P00 machine evaluators remain fail-closed.",
        ],
        "nextAuthorizedAction": (
            "independent review of the exact candidateSourceCommit, controlPlaneDigest, "
            "policy/workflow design, and protected tests; do not create Genesis"
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
    if args.base_commit != PREVIOUS_CANDIDATE_COMMIT:
        parser.error("--base-commit must be the previous committed P00.B00 candidate")
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
            "refusing to generate a request with pre-Genesis state present: "
            + ", ".join(present)
        )
    digest, _ = compute_control_plane_digest(root)
    _bind_contract_references(root, digest)
    rebound_digest, components = compute_control_plane_digest(root)
    if rebound_digest != digest:
        raise RuntimeError("binding changed the normalized control-plane digest")
    validate_bootstrap_candidate(root, require_request=False)
    _ensure_source_commit_matches_inputs(root, args.candidate_source_commit)
    request = build_request(
        root,
        base_commit=args.base_commit,
        candidate_source_commit=args.candidate_source_commit,
        digest=rebound_digest,
        components=components,
    )
    output = root / ACTIVE_REQUEST_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = (
        json.dumps(request, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output, flags, 0o644)
    except FileExistsError:
        if output.is_symlink() or output.read_text(encoding="utf-8") != serialized:
            raise RuntimeError(
                "refusing to overwrite an existing non-identical P00.B00-R2 request"
            )
    except OSError as exc:
        raise RuntimeError(
            f"cannot create immutable P00.B00-R2 request: {exc}"
        ) from exc
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(serialized)
    print(
        json.dumps(
            {
                "status": "candidate_request_generated",
                "requestId": "P00.B00-R2",
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
