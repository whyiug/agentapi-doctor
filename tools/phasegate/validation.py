"""Fail-closed validation for the P00.B00 bootstrap candidate."""

from __future__ import annotations

from dataclasses import dataclass
import ast
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable

from .digest import (
    DigestError,
    approval_digest_groups,
    compute_control_plane_digest,
    load_json_yaml,
    read_input_manifest,
    sha256_bytes,
)
from .protected import (
    ProtectedVerificationError,
    document_digest,
)
from .oidc import jwks_snapshot_digest
from .protected_v2 import validate_trust_policy_v2


@dataclass(frozen=True)
class Issue:
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class ValidationError(ValueError):
    def __init__(self, issues: Iterable[Issue]):
        self.issues = tuple(issues)
        super().__init__("; ".join(issue.message for issue in self.issues))


REQUIRED_CONTRACT_FIELDS = {
    "schemaVersion",
    "kind",
    "contractStatus",
    "id",
    "phase",
    "title",
    "objective",
    "controlPlaneDigest",
    "readFirst",
    "inScope",
    "outOfScope",
    "protectedAcceptanceInputs",
    "mutableImplementationTests",
    "prerequisites",
    "deliverables",
    "verification",
    "convergence",
    "resourceBudget",
    "networkPolicy",
    "stopAndBlock",
    "humanGate",
}

REQUIRED_CRITERION_FIELDS = {
    "id",
    "kind",
    "evaluator",
    "threshold",
    "evidenceSchema",
}

IMPLEMENTED_HANDLERS = {
    "evaluator://bootstrap/control-plane/v1": "bootstrap.control_plane",
    "evaluator://bootstrap/anti-placeholder/v1": "bootstrap.anti_placeholder",
    "evaluator://research/competitive/v1": "p00.competitive",
    "evaluator://catalog/provenance-count/v1": "p00.provenance_count",
    "evaluator://corpus/reproduction/v1": "p00.reproduction",
    "evaluator://corpus/taxonomy/v1": "p00.taxonomy",
    "evaluator://corpus/replay/v1": "p00.replay",
    "evaluator://experiment/dual-view/v1": "p00.dual_view",
    "evaluator://experiment/minimization/v1": "p00.minimization",
    "evaluator://redaction/secret-canary/v1": "p00.secret_canary",
    "evaluator://attribution/unknown/v1": "p00.unknown",
    "evaluator://docs/license-links/v1": "p00.docs",
    "evaluator://phase/aggregate/v1": "p00.aggregate",
}

EXTERNAL_VERIFIER_SPECS = {
    "attestation://ci/cross-platform/v1": {
        "factory": "tools.phasegate.external_facts.build_p00_external_fact_verifier",
        "implementationPaths": ["tools/phasegate/external_facts.py"],
        "protectedTests": ["test/bootstrap/test_external_facts.py"],
        "factVerifierDigest": "sha256:c6e5a2fafacf90f1be7c51988641b000c9a576d103fd0e0a0ad8a6d72a832a29",
        "network": "fixed-read-only-github-rest",
    },
    "attestation://upstream/outreach/v1": {
        "factory": "tools.phasegate.community_facts.build_p00_community_fact_verifier",
        "implementationPaths": ["tools/phasegate/community_facts.py"],
        "protectedTests": ["test/bootstrap/test_community_facts.py"],
        "factVerifierDigest": "sha256:9a0427cdaae70b076572ebdc107d20cff6374a4374625a49074d5482305e3998",
        "network": "offline-signed-evidence",
    },
    "attestation://review/design-partners/v1": {
        "factory": "tools.phasegate.community_facts.build_p00_community_fact_verifier",
        "implementationPaths": ["tools/phasegate/community_facts.py"],
        "protectedTests": ["test/bootstrap/test_community_facts.py"],
        "factVerifierDigest": "sha256:9a0427cdaae70b076572ebdc107d20cff6374a4374625a49074d5482305e3998",
        "network": "offline-signed-evidence",
    },
    "attestation://review/external-feedback/v1": {
        "factory": "tools.phasegate.community_facts.build_p00_community_fact_verifier",
        "implementationPaths": ["tools/phasegate/community_facts.py"],
        "protectedTests": ["test/bootstrap/test_community_facts.py"],
        "factVerifierDigest": "sha256:9a0427cdaae70b076572ebdc107d20cff6374a4374625a49074d5482305e3998",
        "network": "offline-signed-evidence",
    },
}

FORBIDDEN_IMPLEMENTATION_TYPES = {
    "constant",
    "fixed",
    "always-pass",
    "file-exists-only",
    "manual-metric",
    "placeholder",
}

FORBIDDEN_RESULT_KEYS = {
    "metricValue",
    "numeratorValue",
    "denominatorValue",
    "passed",
    "verdict",
    "result",
}

FORBIDDEN_REQUEST_KEY_FRAGMENTS = {
    "reviewer",
    "signature",
    "attestation",
    "approvedby",
    "approvaldigest",
    "reviewedat",
}

FORBIDDEN_REQUEST_FACT_KEYS = {
    "actor",
    "approval",
    "approvals",
    "approved",
    "approvalresult",
    "approvalstatus",
    "decision",
    "decisionresult",
    "outcome",
    "timestamp",
}

REQUIRED_ANTI_PLACEHOLDER_TESTS = (
    "test_missing_declared_input_cannot_pass",
    "test_incomplete_contract_cannot_pass",
    "test_undeclared_control_plane_file_cannot_escape_digest",
    "test_duplicate_json_key_cannot_pass",
    "test_non_finite_number_cannot_pass",
    "test_constant_pass_evaluator_cannot_pass",
    "test_hand_entered_metric_result_cannot_pass",
    "test_control_plane_digest_drift_cannot_pass",
    "test_agent_authored_reviewer_identity_cannot_pass",
    "test_phase_state_before_genesis_cannot_pass",
    "test_transition_chain_before_genesis_cannot_pass",
    "test_runtime_logs_are_forbidden_pre_genesis_and_excluded_afterward",
    "test_missing_approval_request_cannot_pass",
    "test_previous_request_revision_cannot_be_rewritten",
    "test_request_cannot_bind_a_nonexistent_source_commit",
    "test_agent_cannot_configure_trust_roots_after_rebind",
    "test_state_transition_policy_cannot_be_weakened_after_rebind",
    "test_protected_workflow_cannot_gain_write_permission_after_rebind",
    "test_cross_platform_workflow_cannot_use_shallow_history_after_rebind",
    "test_gate_digest_mismatch_cannot_pass_after_rebind",
    "test_request_integrity_fields_cannot_be_forged",
    "test_empty_fail_open_gate_cannot_pass_after_rebind",
    "test_contract_without_phase_cannot_pass_after_rebind",
    "test_criterion_kind_and_threshold_drift_cannot_pass_after_rebind",
    "test_protected_acceptance_catalog_cannot_be_emptied_after_rebind",
    "test_bootstrap_catalog_cannot_be_emptied_after_rebind",
    "test_prerequisite_and_network_policy_cannot_be_relaxed_after_rebind",
    "test_contract_references_and_verification_cannot_be_replaced_after_rebind",
    "test_planned_evaluator_cannot_reuse_bootstrap_handler_after_rebind",
    "test_input_kind_cannot_hide_non_json_gate",
    "test_human_attestation_schema_cannot_be_weakened_after_rebind",
    "test_external_fact_schema_must_bind_subject_and_fact_digest",
    "test_r3_request_identity_and_ambiguity_projection_cannot_drift",
    "test_p00_evaluator_cannot_be_downgraded_after_rebind",
    "test_late_bound_dataset_cannot_be_prefilled_after_rebind",
    "test_protected_v2_contract_cannot_be_downgraded_after_rebind",
    "test_codeowners_cannot_be_weakened_after_rebind",
    "test_planned_machine_evaluator_is_not_executable",
    "test_unknown_evaluator_is_not_executable",
    "test_unit_gate_fails_before_independent_approval_and_genesis",
)

REQUIRED_PROTECTED_VERIFIER_TESTS = (
    "test_active_rejection_clears_pointers_without_false_conflict",
    "test_approval_bundle_cannot_hide_state_artifacts",
    "test_approval_namespace_replay_is_rejected",
    "test_candidate_source_commit_pin_is_required",
    "test_claimed_reviewer_role_must_match_policy",
    "test_event_chain_reordering_is_rejected",
    "test_evidence_attachment_is_bound_and_does_not_change_state",
    "test_expired_approval_is_rejected",
    "test_external_chain_head_detects_signed_tail_truncation",
    "test_external_policy_pin_rejects_replaced_roster",
    "test_hand_edited_phase_state_view_is_rejected",
    "test_illegal_state_transition_is_rejected",
    "test_machine_transition_requires_approved_evidence_result",
    "test_one_key_cannot_approve_and_sign_state",
    "test_pending_policy_cannot_authorize",
    "test_parent_directory_symlink_input_is_rejected",
    "test_path_substitution_cannot_replace_ssh_keygen",
    "test_prior_chain_prefix_cannot_be_rewritten",
    "test_request_digest_pin_is_required",
    "test_second_genesis_is_rejected",
    "test_signed_approval_tamper_is_rejected",
    "test_state_transition_cannot_consume_random_approval_digest",
    "test_unlisted_approval_signer_is_rejected",
    "test_valid_approval_is_verified_without_state_write",
    "test_valid_signed_genesis_replays_to_unique_active_unit",
)

REQUIRED_FORBIDDEN_ABSENCE = (
    "execution/phase-state.yaml",
    "execution/transitions",
    "execution/approvals",
    "execution/progress.md",
    "execution/decisions.md",
    "execution/blockers.md",
    "execution/waivers.yaml",
    "Genesis or StateTransition events",
    "valid P00 completion evidence",
    "product implementation",
)

REQUIRED_DECISION_IDS = {
    "canonical-plan-path",
    "working-name-and-license-direction",
    "digest-projection",
    "protected-dataset-freeze",
    "p00-contracts-and-gates",
    "protected-genesis",
    "post-genesis-verifier",
    "external-actions",
    "protected-verifier-format",
    "externally-pinned-trust-roots",
    "read-only-protected-workflow",
    "request-revision-chain",
}

ACTIVE_REQUEST_PATH = "execution/approval-requests/P00.B00-R3.yaml"
R2_REQUEST_PATH = "execution/approval-requests/P00.B00-R2.yaml"
ORIGINAL_REQUEST_PATH = "execution/approval-requests/P00.B00.yaml"
ORIGINAL_REQUEST_FILE_DIGEST = (
    "sha256:4abd872ab81a1f1fcca65492843ddcb587f1716ce692f4763ef3c3709b3bf310"
)
ORIGINAL_REQUEST_DIGEST = (
    "sha256:54c8a29baafb06c13d3d3eb35183bd95aab44ea63f638c53c997da5d60ddb8de"
)
ORIGINAL_CONTROL_PLANE_DIGEST = (
    "sha256:b37b85c688c099899421740d4a82ff4405aba1daed195cdb5c58b0b0889eca77"
)
ORIGINAL_CANDIDATE_SOURCE_COMMIT = "1e2409c24231b83c09a93ee18764cce9ee1a4efc"
R2_REQUEST_FILE_DIGEST = (
    "sha256:adc59eb65e0c963429c824ba2a889092dd16f01773809042d4254be33ab943b7"
)
R2_REQUEST_DIGEST = (
    "sha256:3fc6b9adfc077a2b3f78c2a811a8d61f9fb72c0e7a6c03ff269ff0ee4cc35ca0"
)
R2_CONTROL_PLANE_DIGEST = (
    "sha256:8423ed10cd3af376e58382226ba1550f3831d93542ffb580bc1c755e1dee44c6"
)
R2_CANDIDATE_SOURCE_COMMIT = "5babc022f1a714024c903122eb150ed49c515e6d"
R2_REQUEST_COMMIT = "8faf45512ec5384e816390ad1a46a403c103c5dc"

TEST_SUITE_MODULES = {
    "bootstrap": ("test/bootstrap/test_phasegate.py", "test.bootstrap.test_phasegate"),
    "chainArtifact": (
        "test/bootstrap/test_chain_artifact.py",
        "test.bootstrap.test_chain_artifact",
    ),
    "chainWitness": (
        "test/bootstrap/test_chain_witness.py",
        "test.bootstrap.test_chain_witness",
    ),
    "communityFacts": (
        "test/bootstrap/test_community_facts.py",
        "test.bootstrap.test_community_facts",
    ),
    "controlContext": (
        "test/bootstrap/test_control_context.py",
        "test.bootstrap.test_control_context",
    ),
    "delegation": (
        "test/bootstrap/test_delegation.py",
        "test.bootstrap.test_delegation",
    ),
    "executionArtifact": (
        "test/bootstrap/test_execution_artifact.py",
        "test.bootstrap.test_execution_artifact",
    ),
    "externalFacts": (
        "test/bootstrap/test_external_facts.py",
        "test.bootstrap.test_external_facts",
    ),
    "gateRunner": (
        "test/bootstrap/test_gate_runner.py",
        "test.bootstrap.test_gate_runner",
    ),
    "lifecycleEvidence": (
        "test/bootstrap/test_lifecycle_evidence.py",
        "test.bootstrap.test_lifecycle_evidence",
    ),
    "phaseBundle": (
        "test/bootstrap/test_phase_bundle.py",
        "test.bootstrap.test_phase_bundle",
    ),
    "phaseEvidence": (
        "test/bootstrap/test_phase_evidence.py",
        "test.bootstrap.test_phase_evidence",
    ),
    "protectedChainCli": (
        "test/bootstrap/test_protected_chain_cli.py",
        "test.bootstrap.test_protected_chain_cli",
    ),
    "protectedStateWriterWorkflow": (
        "test/bootstrap/test_protected_state_writer_workflow.py",
        "test.bootstrap.test_protected_state_writer_workflow",
    ),
    "protectedV1Historical": (
        "test/bootstrap/test_protected_verifier.py",
        "test.bootstrap.test_protected_verifier",
    ),
    "protectedV2": (
        "test/bootstrap/test_protected_v2.py",
        "test.bootstrap.test_protected_v2",
    ),
    "oidc": ("test/bootstrap/test_oidc.py", "test.bootstrap.test_oidc"),
    "oidcProvenance": (
        "test/bootstrap/test_oidc_provenance.py",
        "test.bootstrap.test_oidc_provenance",
    ),
    "postEventWriter": (
        "test/bootstrap/test_post_event_writer.py",
        "test.bootstrap.test_post_event_writer",
    ),
    "runExecutor": (
        "test/bootstrap/test_run_executor.py",
        "test.bootstrap.test_run_executor",
    ),
    "serializedBundle": (
        "test/bootstrap/test_serialized_bundle.py",
        "test.bootstrap.test_serialized_bundle",
    ),
    "sshsig": ("test/bootstrap/test_sshsig.py", "test.bootstrap.test_sshsig"),
    "stateChainV2": (
        "test/bootstrap/test_state_chain_v2.py",
        "test.bootstrap.test_state_chain_v2",
    ),
    "stateWriter": (
        "test/bootstrap/test_state_writer.py",
        "test.bootstrap.test_state_writer",
    ),
    "workflowOrchestrator": (
        "test/bootstrap/test_workflow_orchestrator.py",
        "test.bootstrap.test_workflow_orchestrator",
    ),
    "provenance": (
        "test/bootstrap/test_provenance.py",
        "test.bootstrap.test_provenance",
    ),
    "provenanceWriter": (
        "test/bootstrap/test_provenance_writer.py",
        "test.bootstrap.test_provenance_writer",
    ),
    "p00Evaluators": (
        "test/bootstrap/test_p00_evaluators.py",
        "test.bootstrap.test_p00_evaluators",
    ),
}


def _test_methods(root: Path, relative: str) -> list[str]:
    path = root / relative
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    methods = [
        node.name
        for class_node in tree.body
        if isinstance(class_node, ast.ClassDef)
        for node in class_node.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    return sorted(methods, key=lambda value: value.encode("utf-8"))


def _expected_test_suites(root: Path, issues: list[Issue]) -> dict[str, dict[str, Any]]:
    suites: dict[str, dict[str, Any]] = {}
    for suite_id, (relative, module) in TEST_SUITE_MODULES.items():
        try:
            cases = _test_methods(root, relative)
        except (OSError, SyntaxError) as exc:
            issues.append(Issue("invalid_protected_test_source", relative, str(exc)))
            cases = []
        if not cases or len(cases) != len(set(cases)):
            issues.append(
                Issue(
                    "invalid_protected_test_contract",
                    relative,
                    "test suite must contain unique test_* methods",
                )
            )
        suites[suite_id] = {
            "command": (
                "python3 -m unittest discover -s test/bootstrap "
                f"-p '{Path(relative).name}'"
            ),
            "protectedFile": relative,
            "cases": cases,
        }
    return suites


def _json_files(root: Path, declared_inputs: list[dict[str, Any]]) -> dict[str, Any]:
    documents: dict[str, Any] = {}
    json_kinds = {"json", "json-yaml", "manifest", "contract", "catalog", "gate"}
    for entry in declared_inputs:
        if entry["kind"] in json_kinds:
            documents[entry["path"]] = load_json_yaml(root / entry["path"])
    return documents


def _validate_input_closure(
    root: Path, declared_inputs: list[dict[str, Any]], issues: list[Issue]
) -> None:
    declared = {entry["path"] for entry in declared_inputs}
    expected_special = {
        ".github/CODEOWNERS",
        ".gitignore",
        "AGENTS.md",
        "Makefile",
        "agentapi-doctor-Plan.md",
    }
    for special in expected_special - declared:
        issues.append(
            Issue(
                "missing_control_plane_input",
                special,
                "required bootstrap input is undeclared",
            )
        )

    def expected_kind(path: str) -> str:
        if (
            path in expected_special
            or path == "execution/README.md"
            or path.startswith(".github/workflows/")
            or path.endswith(".py")
        ):
            return "text"
        if path == "execution/control-plane-inputs.yaml" or path in {
            "execution/product-stage-map.yaml",
            "execution/impact-map.yaml",
        }:
            return "manifest"
        if path.startswith("execution/phases/") or path.startswith(
            "execution/work-units/"
        ):
            return "contract"
        if path.startswith("execution/gates/p00/"):
            return "gate"
        if path == "execution/protected-verifier/github-actions-oidc-jwks.json":
            return "catalog"
        if path.startswith("execution/") and path.endswith(".yaml"):
            return "catalog"
        return ""

    for entry in declared_inputs:
        wanted = expected_kind(entry["path"])
        if not wanted or entry["kind"] != wanted:
            issues.append(
                Issue(
                    "control_plane_input_kind_mismatch",
                    entry["path"],
                    f"expected {wanted or 'no B00 input'}, got {entry['kind']}",
                )
            )

    discovered: set[str] = set()
    execution = root / "execution"
    if execution.exists():
        for path in execution.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if (
                relative.startswith("execution/approval-requests/")
                or relative.startswith("execution/approvals/")
                or relative.startswith("execution/transitions/")
                or relative.startswith("execution/gates/p00/evidence/")
                or relative
                in {
                    "execution/blockers.md",
                    "execution/decisions.md",
                    "execution/phase-state.yaml",
                    "execution/progress.md",
                    "execution/gates/p00/latest.json",
                    "execution/waivers.yaml",
                }
            ):
                continue
            discovered.add(relative)
    for directory in (root / "tools/phasegate", root / "test/bootstrap"):
        if directory.exists():
            for path in directory.rglob("*.py"):
                if path.is_file() and "__pycache__" not in path.parts:
                    discovered.add(path.relative_to(root).as_posix())
    workflows = root / ".github/workflows"
    if workflows.exists():
        for path in workflows.rglob("*"):
            if path.is_file():
                discovered.add(path.relative_to(root).as_posix())
    for path in sorted(discovered - declared):
        issues.append(
            Issue(
                "undeclared_control_plane_file",
                path,
                "bootstrap behavior/input is outside the aggregate digest",
            )
        )
    for path in sorted(declared - discovered - expected_special):
        # Digest computation reports missing files.  This branch catches a
        # declared non-bootstrap path that exists but is outside the closed set.
        if (root / path).exists():
            issues.append(
                Issue(
                    "unexpected_control_plane_input",
                    path,
                    "declared input is outside the reviewed bootstrap closure",
                )
            )


def _walk_keys(value: Any, prefix: str = "") -> Iterable[tuple[str, Any, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            location = f"{prefix}.{key}" if prefix else key
            yield key, item, location
            yield from _walk_keys(item, location)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_keys(item, f"{prefix}[{index}]")


def _catalog_entries(
    document: Any, path: str, issues: list[Issue]
) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        issues.append(Issue("invalid_catalog", path, "catalog must be an object"))
        return []
    entries = document.get("evaluators")
    if not isinstance(entries, list):
        issues.append(
            Issue("invalid_evaluator_catalog", path, "evaluators must be an array")
        )
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _validate_evaluator_catalog(
    document: Any, path: str, issues: list[Issue]
) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(_catalog_entries(document, path, issues)):
        location = f"{path}#evaluators[{index}]"
        evaluator_id = entry.get("id")
        status = entry.get("status")
        kind = entry.get("kind")
        implementation = entry.get("implementation")
        if not isinstance(evaluator_id, str) or not evaluator_id:
            issues.append(
                Issue("invalid_evaluator", location, "evaluator id is required")
            )
            continue
        if evaluator_id in catalog:
            issues.append(Issue("duplicate_evaluator", location, evaluator_id))
            continue
        if status not in {"implemented", "planned", "external-only", "human-only"}:
            issues.append(Issue("invalid_evaluator_status", location, str(status)))
        if kind not in {"MACHINE", "EXTERNAL", "TIME", "HUMAN"}:
            issues.append(Issue("invalid_evaluator_kind", location, str(kind)))
        if not isinstance(implementation, dict):
            issues.append(
                Issue("missing_evaluator_implementation", location, evaluator_id)
            )
        else:
            implementation_type = implementation.get("type")
            handler = implementation.get("handler")
            if implementation_type in FORBIDDEN_IMPLEMENTATION_TYPES:
                issues.append(
                    Issue(
                        "placeholder_evaluator",
                        location,
                        f"{evaluator_id} uses forbidden type {implementation_type!r}",
                    )
                )
            if status == "implemented" and (
                IMPLEMENTED_HANDLERS.get(evaluator_id) != handler
                or implementation_type != "builtin"
            ):
                issues.append(
                    Issue(
                        "unknown_implemented_handler",
                        location,
                        f"{evaluator_id} cannot use handler {handler!r}",
                    )
                )
            if status != "implemented" and implementation_type == "builtin":
                issues.append(
                    Issue(
                        "status_implementation_mismatch",
                        location,
                        f"{evaluator_id} is {status} but declares builtin implementation",
                    )
                )
            expected_type = {
                "implemented": "builtin",
                "planned": "planned",
                "external-only": "attestation",
                "human-only": "attestation",
            }.get(status)
            if expected_type is not None and implementation_type != expected_type:
                issues.append(
                    Issue(
                        "status_implementation_mismatch",
                        location,
                        f"{status} evaluator requires implementation type {expected_type}",
                    )
                )
        if status == "implemented":
            if entry.get("mayProducePass") is not True:
                issues.append(
                    Issue("invalid_evaluator_pass_policy", location, evaluator_id)
                )
            if (
                not isinstance(entry.get("protectedTests"), list)
                or not entry["protectedTests"]
            ):
                issues.append(
                    Issue("missing_protected_evaluator_tests", location, evaluator_id)
                )
        elif status == "planned":
            if (
                entry.get("mayProducePass") is not False
                or entry.get("failClosed") is not True
            ):
                issues.append(
                    Issue("planned_evaluator_not_fail_closed", location, evaluator_id)
                )
        elif status in {"external-only", "human-only"}:
            if entry.get("localGateMayProduce") is not False:
                issues.append(
                    Issue(
                        "local_attestation_production_allowed", location, evaluator_id
                    )
                )
            expected_verifier = EXTERNAL_VERIFIER_SPECS.get(evaluator_id)
            if status == "external-only" and (
                expected_verifier is None
                or entry.get("verification") != expected_verifier
            ):
                issues.append(
                    Issue(
                        "missing_external_fact_verifier",
                        location,
                        f"{evaluator_id} lacks its exact protected fact verifier",
                    )
                )
        expected_status_kind = {
            "implemented": "MACHINE",
            "planned": "MACHINE",
            "external-only": "EXTERNAL",
            "human-only": "HUMAN",
        }.get(status)
        if expected_status_kind is not None and kind != expected_status_kind:
            issues.append(
                Issue("evaluator_status_kind_mismatch", location, f"{status} vs {kind}")
            )
        catalog[evaluator_id] = entry
    return catalog


def _validate_metric_document(
    document: Any, path: str, issues: list[Issue]
) -> dict[str, dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("metrics"), list):
        issues.append(Issue("invalid_metric_catalog", path, "metrics must be an array"))
        return {}
    metrics: dict[str, dict[str, Any]] = {}
    required = {
        "id",
        "status",
        "formula",
        "numerator",
        "denominator",
        "minimumN",
        "datasetCatalog",
        "datasetStatus",
        "datasetDigest",
        "window",
        "exclusions",
        "unknownPolicy",
        "quarantinePolicy",
        "confidenceMethod",
        "evaluator",
        "evaluatorDigest",
        "threshold",
    }
    for index, metric in enumerate(document["metrics"]):
        location = f"{path}#metrics[{index}]"
        if not isinstance(metric, dict):
            issues.append(Issue("invalid_metric", location, "metric must be an object"))
            continue
        missing = sorted(required - metric.keys())
        if missing:
            issues.append(Issue("incomplete_metric", location, f"missing {missing}"))
        metric_id = metric.get("id")
        if not isinstance(metric_id, str) or not metric_id:
            issues.append(Issue("invalid_metric_id", location, "metric id is required"))
        elif metric_id in metrics:
            issues.append(Issue("duplicate_metric", location, metric_id))
        else:
            metrics[metric_id] = metric
        for key, _, key_path in _walk_keys(metric):
            if key in FORBIDDEN_RESULT_KEYS:
                issues.append(
                    Issue(
                        "hand_entered_metric_result",
                        f"{location}.{key_path}",
                        f"metric definitions cannot contain result field {key!r}",
                    )
                )
        minimum_n = metric.get("minimumN")
        if (
            not isinstance(minimum_n, int)
            or isinstance(minimum_n, bool)
            or minimum_n < 0
        ):
            issues.append(Issue("invalid_minimum_n", location, str(minimum_n)))
        dataset_status = metric.get("datasetStatus")
        if dataset_status not in {
            "frozen",
            "pending_protected_input",
            "late_bound_requires_signed_freeze",
            "not_applicable",
        }:
            issues.append(
                Issue("invalid_dataset_status", location, str(dataset_status))
            )
        dataset_digest = metric.get("datasetDigest")
        if (
            dataset_status
            in {
                "pending_protected_input",
                "late_bound_requires_signed_freeze",
            }
            and dataset_digest is not None
        ):
            issues.append(
                Issue(
                    "unapproved_dataset_digest",
                    location,
                    "pending datasetDigest must be null",
                )
            )
        if dataset_status == "frozen" and not (
            isinstance(dataset_digest, str)
            and len(dataset_digest) == 71
            and dataset_digest.startswith("sha256:")
        ):
            issues.append(
                Issue("missing_dataset_digest", location, "frozen dataset needs sha256")
            )
        if metric.get("status") != "implemented-evaluator-late-bound-dataset":
            issues.append(
                Issue("unapproved_metric_state", location, str(metric.get("status")))
            )
        evaluator_digest = metric.get("evaluatorDigest")
        if not (
            isinstance(evaluator_digest, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", evaluator_digest)
        ):
            issues.append(
                Issue(
                    "missing_evaluator_digest",
                    location,
                    str(evaluator_digest),
                )
            )
        for field in ("formula", "numerator", "denominator", "threshold"):
            if not isinstance(metric.get(field), str) or not metric[field].strip():
                issues.append(Issue("empty_metric_field", location, field))
    return metrics


def _validate_evidence_schema_catalog(
    document: Any, path: str, issues: list[Issue]
) -> dict[str, dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("schemas"), list):
        issues.append(
            Issue("invalid_evidence_schema_catalog", path, "schemas must be an array")
        )
        return {}
    schemas: dict[str, dict[str, Any]] = {}
    for index, schema in enumerate(document["schemas"]):
        location = f"{path}#schemas[{index}]"
        if not isinstance(schema, dict):
            issues.append(
                Issue("invalid_evidence_schema", location, "must be an object")
            )
            continue
        schema_id = schema.get("id")
        if not isinstance(schema_id, str) or not schema_id:
            issues.append(
                Issue("invalid_evidence_schema_id", location, "id is required")
            )
            continue
        if schema_id in schemas:
            issues.append(Issue("duplicate_evidence_schema", location, schema_id))
        schemas[schema_id] = schema
        if schema.get("kind") not in {"MACHINE", "EXTERNAL", "TIME", "HUMAN"}:
            issues.append(
                Issue("invalid_evidence_schema_kind", location, str(schema.get("kind")))
            )
        required_fields = schema.get("requiredFields")
        if not isinstance(required_fields, list) or not required_fields:
            issues.append(
                Issue(
                    "incomplete_evidence_schema",
                    location,
                    "requiredFields must be non-empty",
                )
            )
            required_fields = []
        expected_status = {
            "MACHINE": {"implemented", "planned"},
            "EXTERNAL": {"external-only"},
            "HUMAN": {"human-only"},
            "TIME": {"time-only"},
        }.get(schema.get("kind"), set())
        if schema.get("status") not in expected_status:
            issues.append(
                Issue(
                    "evidence_schema_status_kind_mismatch",
                    location,
                    f"{schema.get('status')} vs {schema.get('kind')}",
                )
            )
        required_field_set = set(required_fields)
        # HUMAN/TIME attestations in this catalog are flat signed envelopes.
        # EXTERNAL entries are fact-evidence inputs: their producer signature
        # is verified by the enclosing criterion result, while criterion-
        # specific verifiers independently re-observe the fact.  Requiring
        # flat actor/signature fields here would make the implemented nested
        # GitHub/community schemas lie about their actual byte contract.
        if schema.get("kind") in {"HUMAN", "TIME"}:
            attestation_base = {
                "schemaVersion",
                "sourceCommit",
                "controlPlaneDigest",
                "actor",
                "timestamp",
                "signature",
            }
            missing_attestation = sorted(attestation_base - required_field_set)
            if missing_attestation:
                issues.append(
                    Issue(
                        "incomplete_attestation_schema",
                        location,
                        f"missing {missing_attestation}",
                    )
                )
        if schema.get("kind") == "EXTERNAL":
            external_base = {"schemaVersion", "factEvidenceDigest"}
            missing_external = sorted(external_base - required_field_set)
            has_subject_binding = "subject" in required_field_set or {
                "sourceCommit",
                "controlPlaneDigest",
            }.issubset(required_field_set)
            if missing_external or not has_subject_binding:
                detail = (
                    f"missing {missing_external}; "
                    "subject or flat source/control binding required"
                )
                issues.append(
                    Issue("incomplete_external_fact_schema", location, detail)
                )
        if schema.get("kind") == "HUMAN":
            human_fields = {"criterionId", "subjectDigest", "decision", "actorRole"}
            missing_human = sorted(human_fields - required_field_set)
            if missing_human:
                issues.append(
                    Issue(
                        "incomplete_human_schema", location, f"missing {missing_human}"
                    )
                )
        if schema.get("kind") == "MACHINE" and not (
            {"evaluatorDigest", "evaluatorSetDigest"} & required_field_set
        ):
            issues.append(
                Issue("missing_evaluator_digest_field", location, str(schema_id))
            )
    return schemas


def _validate_contract(
    root: Path,
    document: Any,
    path: str,
    expected_digest: str,
    evaluator_catalog: dict[str, dict[str, Any]],
    metric_catalog: dict[str, dict[str, Any]],
    evidence_schema_catalog: dict[str, dict[str, Any]],
    declared_paths: set[str],
    issues: list[Issue],
) -> None:
    if not isinstance(document, dict):
        issues.append(Issue("invalid_contract", path, "contract must be an object"))
        return
    missing = sorted(REQUIRED_CONTRACT_FIELDS - document.keys())
    if missing:
        issues.append(Issue("incomplete_contract", path, f"missing {missing}"))
    expected_kind = (
        "PhaseAggregateContractCandidate"
        if path.startswith("execution/phases/")
        else "WorkUnitContractCandidate"
    )
    if document.get("kind") != expected_kind:
        issues.append(Issue("invalid_contract_kind", path, str(document.get("kind"))))
    if document.get("contractStatus") != "candidate-unapproved":
        issues.append(
            Issue("invalid_contract_status", path, str(document.get("contractStatus")))
        )
    for field in ("title", "objective", "humanGate"):
        if not isinstance(document.get(field), str) or not document[field].strip():
            issues.append(Issue("empty_contract_field", path, field))
    contract_id = document.get("id")
    phase = document.get("phase")
    if path.startswith("execution/phases/"):
        if contract_id != "P00" or phase != "P00":
            issues.append(
                Issue("invalid_phase_contract_identity", path, f"{contract_id}/{phase}")
            )
        if document.get("workUnits") != [f"P00.W0{index}" for index in range(1, 6)]:
            issues.append(
                Issue("phase_work_unit_drift", path, str(document.get("workUnits")))
            )
    elif not (
        isinstance(contract_id, str)
        and contract_id in {f"P00.W0{index}" for index in range(1, 6)}
        and phase == "P00"
        and path == f"execution/work-units/{contract_id}.yaml"
    ):
        issues.append(
            Issue("invalid_work_unit_identity", path, f"{contract_id}/{phase}")
        )
    if document.get("controlPlaneDigest") != expected_digest:
        issues.append(
            Issue(
                "control_plane_digest_mismatch",
                path,
                "contract is not bound to the computed candidate digest",
            )
        )
    for field in (
        "readFirst",
        "inScope",
        "outOfScope",
        "protectedAcceptanceInputs",
        "deliverables",
        "verification",
        "stopAndBlock",
    ):
        if field in document and (
            not isinstance(document[field], list) or not document[field]
        ):
            issues.append(
                Issue("empty_contract_field", path, f"{field} must be non-empty")
            )
    for field in ("mutableImplementationTests", "prerequisites"):
        if field in document and not isinstance(document[field], list):
            issues.append(
                Issue("invalid_contract_field", path, f"{field} must be an array")
            )
    for field in (
        "readFirst",
        "inScope",
        "outOfScope",
        "protectedAcceptanceInputs",
        "mutableImplementationTests",
        "prerequisites",
        "deliverables",
        "verification",
        "stopAndBlock",
    ):
        value = document.get(field)
        if isinstance(value, list) and any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            issues.append(Issue("invalid_contract_list_item", path, field))
    for reference in document.get("readFirst", []):
        if not isinstance(reference, str):
            issues.append(Issue("invalid_read_first", path, str(reference)))
        elif (
            reference != "execution/phase-state.yaml"
            and not (root / reference).is_file()
        ):
            issues.append(Issue("missing_read_first", path, reference))
    for reference in document.get("protectedAcceptanceInputs", []):
        if not isinstance(reference, str) or reference not in declared_paths:
            issues.append(Issue("unbound_protected_input", path, str(reference)))
    for command in document.get("verification", []):
        if not isinstance(command, str) or not command.startswith("make "):
            issues.append(Issue("invalid_verification_command", path, str(command)))
        elif command.strip() in {"make true", "make pass", "make noop"}:
            issues.append(Issue("placeholder_verification_command", path, command))
    network_policy = document.get("networkPolicy")
    if not isinstance(network_policy, dict):
        issues.append(Issue("invalid_network_policy", path, "must be an object"))
    else:
        if network_policy.get("gate") != "offline":
            issues.append(
                Issue("online_gate_policy", path, str(network_policy.get("gate")))
            )
        allowlist = network_policy.get("researchAllowlist")
        if not isinstance(allowlist, list) or any(
            not isinstance(host, str) or not host or "*" in host or "://" in host
            for host in (allowlist if isinstance(allowlist, list) else [])
        ):
            issues.append(Issue("invalid_research_allowlist", path, str(allowlist)))
        if network_policy.get("dependencyFetch") != "lockfile-only":
            issues.append(
                Issue(
                    "invalid_dependency_fetch_policy",
                    path,
                    str(network_policy.get("dependencyFetch")),
                )
            )
    resource_budget = document.get("resourceBudget")
    required_budget = {
        "wallTime",
        "commandTimeout",
        "fuzzCPUHours",
        "diskBytes",
        "downloadBytes",
        "processLimit",
    }
    if (
        not isinstance(resource_budget, dict)
        or required_budget - resource_budget.keys()
    ):
        issues.append(
            Issue("incomplete_resource_budget", path, "required budget fields missing")
        )
    expected_prerequisites = {
        "P00": [],
        "P00.W01": [
            "P00.B00: independently approved",
            "Genesis: verified and P00.W01 ACTIVE",
        ],
        "P00.W02": ["P00.W01: CONVERGED"],
        "P00.W03": [
            "P00.W02: CONVERGED",
            "approved P00 corpus dataset slot and late-bound freeze semantics: independently approved",
        ],
        "P00.W04": [
            "P00.W03: CONVERGED",
            "approved P00 experiment dataset slot and late-bound freeze semantics: independently approved",
        ],
        "P00.W05": ["P00.W04: CONVERGED"],
    }
    if (
        contract_id in expected_prerequisites
        and document.get("prerequisites") != expected_prerequisites[contract_id]
    ):
        issues.append(
            Issue("prerequisite_drift", path, str(document.get("prerequisites")))
        )
    criteria = document.get("convergence")
    if not isinstance(criteria, list) or not criteria:
        issues.append(
            Issue("missing_convergence", path, "convergence must be non-empty")
        )
        return
    seen: set[str] = set()
    for index, criterion in enumerate(criteria):
        location = f"{path}#convergence[{index}]"
        if not isinstance(criterion, dict):
            issues.append(
                Issue("invalid_criterion", location, "criterion must be an object")
            )
            continue
        missing_criterion = sorted(REQUIRED_CRITERION_FIELDS - criterion.keys())
        if missing_criterion:
            issues.append(
                Issue("incomplete_criterion", location, f"missing {missing_criterion}")
            )
        criterion_id = criterion.get("id")
        if not isinstance(criterion_id, str) or not criterion_id:
            issues.append(Issue("invalid_criterion_id", location, "id is required"))
        elif criterion_id in seen:
            issues.append(Issue("duplicate_criterion", location, criterion_id))
        else:
            seen.add(criterion_id)
        evaluator = criterion.get("evaluator")
        evaluator_entry = evaluator_catalog.get(evaluator)
        if evaluator_entry is None:
            issues.append(Issue("unknown_evaluator", location, str(evaluator)))
        elif criterion.get("kind") != evaluator_entry.get("kind"):
            issues.append(
                Issue(
                    "criterion_evaluator_kind_mismatch",
                    location,
                    f"{criterion.get('kind')} vs {evaluator_entry.get('kind')}",
                )
            )
        evidence_schema = criterion.get("evidenceSchema")
        schema_entry = evidence_schema_catalog.get(evidence_schema)
        if schema_entry is None:
            issues.append(
                Issue("unknown_evidence_schema", location, str(evidence_schema))
            )
        elif criterion.get("kind") != schema_entry.get("kind"):
            issues.append(
                Issue(
                    "criterion_evidence_kind_mismatch",
                    location,
                    f"{criterion.get('kind')} vs {schema_entry.get('kind')}",
                )
            )
        threshold = criterion.get("threshold")
        if not isinstance(threshold, str) or not threshold.strip():
            issues.append(Issue("empty_criterion_threshold", location, str(threshold)))
        metric = criterion.get("metric")
        if metric is not None:
            metric_entry = metric_catalog.get(metric)
            if metric_entry is None:
                issues.append(Issue("unknown_metric", location, str(metric)))
            else:
                if metric_entry.get("evaluator") != evaluator:
                    issues.append(
                        Issue("metric_evaluator_mismatch", location, str(metric))
                    )
                expected_threshold = (
                    f"execution/metrics/definitions.yaml#{metric}.threshold"
                )
                if threshold != expected_threshold:
                    issues.append(
                        Issue(
                            "metric_threshold_not_authoritative",
                            location,
                            str(threshold),
                        )
                    )
        if criterion.get("status") in {"pass", "passed", "complete", "completed"}:
            issues.append(
                Issue(
                    "precomputed_criterion",
                    location,
                    "candidate criteria cannot be pre-passed",
                )
            )


def _validate_gate_documents(
    documents: dict[str, Any],
    expected_digest: str,
    evaluator_catalog: dict[str, dict[str, Any]],
    metric_catalog: dict[str, dict[str, Any]],
    evidence_schema_catalog: dict[str, dict[str, Any]],
    declared_paths: set[str],
    issues: list[Issue],
) -> None:
    required_gate_fields = {
        "schemaVersion",
        "kind",
        "id",
        "phase",
        "workUnit",
        "contract",
        "gateStatus",
        "machineImplementationStatus",
        "controlPlaneDigest",
        "networkPolicy",
        "failClosed",
        "criteria",
        "protectedInputs",
        "missingEvidencePolicy",
        "unknownOrPlannedEvaluatorResult",
    }
    criterion_fields = (
        "id",
        "kind",
        "evaluator",
        "metric",
        "threshold",
        "evidenceSchema",
    )
    for path, document in documents.items():
        if not path.startswith("execution/gates/p00/"):
            continue
        if not isinstance(document, dict):
            issues.append(Issue("invalid_gate", path, "gate must be an object"))
            continue
        missing_gate_fields = sorted(required_gate_fields - document.keys())
        if missing_gate_fields:
            issues.append(
                Issue("incomplete_gate", path, f"missing {missing_gate_fields}")
            )
        aggregate = path == "execution/gates/p00/aggregate.yaml"
        expected_kind = (
            "PhaseAggregateGateDefinitionCandidate"
            if aggregate
            else "WorkUnitGateDefinitionCandidate"
        )
        if document.get("kind") != expected_kind:
            issues.append(Issue("invalid_gate_kind", path, str(document.get("kind"))))
        if document.get("gateStatus") != "candidate-unapproved":
            issues.append(
                Issue("invalid_gate_status", path, str(document.get("gateStatus")))
            )
        if document.get("controlPlaneDigest") != expected_digest:
            issues.append(
                Issue("gate_digest_mismatch", path, "gate is not bound to aggregate")
            )
        if document.get("networkPolicy") != "offline":
            issues.append(
                Issue(
                    "online_gate_definition", path, str(document.get("networkPolicy"))
                )
            )
        if document.get("failClosed") is not True:
            issues.append(
                Issue("gate_not_fail_closed", path, "failClosed must be true")
            )
        expected_missing_policy = {
            "MACHINE": "FAIL",
            "EXTERNAL": "WAITING_EXTERNAL",
            "HUMAN": "REVIEW_PENDING",
        }
        if document.get("missingEvidencePolicy") != expected_missing_policy:
            issues.append(
                Issue("invalid_missing_evidence_policy", path, "policy drift")
            )
        expected_unknown_policy = (
            {
                "status": "ERROR",
                "reasonCode": "missing_evaluator",
                "mayPass": False,
            }
            if path == "execution/gates/p00/P00.W01.yaml"
            else {
                "status": "ERROR",
                "reasonCode": "unknown_or_unapproved_evaluator",
                "mayPass": False,
            }
        )
        if document.get("unknownOrPlannedEvaluatorResult") != expected_unknown_policy:
            issues.append(
                Issue("invalid_missing_evaluator_policy", path, "policy drift")
            )
        protected_inputs = document.get("protectedInputs")
        if not isinstance(protected_inputs, list) or not protected_inputs:
            issues.append(
                Issue("missing_gate_protected_inputs", path, "must be non-empty")
            )
        else:
            for reference in protected_inputs:
                if reference not in declared_paths:
                    issues.append(
                        Issue("unbound_gate_protected_input", path, str(reference))
                    )
        contract_path = document.get("contract")
        contract = (
            documents.get(contract_path) if isinstance(contract_path, str) else None
        )
        if not isinstance(contract, dict):
            issues.append(Issue("missing_gate_contract", path, str(contract_path)))
            contract_criteria: list[Any] = []
        else:
            contract_criteria = contract.get("convergence", [])
        if aggregate:
            if document.get("phase") != "P00" or document.get("workUnit") is not None:
                issues.append(
                    Issue("invalid_aggregate_gate_identity", path, "identity drift")
                )
            expected_units = [f"gate://p00/P00.W0{index}/v1" for index in range(1, 6)]
            if document.get("requiredUnitGates") != expected_units:
                issues.append(
                    Issue("aggregate_unit_gate_drift", path, "requiredUnitGates drift")
                )
            if document.get("selfEvidenceMaySatisfyCriterion") is not False:
                issues.append(
                    Issue("aggregate_self_evidence_allowed", path, "must be false")
                )
        else:
            unit = document.get("workUnit")
            if not (
                isinstance(unit, str)
                and unit in {f"P00.W0{index}" for index in range(1, 6)}
                and document.get("phase") == "P00"
                and path == f"execution/gates/p00/{unit}.yaml"
                and document.get("id") == f"gate://p00/{unit}/v1"
                and contract_path == f"execution/work-units/{unit}.yaml"
            ):
                issues.append(
                    Issue("invalid_unit_gate_identity", path, "identity drift")
                )
        criteria = document.get("criteria")
        if not isinstance(criteria, list) or not criteria:
            issues.append(
                Issue("empty_gate_criteria", path, "criteria must be non-empty")
            )
            criteria = []
        gate_projection = [
            {key: criterion.get(key) for key in criterion_fields if key in criterion}
            for criterion in criteria
            if isinstance(criterion, dict)
        ]
        contract_projection = [
            {key: criterion.get(key) for key in criterion_fields if key in criterion}
            for criterion in contract_criteria
            if isinstance(criterion, dict)
        ]
        if gate_projection != contract_projection:
            issues.append(
                Issue(
                    "gate_contract_criterion_drift",
                    path,
                    "gate criteria differ from contract",
                )
            )
        machine_statuses = [
            evaluator_catalog.get(criterion.get("evaluator"), {}).get("status")
            for criterion in criteria
            if isinstance(criterion, dict) and criterion.get("kind") == "MACHINE"
        ]
        if machine_statuses and all(
            status == "implemented" for status in machine_statuses
        ):
            expected_machine_status = (
                "implemented"
                if path == "execution/gates/p00/P00.W01.yaml"
                else "implemented-protected-paired"
            )
        else:
            expected_machine_status = "planned-fail-closed"
        if document.get("machineImplementationStatus") != expected_machine_status:
            issues.append(
                Issue(
                    "gate_machine_status_drift",
                    path,
                    f"expected {expected_machine_status}",
                )
            )
        if path != "execution/gates/p00/P00.W01.yaml" and document.get(
            "datasetPolicy"
        ) != {
            "status": "late_bound_requires_signed_freeze",
            "digest": None,
            "missingOrUnfrozenResult": "insufficient_samples",
        }:
            issues.append(
                Issue("invalid_dataset_policy", path, "late-bound freeze policy drift")
            )
        for index, criterion in enumerate(criteria):
            location = f"{path}#criteria[{index}]"
            if not isinstance(criterion, dict):
                issues.append(
                    Issue("invalid_gate_criterion", location, "must be an object")
                )
                continue
            evaluator_id = criterion.get("evaluator")
            evaluator_entry = evaluator_catalog.get(evaluator_id)
            if evaluator_entry is None:
                issues.append(Issue("unknown_evaluator", location, str(evaluator_id)))
            elif criterion.get("kind") != evaluator_entry.get("kind"):
                issues.append(
                    Issue(
                        "criterion_evaluator_kind_mismatch", location, str(evaluator_id)
                    )
                )
            evidence_schema = criterion.get("evidenceSchema")
            schema_entry = evidence_schema_catalog.get(evidence_schema)
            if schema_entry is None:
                issues.append(
                    Issue("unknown_evidence_schema", location, str(evidence_schema))
                )
            elif criterion.get("kind") != schema_entry.get("kind"):
                issues.append(
                    Issue(
                        "criterion_evidence_kind_mismatch",
                        location,
                        str(evidence_schema),
                    )
                )
            threshold = criterion.get("threshold")
            if not isinstance(threshold, str) or not threshold.strip():
                issues.append(
                    Issue("empty_criterion_threshold", location, str(threshold))
                )
            metric_id = criterion.get("metric")
            if metric_id is not None:
                metric_entry = metric_catalog.get(metric_id)
                if metric_entry is None:
                    issues.append(Issue("unknown_metric", location, str(metric_id)))
                elif metric_entry.get("evaluator") != evaluator_id:
                    issues.append(
                        Issue("metric_evaluator_mismatch", location, str(metric_id))
                    )
            for key, _, key_path in _walk_keys(criterion):
                if key in FORBIDDEN_RESULT_KEYS:
                    issues.append(
                        Issue(
                            "precomputed_gate_result",
                            f"{location}.{key_path}",
                            f"gate definitions cannot contain {key!r}",
                        )
                    )


def _validate_catalog_semantics(
    documents: dict[str, Any],
    evaluator_catalog: dict[str, dict[str, Any]],
    issues: list[Issue],
) -> None:
    acceptance_path = "execution/catalogs/p00/acceptance.yaml"
    acceptance = documents.get(acceptance_path)
    if not isinstance(acceptance, dict):
        issues.append(Issue("invalid_acceptance_catalog", acceptance_path, "missing"))
        return
    contract_criteria: dict[str, tuple[str, dict[str, Any]]] = {}
    for path, contract in documents.items():
        if not (
            path.startswith("execution/phases/")
            or path.startswith("execution/work-units/")
        ) or not isinstance(contract, dict):
            continue
        owner = contract.get("id")
        for criterion in contract.get("convergence", []):
            if isinstance(criterion, dict) and isinstance(criterion.get("id"), str):
                criterion_id = criterion["id"]
                if criterion_id in contract_criteria:
                    issues.append(
                        Issue("duplicate_cross_contract_criterion", path, criterion_id)
                    )
                contract_criteria[criterion_id] = (owner, criterion)
    acceptance_criteria = acceptance.get("criteria")
    if not isinstance(acceptance_criteria, list) or not acceptance_criteria:
        issues.append(
            Issue("empty_acceptance_catalog", acceptance_path, "criteria empty")
        )
        acceptance_criteria = []
    seen: set[str] = set()
    for index, item in enumerate(acceptance_criteria):
        location = f"{acceptance_path}#criteria[{index}]"
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            issues.append(Issue("invalid_acceptance_criterion", location, "invalid"))
            continue
        criterion_id = item["id"]
        seen.add(criterion_id)
        expected = contract_criteria.get(criterion_id)
        if expected is None:
            issues.append(Issue("orphan_acceptance_criterion", location, criterion_id))
            continue
        owner, criterion = expected
        evaluator = evaluator_catalog.get(criterion.get("evaluator"), {})
        expected_projection = {
            "id": criterion_id,
            "owner": owner,
            "kind": criterion.get("kind"),
            "evaluator": criterion.get("evaluator"),
            "evaluatorStatus": evaluator.get("status"),
        }
        if item != expected_projection:
            issues.append(
                Issue(
                    "acceptance_contract_drift", location, "criterion projection drift"
                )
            )
    if seen != set(contract_criteria):
        issues.append(
            Issue(
                "acceptance_criterion_set_drift",
                acceptance_path,
                f"missing={sorted(set(contract_criteria) - seen)} extra={sorted(seen - set(contract_criteria))}",
            )
        )
    anti_gaming = acceptance.get("antiGaming")
    if not isinstance(anti_gaming, list) or len(anti_gaming) < 5:
        issues.append(Issue("missing_anti_gaming_rules", acceptance_path, "need >= 5"))

    for path, document in documents.items():
        if not path.startswith("execution/catalogs/p00/") or not isinstance(
            document, dict
        ):
            continue
        if document.get("protected") is not True:
            issues.append(
                Issue("unprotected_acceptance_catalog", path, "protected must be true")
            )
        if document.get("catalogStatus") != "candidate-unapproved":
            issues.append(
                Issue(
                    "invalid_catalog_status", path, str(document.get("catalogStatus"))
                )
            )
    expected_catalog_kinds = {
        "execution/catalogs/p00/acceptance.yaml": "ProtectedAcceptanceCatalogCandidate",
        "execution/catalogs/p00/bootstrap.yaml": "BootstrapAcceptanceDefinitionCandidate",
        "execution/catalogs/p00/competitor-research.yaml": "CompetitorResearchAcceptanceDefinitionCandidate",
        "execution/catalogs/p00/corpus.yaml": "CorpusAcceptanceDefinitionCandidate",
        "execution/catalogs/p00/risk-experiments.yaml": "RiskExperimentAcceptanceDefinitionCandidate",
        "execution/catalogs/p00/go-no-go.yaml": "GoNoGoAcceptanceDefinitionCandidate",
    }
    for path, expected_kind in expected_catalog_kinds.items():
        if documents.get(path, {}).get("kind") != expected_kind:
            issues.append(Issue("invalid_catalog_kind", path, expected_kind))

    bootstrap_path = "execution/catalogs/p00/bootstrap.yaml"
    bootstrap = documents.get(bootstrap_path, {})
    assertion_ids = {
        item.get("id")
        for item in bootstrap.get("requiredAssertions", [])
        if isinstance(item, dict)
    }
    required_assertion_ids = {
        "json-compatible-yaml",
        "contract-shape",
        "input-closure",
        "evaluator-status",
        "anti-placeholder",
        "genesis-boundary",
        "digest-normalization",
    }
    if assertion_ids != required_assertion_ids or any(
        not isinstance(item.get("semantic"), str) or not item["semantic"].strip()
        for item in bootstrap.get("requiredAssertions", [])
        if isinstance(item, dict)
    ):
        issues.append(
            Issue(
                "bootstrap_assertion_drift", bootstrap_path, "required assertions drift"
            )
        )
    required_negative_fragments = {
        "unknown evaluator",
        "planned evaluator",
        "missing evaluator",
        "missing evidence schema",
        "missing protected input",
        "existence-only assertion",
        "hand-written metric",
        "unfrozen dataset",
        "forbidden pre-Genesis state artifact",
    }
    if set(bootstrap.get("protectedNegativeCases", [])) != required_negative_fragments:
        issues.append(
            Issue("bootstrap_negative_case_drift", bootstrap_path, "case set drift")
        )
    required_forbidden_paths = {
        "execution/phase-state.yaml",
        "execution/transitions/**",
        "execution/approvals/**",
        "execution/gates/p00/evidence/**",
        "execution/gates/p00/latest.json",
    }
    if set(bootstrap.get("forbiddenPreGenesisPaths", [])) != required_forbidden_paths:
        issues.append(
            Issue("bootstrap_forbidden_path_drift", bootstrap_path, "path set drift")
        )

    competitor_path = "execution/catalogs/p00/competitor-research.yaml"
    competitor = documents.get(competitor_path, {})
    if set(competitor.get("namedProjects", [])) != {
        "am-i-openai-compatible",
        "octest",
        "FauxpenAI-conformance",
        "Open Responses",
    }:
        issues.append(
            Issue("competitor_catalog_drift", competitor_path, "project set drift")
        )
    for field, minimum in (
        ("interviewMinimum", 5),
        ("designPartnerMinimum", 3),
        ("namingCandidateMinimum", 3),
    ):
        if competitor.get(field) != minimum:
            issues.append(Issue("competitor_threshold_drift", competitor_path, field))
    source_policy = competitor.get("sourcePolicy", {})
    if not isinstance(source_policy, dict) or not all(source_policy.values()):
        issues.append(
            Issue(
                "weak_competitor_source_policy",
                competitor_path,
                "all source facts required",
            )
        )
    outreach_policy = competitor.get("outreachPolicy", {})
    if not (
        isinstance(outreach_policy, dict)
        and outreach_policy.get("agentMaySend") is False
        and outreach_policy.get("humanReviewBeforeSend") is True
        and outreach_policy.get("signatureRequired") is True
    ):
        issues.append(Issue("unsafe_outreach_policy", competitor_path, "policy drift"))

    corpus_path = "execution/catalogs/p00/corpus.yaml"
    corpus = documents.get(corpus_path, {})
    if (
        corpus.get("datasetStatus") != "pending_protected_input"
        or corpus.get("datasetDigest") is not None
        or "SignedProtectedInputFreeze" not in corpus.get("activationRule", "")
        or "insufficient_samples" not in corpus.get("activationRule", "")
    ):
        issues.append(
            Issue(
                "unapproved_corpus_dataset",
                corpus_path,
                "must remain pending/null and require an independent signed freeze",
            )
        )
    for field, expected in (
        ("candidateMinimum", 30),
        ("attemptMinimum", 20),
        ("reproductionMinimum", 16),
        ("deterministicReplayMinimum", 10),
        ("distinctFaultDomainMinimum", 2),
    ):
        if corpus.get(field) != expected:
            issues.append(Issue("corpus_threshold_drift", corpus_path, field))
    rights_policy = corpus.get("rightsPolicy", {})
    if not isinstance(rights_policy, dict) or not all(rights_policy.values()):
        issues.append(
            Issue("weak_corpus_rights_policy", corpus_path, "all controls required")
        )

    risk_path = "execution/catalogs/p00/risk-experiments.yaml"
    risk = documents.get(risk_path, {})
    if (
        risk.get("datasetStatus") != "pending_protected_input"
        or risk.get("datasetDigest") is not None
        or "SignedProtectedInputFreeze" not in risk.get("activationRule", "")
        or "insufficient_samples" not in risk.get("activationRule", "")
    ):
        issues.append(
            Issue(
                "unapproved_experiment_dataset",
                risk_path,
                "must remain pending/null and require an independent signed freeze",
            )
        )
    experiment_ids = {
        item.get("id") for item in risk.get("experiments", []) if isinstance(item, dict)
    }
    if experiment_ids != {
        "sse-source-faithful-capture",
        "responses-typed-event-fsm",
        "sdk-forward-proxy-correlation",
        "multi-tool-fingerprint-minimization",
    }:
        issues.append(
            Issue("risk_experiment_set_drift", risk_path, "experiment set drift")
        )
    if (
        risk.get("dualView", {}).get("eligibleMinimum") != 10
        or risk.get("dualView", {}).get("successMinimum") != 8
    ):
        issues.append(Issue("dual_view_threshold_drift", risk_path, "threshold drift"))
    if (
        risk.get("minimization", {}).get("attemptMinimum") != 10
        or risk.get("minimization", {}).get("qualifyingMinimum") != 5
        or risk.get("minimization", {}).get("minimumReduction") != 0.3
    ):
        issues.append(
            Issue("minimization_threshold_drift", risk_path, "threshold drift")
        )
    if risk.get("secretCanary", {}).get("maximumPersistedOccurrences") != 0:
        issues.append(Issue("secret_canary_threshold_drift", risk_path, "must be zero"))

    go_path = "execution/catalogs/p00/go-no-go.yaml"
    go_no_go = documents.get(go_path, {})
    if set(go_no_go.get("decisionOptions", [])) != {
        "CONVERGED",
        "BLOCKED",
        "PIVOT_REQUIRED",
    }:
        issues.append(Issue("go_no_go_decision_drift", go_path, "options drift"))
    if (
        go_no_go.get("workUnitMayDecide") is not False
        or go_no_go.get("localGateMayDecide") is not False
    ):
        issues.append(
            Issue("self_deciding_go_no_go", go_path, "local decision forbidden")
        )


def _validate_support_manifests(
    documents: dict[str, Any], expected_digest: str, issues: list[Issue]
) -> None:
    for path, document in documents.items():
        if path in {
            "execution/control-plane-inputs.yaml",
            # This snapshot is content-pinned from the trust policy rather
            # than recursively embedding the aggregate digest it helps form.
            "execution/protected-verifier/github-actions-oidc-jwks.json",
        } or not isinstance(document, dict):
            continue
        if document.get("controlPlaneDigest") != expected_digest:
            issues.append(
                Issue(
                    "control_plane_digest_mismatch",
                    path,
                    "manifest is not bound to aggregate",
                )
            )
    expected_kinds = {
        "execution/control-plane-inputs.yaml": "ControlPlaneInputManifestCandidate",
        "execution/product-stage-map.yaml": "ProductStageMapCandidate",
        "execution/impact-map.yaml": "ImpactMapCandidate",
        "execution/metrics/definitions.yaml": "MetricDefinitionCatalogCandidate",
        "execution/evaluators/catalog.yaml": "EvaluatorCatalogCandidate",
        "execution/evidence-schemas/catalog.yaml": "EvidenceSchemaCatalogCandidate",
    }
    for path, expected_kind in expected_kinds.items():
        if documents.get(path, {}).get("kind") != expected_kind:
            issues.append(Issue("invalid_manifest_kind", path, expected_kind))
    expected_statuses = {
        "execution/control-plane-inputs.yaml": (
            "manifestStatus",
            "candidate-unapproved",
        ),
        "execution/product-stage-map.yaml": ("mapStatus", "candidate-unapproved"),
        "execution/impact-map.yaml": ("mapStatus", "candidate-unapproved"),
        "execution/metrics/definitions.yaml": ("catalogStatus", "candidate-unapproved"),
        "execution/evaluators/catalog.yaml": ("catalogStatus", "candidate-unapproved"),
        "execution/evidence-schemas/catalog.yaml": (
            "catalogStatus",
            "candidate-unapproved",
        ),
    }
    for path, (field, expected_status) in expected_statuses.items():
        if documents.get(path, {}).get(field) != expected_status:
            issues.append(Issue("invalid_manifest_status", path, field))
    stage_path = "execution/product-stage-map.yaml"
    stage_map = documents.get(stage_path, {})
    if stage_map.get("phasePrerequisiteChain") != [f"P0{index}" for index in range(9)]:
        issues.append(Issue("phase_chain_drift", stage_path, "P00-P08 chain required"))
    stages = stage_map.get("stages")
    if not isinstance(stages, list) or len(stages) != 6:
        issues.append(
            Issue("product_stage_map_drift", stage_path, "six stages required")
        )
    else:
        phase_units = {
            "P00": [f"P00.W0{index}" for index in range(1, 6)],
            "P01": [f"P01.W0{index}" for index in range(1, 6)],
            "P02": [f"P02.W0{index}" for index in range(1, 7)],
            "P03": [f"P03.W0{index}" for index in range(1, 7)],
            "P04": [f"P04.W0{index}" for index in range(1, 8)],
            "P05": [f"P05.W0{index}" for index in range(1, 6)],
            "P06": [f"P06.W0{index}" for index in range(1, 6)],
            "P07": [f"P07.W0{index}" for index in range(1, 8)],
            "P08": [f"P08.W0{index}" for index in range(1, 5)],
        }
        expected_stages = {
            "STAGE-0": ["P00"],
            "STAGE-1": ["P01", "P02", "P03"],
            "STAGE-2": ["P04", "P05"],
            "STAGE-3": ["P06", "P07"],
            "STAGE-4": ["P08"],
            "STAGE-5": [],
        }
        actual_by_id = {
            stage.get("id"): stage for stage in stages if isinstance(stage, dict)
        }
        if set(actual_by_id) != set(expected_stages):
            issues.append(
                Issue("product_stage_id_drift", stage_path, "stage IDs drift")
            )
        for stage_id, phases in expected_stages.items():
            stage = actual_by_id.get(stage_id, {})
            expected_units = [unit for phase in phases for unit in phase_units[phase]]
            if (
                stage.get("phases") != phases
                or stage.get("workUnits") != expected_units
            ):
                issues.append(
                    Issue("product_stage_crosswalk_drift", stage_path, stage_id)
                )
    impact_path = "execution/impact-map.yaml"
    impact = documents.get(impact_path, {})
    if impact.get("defaultImpact") != "manual-review-required":
        issues.append(
            Issue("unsafe_default_impact", impact_path, "must require review")
        )
    if not isinstance(impact.get("mappings"), list) or len(impact["mappings"]) < 8:
        issues.append(
            Issue("incomplete_impact_map", impact_path, "P00 mappings missing")
        )
    else:
        expected_mapping_ids = {
            "plan-or-agent-policy",
            "control-plane-core",
            "phase-contract",
            "w01-bootstrap",
            "w02-research",
            "w03-corpus",
            "w04-experiments",
            "w05-design-evidence",
        }
        mapping_ids = {
            mapping.get("id")
            for mapping in impact["mappings"]
            if isinstance(mapping, dict)
        }
        if mapping_ids != expected_mapping_ids or any(
            not isinstance(mapping.get("paths"), list)
            or not mapping["paths"]
            or not isinstance(mapping.get("affected"), list)
            or not mapping["affected"]
            or not isinstance(mapping.get("reason"), str)
            or not mapping["reason"].strip()
            for mapping in impact["mappings"]
            if isinstance(mapping, dict)
        ):
            issues.append(Issue("impact_mapping_drift", impact_path, "mapping drift"))


def _validate_contract_catalog_closure(
    documents: dict[str, Any],
    evaluator_catalog: dict[str, dict[str, Any]],
    evidence_schema_catalog: dict[str, dict[str, Any]],
    issues: list[Issue],
) -> None:
    expected_evaluators: set[str] = set()
    expected_schemas: set[str] = set()
    for path, contract in documents.items():
        if not (
            path.startswith("execution/phases/")
            or path.startswith("execution/work-units/")
        ) or not isinstance(contract, dict):
            continue
        for criterion in contract.get("convergence", []):
            if not isinstance(criterion, dict):
                continue
            evaluator = criterion.get("evaluator")
            schema = criterion.get("evidenceSchema")
            if isinstance(evaluator, str):
                expected_evaluators.add(evaluator)
            if isinstance(schema, str):
                expected_schemas.add(schema)
            evaluator_entry = evaluator_catalog.get(evaluator, {})
            schema_entry = evidence_schema_catalog.get(schema, {})
            if evaluator_entry.get("status") != schema_entry.get("status"):
                issues.append(
                    Issue(
                        "evaluator_evidence_status_mismatch",
                        f"{path}#{criterion.get('id')}",
                        f"{evaluator_entry.get('status')} vs {schema_entry.get('status')}",
                    )
                )
    if set(evaluator_catalog) != expected_evaluators:
        issues.append(
            Issue(
                "evaluator_catalog_closure_drift",
                "execution/evaluators/catalog.yaml",
                f"unused={sorted(set(evaluator_catalog) - expected_evaluators)} missing={sorted(expected_evaluators - set(evaluator_catalog))}",
            )
        )
    if set(evidence_schema_catalog) != expected_schemas:
        issues.append(
            Issue(
                "evidence_schema_catalog_closure_drift",
                "execution/evidence-schemas/catalog.yaml",
                f"unused={sorted(set(evidence_schema_catalog) - expected_schemas)} missing={sorted(expected_schemas - set(evidence_schema_catalog))}",
            )
        )


def _validate_evaluator_references(
    root: Path,
    evaluator_catalog: dict[str, dict[str, Any]],
    declared_paths: set[str],
    issues: list[Issue],
) -> None:
    bootstrap_paths = {
        "tools/phasegate/main.py",
        "tools/phasegate/digest.py",
        "tools/phasegate/validation.py",
        "tools/phasegate/__init__.py",
    }
    p00_paths = {"tools/phasegate/p00_evaluators.py"}
    for evaluator_id, entry in evaluator_catalog.items():
        path = f"execution/evaluators/catalog.yaml#{evaluator_id}"
        implementation_paths = entry.get("implementationPaths")
        if entry.get("status") == "implemented":
            expected_paths = (
                bootstrap_paths
                if evaluator_id.startswith("evaluator://bootstrap/")
                else p00_paths
            )
            expected_tests = (
                ["test/bootstrap/test_phasegate.py"]
                if evaluator_id.startswith("evaluator://bootstrap/")
                else ["test/bootstrap/test_p00_evaluators.py"]
            )
            if set(implementation_paths or []) != expected_paths:
                issues.append(
                    Issue(
                        "implemented_evaluator_path_drift",
                        path,
                        str(implementation_paths),
                    )
                )
            if entry.get("protectedTests") != expected_tests:
                issues.append(
                    Issue(
                        "implemented_evaluator_test_drift", path, "protected test drift"
                    )
                )
        elif entry.get("status") == "planned" and implementation_paths != []:
            issues.append(
                Issue("planned_evaluator_has_code", path, str(implementation_paths))
            )
        for reference in implementation_paths or []:
            if reference not in declared_paths or not (root / reference).is_file():
                issues.append(Issue("unbound_evaluator_path", path, str(reference)))


def _validate_metric_references(
    root: Path,
    metric_catalog: dict[str, dict[str, Any]],
    evaluator_catalog: dict[str, dict[str, Any]],
    declared_paths: set[str],
    issues: list[Issue],
) -> None:
    evaluator_path = root / "tools/phasegate/p00_evaluators.py"
    try:
        expected_evaluator_digest = sha256_bytes(evaluator_path.read_bytes())
    except OSError as exc:
        issues.append(
            Issue(
                "unbound_evaluator_path",
                "tools/phasegate/p00_evaluators.py",
                str(exc),
            )
        )
        expected_evaluator_digest = None
    expected = {
        "p00_provenance_candidate_count": (
            "evaluator://catalog/provenance-count/v1",
            30,
        ),
        "p00_reproduction_rate": ("evaluator://corpus/reproduction/v1", 20),
        "p00_fault_domain_count": ("evaluator://corpus/taxonomy/v1", 20),
        "p00_deterministic_replay_count": ("evaluator://corpus/replay/v1", 10),
        "p00_dual_view_rate": ("evaluator://experiment/dual-view/v1", 10),
        "p00_minimization_30pct_rate": ("evaluator://experiment/minimization/v1", 10),
        "p00_secret_canary_persistence_rate": (
            "evaluator://redaction/secret-canary/v1",
            6,
        ),
        "p00_unknown_attribution_consistency": (
            "evaluator://attribution/unknown/v1",
            1,
        ),
    }
    if set(metric_catalog) != set(expected):
        issues.append(
            Issue(
                "metric_set_drift",
                "execution/metrics/definitions.yaml",
                f"missing={sorted(set(expected) - set(metric_catalog))} extra={sorted(set(metric_catalog) - set(expected))}",
            )
        )
    for metric_id, (evaluator_id, minimum_n) in expected.items():
        metric = metric_catalog.get(metric_id)
        if metric is None:
            continue
        location = f"execution/metrics/definitions.yaml#{metric_id}"
        if metric.get("evaluator") != evaluator_id:
            issues.append(
                Issue("metric_evaluator_drift", location, str(metric.get("evaluator")))
            )
        if evaluator_catalog.get(evaluator_id, {}).get("status") != "implemented":
            issues.append(
                Issue("metric_evaluator_not_implemented", location, evaluator_id)
            )
        if metric.get("minimumN") != minimum_n:
            issues.append(
                Issue("metric_minimum_n_drift", location, str(metric.get("minimumN")))
            )
        if (
            metric.get("status") != "implemented-evaluator-late-bound-dataset"
            or metric.get("datasetStatus") != "late_bound_requires_signed_freeze"
            or metric.get("datasetDigest") is not None
        ):
            issues.append(
                Issue(
                    "unapproved_metric_state",
                    location,
                    "implemented evaluator must remain bound to a null late-bound dataset",
                )
            )
        if metric.get("evaluatorDigest") != expected_evaluator_digest:
            issues.append(
                Issue(
                    "metric_evaluator_digest_mismatch",
                    location,
                    "must bind the exact tools/phasegate/p00_evaluators.py bytes",
                )
            )
        if metric.get("datasetCatalog") not in declared_paths:
            issues.append(
                Issue(
                    "unbound_metric_dataset",
                    location,
                    str(metric.get("datasetCatalog")),
                )
            )


def _validate_protected_test_contract(root: Path, issues: list[Issue]) -> None:
    suites = _expected_test_suites(root, issues)
    required_by_suite = {
        "bootstrap": REQUIRED_ANTI_PLACEHOLDER_TESTS,
        "protectedV1Historical": REQUIRED_PROTECTED_VERIFIER_TESTS,
    }
    for suite_id, required in required_by_suite.items():
        relative = TEST_SUITE_MODULES[suite_id][0]
        methods = set(suites[suite_id]["cases"])
        missing = sorted(
            set(required) - methods, key=lambda value: value.encode("utf-8")
        )
        if missing:
            issues.append(
                Issue("missing_protected_meta_test", relative, f"missing {missing}")
            )


def _validate_pre_genesis(
    root: Path, documents: dict[str, Any], issues: list[Issue]
) -> None:
    forbidden_paths = [
        "execution/phase-state.yaml",
        "execution/transitions",
        "execution/approvals",
        "execution/progress.md",
        "execution/decisions.md",
        "execution/blockers.md",
        "execution/waivers.yaml",
    ]
    for declared in forbidden_paths:
        path = root / declared
        if path.exists():
            issues.append(
                Issue(
                    "forbidden_pre_genesis_state",
                    declared,
                    "must not exist before Genesis",
                )
            )
    for path, document in documents.items():
        if path.startswith("execution/gates/p00/") and isinstance(document, dict):
            if document.get("kind") in {"PhaseGateEvidence", "RunEvidence"}:
                issues.append(
                    Issue(
                        "forbidden_completion_evidence",
                        path,
                        "B00 cannot contain gate evidence",
                    )
                )
    # Product implementation is explicitly out of scope for B00.  Empty
    # directories are harmless and untracked; files are not.
    product_roots = (
        "cmd",
        "internal",
        "pkg",
        "packs",
        "profiles",
        "registry",
        "web",
        "runners",
    )
    for product_root in product_roots:
        path = root / product_root
        if path.exists() and any(item.is_file() for item in path.rglob("*")):
            issues.append(
                Issue(
                    "product_implementation_before_genesis",
                    product_root,
                    "P00.B00 may not add product implementation",
                )
            )


def _validate_protected_verifier_candidate(
    root: Path,
    documents: dict[str, Any],
    control_plane_digest: str,
    issues: list[Issue],
) -> None:
    codeowners_path = ".github/CODEOWNERS"
    try:
        codeowners = (root / codeowners_path).read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(Issue("missing_codeowners", codeowners_path, str(exc)))
    else:
        effective_rules = [
            line.strip()
            for line in codeowners.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if effective_rules != ["* @whyiug"]:
            issues.append(
                Issue(
                    "invalid_codeowners",
                    codeowners_path,
                    "R3 protection requires one exact catch-all owner",
                )
            )
    policy_path = "execution/protected-verifier/trust-policy.yaml"
    jwks_path = "execution/protected-verifier/github-actions-oidc-jwks.json"
    policy = documents.get(policy_path)
    jwks = documents.get(jwks_path)
    if not isinstance(policy, dict):
        issues.append(
            Issue(
                "missing_protected_verifier_policy",
                policy_path,
                "protected verifier policy is required",
            )
        )
    elif not isinstance(jwks, dict):
        issues.append(
            Issue(
                "missing_oidc_jwks_snapshot",
                jwks_path,
                "the offline GitHub Actions JWK snapshot is required",
            )
        )
    else:
        try:
            snapshot_digest = jwks_snapshot_digest(jwks)
            validate_trust_policy_v2(
                policy,
                jwks_snapshot=jwks,
                expected_policy_digest=document_digest(policy),
                expected_jwks_snapshot_digest=snapshot_digest,
                expected_control_plane_digest=control_plane_digest,
            )
        except ProtectedVerificationError as exc:
            issues.append(Issue(exc.code, policy_path, exc.message))
        except ValueError as exc:
            issues.append(Issue("invalid_oidc_jwks_snapshot", jwks_path, str(exc)))

    workflow_contract_path = "execution/protected-verifier/workflow-contract.yaml"
    contract = documents.get(workflow_contract_path)
    if not isinstance(contract, dict):
        issues.append(
            Issue(
                "missing_protected_workflow_contract",
                workflow_contract_path,
                "read-only protected workflow contract is required",
            )
        )
    else:
        required = {
            "schemaVersion": "urn:agentapi-doctor:protected-verifier-workflow-contract:v1alpha2",
            "kind": "ProtectedStateWorkflowContractCandidate",
            "id": "P00.B00-R3-protected-workflows",
            "contractStatus": "candidate-unapproved",
            "authoritative": "conditional-after-independent-R3-approval-and-live-protection-proof",
            "controlPlaneIncluded": True,
            "controlPlaneDigest": control_plane_digest,
        }
        for key, expected in required.items():
            if contract.get(key) != expected:
                issues.append(
                    Issue(
                        "protected_workflow_contract_drift",
                        f"{workflow_contract_path}#{key}",
                        f"expected {expected!r}",
                    )
                )
        expected_workflows = {
            "controlPlane": ".github/workflows/p00-protected-control-plane.yml",
            "crossPlatform": ".github/workflows/p00-bootstrap-cross-platform.yml",
            "stateWriter": ".github/workflows/p00-protected-state-writer.yml",
            "historicalR2ReadOnlyCandidate": ".github/workflows/p00-protected-verifier-candidate.yml",
        }
        if contract.get("workflows") != expected_workflows:
            issues.append(
                Issue(
                    "protected_workflow_contract_drift",
                    f"{workflow_contract_path}#workflows",
                    "R3 workflow set drift",
                )
            )
        permissions = contract.get("permissions")
        genesis = contract.get("genesisWriter")
        activation = contract.get("activation")
        append_writer = contract.get("appendWriter")
        trigger = contract.get("trigger")
        repository_protection = contract.get("repositoryProtection")
        outputs = contract.get("outputs")
        if not (
            isinstance(permissions, dict)
            and permissions.get("contentsWrite") is False
            and isinstance(permissions.get("githubToken"), dict)
            and permissions.get("githubToken", {}).get("actions") == "read"
            and permissions.get("idToken")
            == "write only in the state-writer job after approval validation"
            and permissions.get("secrets") == []
            and isinstance(genesis, dict)
            and genesis.get("present") is True
            and genesis.get("writesRepository") is False
            and genesis.get("createsSignedArtifact") is True
            and isinstance(activation, dict)
            and activation.get("mayProduceApprovalFact") is False
            and activation.get("mayImportOrActivateState") is False
            and isinstance(append_writer, dict)
            and append_writer.get("present") is True
            and append_writer.get("writesRepository") is False
            and append_writer.get("readsArtifactsByImmutableId") is True
            and append_writer.get("replaysFromGenesisBeforeAppend") is True
            and append_writer.get("atomicOutputDirectory") is True
            and append_writer.get("supportedOperations")
            == [
                "evidence-attachment",
                "phase-transition",
                "work-unit-activation",
                "work-unit-convergence",
                "work-unit-readiness",
            ]
            and append_writer.get("unsupportedLifecycleWrites")
            == [
                "work-unit-control-invalidation",
                "work-unit-impact-invalidation",
                "work-unit-resume",
                "work-unit-supersession",
            ]
            and isinstance(trigger, dict)
            and trigger.get("appendPins")
            == [
                "bootstrapRequestCommit",
                "currentChainHeadDigest",
                "workflowExecutionCommit",
                "operation",
                "toState",
                "phase",
                "conditionalWorkUnit",
                "optionalAuthorizationBundleDigest",
            ]
            and isinstance(repository_protection, dict)
            and repository_protection.get("requiredVisibility") == "public"
            and repository_protection.get("branch") == "main"
            and repository_protection.get("liveProofRequired") is True
            and repository_protection.get("oidcRefProtectedRequired") is True
            and repository_protection.get("currentRepositoryVisibility") == "private"
            and repository_protection.get("currentProofStatus")
            == "missing-blocks-authoritative-use"
            and isinstance(outputs, dict)
            and outputs.get("repositoryWrite") is False
        ):
            issues.append(
                Issue(
                    "unsafe_protected_workflow_contract",
                    workflow_contract_path,
                    "R3 may only emit a conditional artifact after approval and live protection proof",
                )
            )
        expected_action_pins = [
            {
                "repository": "actions/checkout",
                "version": "v4.3.1",
                "commit": "34e114876b0b11c390a56381ad16ebd13914f8d5",
            },
            {
                "repository": "actions/upload-artifact",
                "version": "v4.6.2",
                "commit": "ea165f8d65b6e75b540449e92b4886f43607fa02",
            },
            {
                "repository": "actions/download-artifact",
                "version": "v4.3.0",
                "commit": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
            },
        ]
        if contract.get("actionPins") != expected_action_pins:
            issues.append(
                Issue(
                    "protected_workflow_action_pin_drift",
                    workflow_contract_path,
                    "external action pin set drift",
                )
            )

    checkout = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    upload = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    download = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    workflow_contracts = {
        ".github/workflows/p00-protected-control-plane.yml": {
            "actions": {checkout},
            "required": {
                "permissions:\n  contents: read",
                "persist-credentials: false",
                "make verify",
                "state-verify --root .",
            },
            "idToken": False,
        },
        ".github/workflows/p00-bootstrap-cross-platform.yml": {
            "actions": {checkout, upload, download},
            "required": {
                "permissions:\n  contents: read",
                "persist-credentials: false",
                "fetch-depth: 0",
                "ubuntu-24.04, macos-14, windows-2022",
                "expected exactly three platform results",
            },
            "idToken": False,
        },
        ".github/workflows/p00-protected-state-writer.yml": {
            "actions": {checkout, upload, download},
            "required": {
                "permissions:",
                "contents: read",
                "actions: read",
                "id-token: write",
                "inputs.mode == 'genesis'",
                "inputs.mode == 'append'",
                "github.ref_protected == true",
                "github.run_attempt == 1",
                'test "$WORKFLOW_EXECUTION_SHA" = "$GITHUB_SHA"',
                "PYTHONPATH: request-input",
                "validate_bootstrap_candidate",
                "artifact-ids: ${{ inputs.chain_artifact_id }}",
                "artifact-ids: ${{ inputs.bundle_artifact_id }}",
                "github-token: ${{ github.token }}",
                "repository: ${{ github.repository }}",
                "run-id: ${{ inputs.chain_run_id }}",
                "run-id: ${{ inputs.bundle_run_id }}",
                "protected-chain-append",
                "phase-transition",
                'test "$PHASE" = P00',
                "os.O_NOFOLLOW",
                "os.fstat(descriptor)",
                "retention-days: 1",
            },
            "idToken": True,
        },
        ".github/workflows/p00-protected-verifier-candidate.yml": {
            "actions": {checkout},
            "required": {
                "workflow_dispatch:",
                "permissions:\n  contents: read",
                "persist-credentials: false",
                "vars.P00_ACTIVATION_STATUS",
            },
            "idToken": False,
        },
    }
    globally_forbidden = (
        "pull_request_target",
        "contents: write",
        "actions: write",
        "continue-on-error:",
        "curl ",
        "wget ",
        "pip install",
        "python3 candidate-input",
        "bash candidate-input",
        "make -C candidate-input",
        "cd candidate-input",
    )
    for relative, source_contract in workflow_contracts.items():
        workflow_path = root / relative
        try:
            workflow = workflow_path.read_text(encoding="utf-8")
        except OSError as exc:
            issues.append(
                Issue("missing_protected_workflow_candidate", relative, str(exc))
            )
            continue
        action_uses = set(
            re.findall(
                r"^\s*uses:\s*([^#\s]+)(?:\s+#.*)?$",
                workflow,
                flags=re.MULTILINE,
            )
        )
        forbidden = list(globally_forbidden)
        if source_contract["idToken"] is False:
            forbidden.append("id-token: write")
        if relative == ".github/workflows/p00-protected-state-writer.yml":
            forbidden.extend(("PYTHONPATH: trusted", "cd trusted", "python3 trusted"))
        writer_job_guard_drift = (
            relative == ".github/workflows/p00-protected-state-writer.yml"
            and (
                workflow.count("github.ref_protected == true") != 2
                or workflow.count("github.run_attempt == 1") != 2
                or workflow.count("inputs.mode == 'genesis'") != 1
                or workflow.count("inputs.mode == 'append'") != 1
            )
        )
        if (
            any(fragment not in workflow for fragment in source_contract["required"])
            or any(fragment in workflow for fragment in forbidden)
            or action_uses != source_contract["actions"]
            or writer_job_guard_drift
        ):
            issues.append(
                Issue(
                    "unsafe_protected_workflow_candidate",
                    relative,
                    "R3 permission, source-boundary, action-pin, or fail-closed invariant drifted",
                )
            )


def _validate_approval_request(
    root: Path,
    control_plane_digest: str,
    components: list[dict[str, str]],
    issues: list[Issue],
) -> None:
    path = root / ACTIVE_REQUEST_PATH
    historical_requests = (
        (
            ORIGINAL_REQUEST_PATH,
            ORIGINAL_REQUEST_FILE_DIGEST,
            ORIGINAL_REQUEST_DIGEST,
        ),
        (R2_REQUEST_PATH, R2_REQUEST_FILE_DIGEST, R2_REQUEST_DIGEST),
    )
    loaded_history: dict[str, Any] = {}
    for relative, expected_file_digest, expected_document_digest in historical_requests:
        historical_path = root / relative
        try:
            historical = load_json_yaml(historical_path)
        except DigestError as exc:
            issues.append(Issue("invalid_previous_request", relative, str(exc)))
            continue
        loaded_history[relative] = historical
        raw_digest = (
            sha256_bytes(historical_path.read_bytes())
            if historical_path.is_file()
            else None
        )
        if (
            document_digest(historical) != expected_document_digest
            or raw_digest != expected_file_digest
        ):
            issues.append(
                Issue(
                    "previous_request_drift",
                    relative,
                    "historical request revisions must remain byte-for-byte immutable",
                )
            )
    original = loaded_history.get(ORIGINAL_REQUEST_PATH, {})
    r2 = loaded_history.get(R2_REQUEST_PATH, {})
    if isinstance(r2, dict) and r2.get("previousRequest") != {
        "requestId": "P00.B00",
        "revision": 1,
        "requestDigest": ORIGINAL_REQUEST_DIGEST,
        "controlPlaneDigest": ORIGINAL_CONTROL_PLANE_DIGEST,
        "candidateSourceCommit": ORIGINAL_CANDIDATE_SOURCE_COMMIT,
    }:
        issues.append(
            Issue(
                "previous_request_drift",
                R2_REQUEST_PATH,
                "R2 no longer binds the immutable original request",
            )
        )
    if isinstance(original, dict) and original.get("requestId") != "P00.B00":
        issues.append(
            Issue(
                "previous_request_drift",
                ORIGINAL_REQUEST_PATH,
                "original request identity drift",
            )
        )
    if not path.is_file():
        issues.append(
            Issue(
                "missing_approval_request",
                ACTIVE_REQUEST_PATH,
                "P00.B00-R3 request is required",
            )
        )
        return
    try:
        request = load_json_yaml(path)
    except DigestError as exc:
        issues.append(Issue("invalid_approval_request", ACTIVE_REQUEST_PATH, str(exc)))
        return
    if not isinstance(request, dict):
        issues.append(
            Issue("invalid_approval_request", ACTIVE_REQUEST_PATH, "must be an object")
        )
        return
    expected_top_level = {
        "schemaVersion",
        "kind",
        "requestId",
        "revision",
        "previousRequest",
        "requestStatus",
        "candidate",
        "componentDigests",
        "digestGroups",
        "testSuites",
        "diff",
        "decisionsRequested",
        "ambiguities",
        "limitations",
        "nextAuthorizedAction",
    }
    if set(request) != expected_top_level:
        issues.append(
            Issue(
                "invalid_approval_request_schema",
                ACTIVE_REQUEST_PATH,
                "top-level field set drift",
            )
        )
    if (
        request.get("schemaVersion") != "urn:agentapi-doctor:bootstrap-request:v1alpha3"
        or request.get("kind") != "BootstrapControlPlaneReviewRequest"
        or request.get("requestId") != "P00.B00-R3"
        or request.get("revision") != 3
    ):
        issues.append(
            Issue(
                "invalid_approval_request_identity",
                ACTIVE_REQUEST_PATH,
                "revision identity drift",
            )
        )
    expected_previous = {
        "requestId": "P00.B00-R2",
        "revision": 2,
        "requestDigest": R2_REQUEST_DIGEST,
        "controlPlaneDigest": R2_CONTROL_PLANE_DIGEST,
        "candidateSourceCommit": R2_CANDIDATE_SOURCE_COMMIT,
        "requestCommit": R2_REQUEST_COMMIT,
    }
    if request.get("previousRequest") != expected_previous:
        issues.append(
            Issue(
                "request_revision_chain_mismatch",
                ACTIVE_REQUEST_PATH,
                "previous request binding drift",
            )
        )
    if request.get("requestStatus") != "pending_review":
        issues.append(
            Issue(
                "invalid_request_status", ACTIVE_REQUEST_PATH, "must be pending_review"
            )
        )
    candidate = request.get("candidate")
    expected_candidate_keys = {
        "baseCommit",
        "candidateSourceCommit",
        "gitObjectFormat",
        "canonicalPlanPath",
        "controlPlaneDigest",
    }
    if not isinstance(candidate, dict) or set(candidate) != expected_candidate_keys:
        issues.append(
            Issue(
                "invalid_request_candidate",
                ACTIVE_REQUEST_PATH,
                "candidate field set drift",
            )
        )
        candidate = {}
    if candidate.get("controlPlaneDigest") != control_plane_digest:
        issues.append(
            Issue(
                "request_digest_mismatch",
                ACTIVE_REQUEST_PATH,
                "request does not bind computed control-plane digest",
            )
        )
    for key in ("baseCommit", "candidateSourceCommit"):
        value = candidate.get(key)
        if not (
            isinstance(value, str)
            and len(value) == 40
            and all(character in "0123456789abcdef" for character in value)
        ):
            issues.append(
                Issue(
                    "invalid_request_source_commit",
                    ACTIVE_REQUEST_PATH,
                    f"invalid {key}",
                )
            )
    if (
        candidate.get("baseCommit") != R2_REQUEST_COMMIT
        or candidate.get("gitObjectFormat") != "sha1"
        or candidate.get("canonicalPlanPath") != "agentapi-doctor-Plan.md"
    ):
        issues.append(
            Issue(
                "request_candidate_binding_drift",
                ACTIVE_REQUEST_PATH,
                "candidate base/format/path drift",
            )
        )

    source_commit = candidate.get("candidateSourceCommit")
    if (root / ".git").exists() and isinstance(source_commit, str):
        declared_paths = [item["path"] for item in components]
        try:
            committed_paths = set(
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(root),
                        "ls-tree",
                        "-r",
                        "--name-only",
                        source_commit,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                ).stdout.splitlines()
            )
            exact = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "diff",
                    "--quiet",
                    source_commit,
                    "--",
                    *declared_paths,
                ],
                check=False,
                timeout=30,
            ).returncode
            if not set(declared_paths).issubset(committed_paths) or exact != 0:
                raise ValueError(
                    "source commit does not exactly contain current inputs"
                )
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            issues.append(
                Issue(
                    "request_source_commit_mismatch",
                    ACTIVE_REQUEST_PATH,
                    str(exc),
                )
            )

    expected = {item["path"]: item["digest"] for item in components}
    if request.get("componentDigests") != expected:
        issues.append(
            Issue(
                "request_component_digest_mismatch",
                ACTIVE_REQUEST_PATH,
                "componentDigests must exactly match declared inputs",
            )
        )
    try:
        expected_groups = approval_digest_groups(components)
    except DigestError as exc:
        issues.append(
            Issue("request_digest_group_error", ACTIVE_REQUEST_PATH, str(exc))
        )
        expected_groups = {}
    if request.get("digestGroups") != expected_groups:
        issues.append(
            Issue(
                "request_digest_group_mismatch",
                ACTIVE_REQUEST_PATH,
                "named digest groups must be recomputed",
            )
        )
    expected_test_suites = _expected_test_suites(root, issues)
    test_suites = request.get("testSuites")
    if test_suites != expected_test_suites:
        issues.append(
            Issue(
                "request_test_suite_drift",
                ACTIVE_REQUEST_PATH,
                "R3 testSuites must exactly bind every protected module and sorted test_* case",
            )
        )

    diff = request.get("diff")
    if not isinstance(diff, dict):
        issues.append(
            Issue("invalid_request_diff", ACTIVE_REQUEST_PATH, "diff missing")
        )
    else:
        if diff.get("forbiddenArtifactsVerifiedAbsent") != list(
            REQUIRED_FORBIDDEN_ABSENCE
        ):
            issues.append(
                Issue(
                    "request_forbidden_absence_drift",
                    ACTIVE_REQUEST_PATH,
                    "absence list drift",
                )
            )
        entries = diff.get("entries")
        entry_list = entries if isinstance(entries, list) else []
        entry_paths = {
            item.get("path") for item in entry_list if isinstance(item, dict)
        }
        required_diff_paths = {
            ".github/CODEOWNERS",
            ".github/workflows/p00-bootstrap-cross-platform.yml",
            ".github/workflows/p00-protected-control-plane.yml",
            ".github/workflows/p00-protected-state-writer.yml",
            "execution/control-plane-inputs.yaml",
            "execution/evaluators/catalog.yaml",
            "execution/evidence-schemas/catalog.yaml",
            "execution/metrics/definitions.yaml",
            "execution/protected-verifier/ambiguities.yaml",
            "execution/protected-verifier/github-actions-oidc-jwks.json",
            "execution/protected-verifier/trust-policy.yaml",
            "execution/protected-verifier/workflow-contract.yaml",
            "test/bootstrap/test_chain_artifact.py",
            "test/bootstrap/test_oidc.py",
            "test/bootstrap/test_oidc_provenance.py",
            "test/bootstrap/test_chain_witness.py",
            "test/bootstrap/test_control_context.py",
            "test/bootstrap/test_delegation.py",
            "test/bootstrap/test_execution_artifact.py",
            "test/bootstrap/test_external_facts.py",
            "test/bootstrap/test_gate_runner.py",
            "test/bootstrap/test_p00_evaluators.py",
            "test/bootstrap/test_phasegate.py",
            "test/bootstrap/test_post_event_writer.py",
            "test/bootstrap/test_protected_v2.py",
            "test/bootstrap/test_provenance.py",
            "test/bootstrap/test_provenance_writer.py",
            "test/bootstrap/test_run_executor.py",
            "test/bootstrap/test_serialized_bundle.py",
            "test/bootstrap/test_sshsig.py",
            "test/bootstrap/test_state_chain_v2.py",
            "test/bootstrap/test_state_writer.py",
            "test/bootstrap/test_workflow_orchestrator.py",
            "tools/phasegate/oidc.py",
            "tools/phasegate/chain_artifact.py",
            "tools/phasegate/oidc_provenance.py",
            "tools/phasegate/chain_witness.py",
            "tools/phasegate/control_context.py",
            "tools/phasegate/delegation.py",
            "tools/phasegate/execution_artifact.py",
            "tools/phasegate/external_facts.py",
            "tools/phasegate/gate_runner.py",
            "tools/phasegate/p00_evaluators.py",
            "tools/phasegate/prepare_request.py",
            "tools/phasegate/post_event_writer.py",
            "tools/phasegate/protected_v2.py",
            "tools/phasegate/provenance.py",
            "tools/phasegate/provenance_writer.py",
            "tools/phasegate/run_executor.py",
            "tools/phasegate/serialized_bundle.py",
            "tools/phasegate/sshsig.py",
            "tools/phasegate/state_chain_v2.py",
            "tools/phasegate/state_writer.py",
            "tools/phasegate/workflow_orchestrator.py",
            "tools/phasegate/validation.py",
        }
        required_diff_paths.add(ACTIVE_REQUEST_PATH)
        if not isinstance(entries, list) or not required_diff_paths.issubset(
            entry_paths
        ):
            issues.append(
                Issue(
                    "incomplete_request_diff",
                    ACTIVE_REQUEST_PATH,
                    "verifier revision paths are missing",
                )
            )
        if any(
            not isinstance(item, dict)
            or set(item) != {"status", "path"}
            or not isinstance(item.get("status"), str)
            or not item["status"]
            or not isinstance(item.get("path"), str)
            or not item["path"]
            or item["path"].startswith("/")
            or ".." in Path(item["path"]).parts
            for item in entry_list
        ) or len(entry_paths) != len(entry_list):
            issues.append(
                Issue(
                    "invalid_request_diff",
                    ACTIVE_REQUEST_PATH,
                    "diff entries must be unique, relative {status,path} objects",
                )
            )
        if diff.get("baseCommit") != candidate.get("baseCommit"):
            issues.append(
                Issue("request_diff_base_mismatch", ACTIVE_REQUEST_PATH, "base drift")
            )
    decisions = request.get("decisionsRequested")
    decision_ids = [
        item.get("id")
        for item in (decisions if isinstance(decisions, list) else [])
        if isinstance(item, dict)
    ]
    if (
        set(decision_ids) != REQUIRED_DECISION_IDS
        or len(decision_ids) != len(REQUIRED_DECISION_IDS)
        or not isinstance(decisions, list)
        or len(decisions) != len(REQUIRED_DECISION_IDS)
        or any(
            set(item) != {"id", "question"}
            or not isinstance(item.get("question"), str)
            or not item["question"].strip()
            for item in (decisions if isinstance(decisions, list) else [])
            if isinstance(item, dict)
        )
    ):
        issues.append(
            Issue(
                "request_decision_set_drift", ACTIVE_REQUEST_PATH, "decision set drift"
            )
        )
    ambiguity_path = "execution/protected-verifier/ambiguities.yaml"
    try:
        ambiguity_register = load_json_yaml(root / ambiguity_path)
        entries = ambiguity_register.get("entries")
        if not isinstance(entries, list):
            raise ValueError("entries must be a list")
        expected_ambiguities = [
            {
                "id": item["id"],
                "decisionCandidate": item["decisionCandidate"],
                "currentEffect": item["currentEffect"],
            }
            for item in entries
            if isinstance(item, dict)
        ]
    except (DigestError, KeyError, TypeError, ValueError) as exc:
        issues.append(Issue("invalid_ambiguity_register", ambiguity_path, str(exc)))
        expected_ambiguities = []
    expected_ambiguity_ids = {
        "P00-A-OIDC-PROTECTED-WORKFLOW",
        "P00-A-LATE-BOUND-DATASET-FREEZE",
        "P00-A-CONTROL-PLANE-REVISION",
        "P00-A-GO-NOGO-THRESHOLD",
    }
    if (
        request.get("ambiguities") != expected_ambiguities
        or {item.get("id") for item in expected_ambiguities} != expected_ambiguity_ids
        or len(expected_ambiguities) != len(expected_ambiguity_ids)
    ):
        issues.append(
            Issue(
                "request_ambiguity_projection_drift",
                ACTIVE_REQUEST_PATH,
                "ambiguities must exactly project id/decisionCandidate/currentEffect",
            )
        )
    if (
        not isinstance(request.get("limitations"), list)
        or len(request["limitations"]) < 6
        or any(
            not isinstance(item, str) or not item.strip()
            for item in request.get("limitations", [])
        )
        or (
            all(isinstance(item, str) for item in request.get("limitations", []))
            and len(request["limitations"]) != len(set(request["limitations"]))
        )
    ):
        issues.append(
            Issue(
                "missing_request_limitations",
                ACTIVE_REQUEST_PATH,
                "limitations missing",
            )
        )
    if (
        not isinstance(request.get("nextAuthorizedAction"), str)
        or not request["nextAuthorizedAction"].strip()
    ):
        issues.append(
            Issue(
                "missing_next_authorized_action",
                ACTIVE_REQUEST_PATH,
                "request must name the next independently authorized action",
            )
        )
    for key, _, location in _walk_keys(request):
        normalized = key.lower().replace("_", "").replace("-", "")
        if any(fragment in normalized for fragment in FORBIDDEN_REQUEST_KEY_FRAGMENTS):
            issues.append(
                Issue(
                    "agent_authored_approval_fact",
                    f"{ACTIVE_REQUEST_PATH}#{location}",
                    f"request may not contain approval fact key {key!r}",
                )
            )
        if normalized in FORBIDDEN_REQUEST_FACT_KEYS:
            issues.append(
                Issue(
                    "agent_authored_approval_fact",
                    f"{ACTIVE_REQUEST_PATH}#{location}",
                    f"request may not contain decision fact key {key!r}",
                )
            )
        if normalized in {"phase", "activephase", "activeworkunit", "phasestatus"}:
            issues.append(
                Issue(
                    "approval_request_is_not_state",
                    f"{ACTIVE_REQUEST_PATH}#{location}",
                    f"request may not contain state field {key!r}",
                )
            )


def validate_bootstrap_candidate(
    root: Path,
    require_request: bool = True,
    require_pre_genesis: bool = True,
) -> dict[str, Any]:
    root = root.resolve()
    issues: list[Issue] = []
    try:
        manifest, declared_inputs = read_input_manifest(root)
        control_plane_digest, components = compute_control_plane_digest(
            root, declared_inputs
        )
        documents = _json_files(root, declared_inputs)
    except DigestError as exc:
        raise ValidationError(
            [
                Issue(
                    "digest_input_error",
                    "execution/control-plane-inputs.yaml",
                    str(exc),
                )
            ]
        ) from exc

    _validate_input_closure(root, declared_inputs, issues)

    if (
        manifest.get("controlPlaneDigestPlaceholder")
        != "sha256:__CONTROL_PLANE_DIGEST__"
    ):
        issues.append(
            Issue(
                "invalid_digest_projection",
                "execution/control-plane-inputs.yaml",
                "controlPlaneDigestPlaceholder is not the fixed bootstrap token",
            )
        )
    if manifest.get("canonicalization") != "bootstrap-canonical-json-v1":
        issues.append(
            Issue(
                "invalid_canonicalization",
                "execution/control-plane-inputs.yaml",
                "B00 supports only bootstrap-canonical-json-v1",
            )
        )
    if manifest.get("digestAlgorithm") != "sha256":
        issues.append(
            Issue(
                "invalid_digest_algorithm",
                "execution/control-plane-inputs.yaml",
                "sha256 required",
            )
        )
    normalization = manifest.get("normalization")
    if (
        not isinstance(normalization, dict)
        or set(normalization)
        != {
            "jsonCompatibleYaml",
            "controlPlaneDigest",
            "text",
            "aggregate",
        }
        or any(
            not isinstance(value, str) or not value for value in normalization.values()
        )
    ):
        issues.append(
            Issue(
                "invalid_normalization_contract",
                "execution/control-plane-inputs.yaml",
                "projection drift",
            )
        )
    excluded = manifest.get("excluded")
    excluded_paths = {
        item.get("path")
        for item in (excluded if isinstance(excluded, list) else [])
        if isinstance(item, dict)
    }
    required_excluded_paths = {
        "execution/approval-requests/**",
        "execution/approvals/**",
        "execution/blockers.md",
        "execution/decisions.md",
        "execution/phase-state.yaml",
        "execution/progress.md",
        "execution/transitions/**",
        "execution/gates/p00/evidence/**",
        "execution/gates/p00/latest.json",
        "execution/waivers.yaml",
    }
    if excluded_paths != required_excluded_paths or any(
        not isinstance(item.get("reason"), str) or not item["reason"].strip()
        for item in (excluded if isinstance(excluded, list) else [])
        if isinstance(item, dict)
    ):
        issues.append(
            Issue(
                "invalid_exclusion_contract",
                "execution/control-plane-inputs.yaml",
                "exclusion drift",
            )
        )

    evaluator_path = "execution/evaluators/catalog.yaml"
    evidence_schema_path = "execution/evidence-schemas/catalog.yaml"
    metric_path = "execution/metrics/definitions.yaml"
    evaluator_catalog = _validate_evaluator_catalog(
        documents.get(evaluator_path), evaluator_path, issues
    )
    metric_catalog = _validate_metric_document(
        documents.get(metric_path), metric_path, issues
    )
    evidence_schema_catalog = _validate_evidence_schema_catalog(
        documents.get(evidence_schema_path), evidence_schema_path, issues
    )
    declared_paths = {entry["path"] for entry in declared_inputs}
    _validate_support_manifests(documents, control_plane_digest, issues)
    _validate_evaluator_references(root, evaluator_catalog, declared_paths, issues)
    _validate_metric_references(
        root, metric_catalog, evaluator_catalog, declared_paths, issues
    )
    _validate_protected_test_contract(root, issues)

    for path, document in documents.items():
        if path.startswith("execution/phases/") or path.startswith(
            "execution/work-units/"
        ):
            _validate_contract(
                root,
                document,
                path,
                control_plane_digest,
                evaluator_catalog,
                metric_catalog,
                evidence_schema_catalog,
                declared_paths,
                issues,
            )
    _validate_contract_catalog_closure(
        documents, evaluator_catalog, evidence_schema_catalog, issues
    )
    _validate_gate_documents(
        documents,
        control_plane_digest,
        evaluator_catalog,
        metric_catalog,
        evidence_schema_catalog,
        declared_paths,
        issues,
    )
    _validate_catalog_semantics(documents, evaluator_catalog, issues)
    _validate_protected_verifier_candidate(
        root, documents, control_plane_digest, issues
    )
    if require_pre_genesis:
        _validate_pre_genesis(root, documents, issues)
    if require_request:
        _validate_approval_request(root, control_plane_digest, components, issues)

    if issues:
        raise ValidationError(issues)
    return {
        "mode": (
            "pre_genesis_candidate"
            if require_pre_genesis
            else "protected_state_verifier_candidate"
        ),
        "controlPlaneDigest": control_plane_digest,
        "componentDigests": {item["path"]: item["digest"] for item in components},
        "componentCount": len(components),
        "contractCount": sum(
            1
            for path in documents
            if path.startswith("execution/phases/")
            or path.startswith("execution/work-units/")
        ),
        "evaluatorCount": len(evaluator_catalog),
        "metricCount": len(metric_catalog),
    }


def ensure_gate_is_executable(root: Path, gate_path: str) -> None:
    """Reject a gate containing an unknown or not-yet-implemented evaluator."""

    evaluator_document = load_json_yaml(root / "execution/evaluators/catalog.yaml")
    issues: list[Issue] = []
    evaluators = _validate_evaluator_catalog(
        evaluator_document, "execution/evaluators/catalog.yaml", issues
    )
    gate = load_json_yaml(root / gate_path)
    if not isinstance(gate, dict) or not isinstance(gate.get("criteria"), list):
        issues.append(
            Issue("invalid_gate", gate_path, "gate criteria must be an array")
        )
    else:
        for index, criterion in enumerate(gate["criteria"]):
            evaluator_id = (
                criterion.get("evaluator") if isinstance(criterion, dict) else None
            )
            evaluator = evaluators.get(evaluator_id)
            location = f"{gate_path}#criteria[{index}]"
            if evaluator is None:
                issues.append(Issue("unknown_evaluator", location, str(evaluator_id)))
            elif (
                evaluator.get("kind") == "MACHINE"
                and evaluator.get("status") != "implemented"
            ):
                issues.append(
                    Issue(
                        "missing_evaluator",
                        location,
                        f"{evaluator_id} is {evaluator.get('status')}",
                    )
                )
    if issues:
        raise ValidationError(issues)
