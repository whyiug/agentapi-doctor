"""Strict raw authorization bundles for the protected post-Genesis writer.

The provenance and state-chain modules intentionally return process-local,
identity-sealed objects.  Such an object cannot be serialized and trusted in a
later workflow process.  This module is the narrow import boundary: it accepts
one canonical JSON artifact containing the *raw* signed statements, verifies
every statement again against an already sealed current state and externally
pinned inputs, and only then returns fresh seals for ``post_event_writer``.

No digest, role, criterion, source commit, transition, or current-chain value
is trusted merely because it appears in the artifact.  Operation metadata is
an exact redundancy check against trusted arguments and replayed state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, NoReturn, Sequence
import weakref

from .chain_witness import VerifiedChainHeadWitness, verify_chain_head_witness
from .control_context import (
    VerifiedWorkUnitControlContext,
    criterion_documents,
    finalize_late_bound_dataset_context,
    require_verified_work_unit_control_context,
)
from .community_facts import (
    SUPPORTED_CRITERIA as COMMUNITY_FACT_CRITERIA,
    build_p00_community_fact_verifier,
)
from .delegation import (
    EffectiveReviewerRoster,
    authorize_criterion_signer,
    build_effective_reviewer_roster,
    make_provenance_signer_verifier,
)
from .digest import canonical_json_bytes, sha256_bytes
from .execution_artifact import (
    ExecutionArtifactError,
    verify_execution_artifact_bundle,
)
from .external_facts import (
    ExternalFactError,
    build_p00_external_fact_verifier,
)
from .oidc_provenance import OidcProvenanceError, build_oidc_provenance_verifier
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    ACTIVATION_APPROVAL_NAMESPACE,
    ACTIVATION_PROOF_NAMESPACE,
    EXTERNAL_CRITERION_NAMESPACE,
    FREEZE_NAMESPACE,
    HUMAN_CRITERION_NAMESPACE,
    LIFECYCLE_APPROVAL_NAMESPACE,
    LIFECYCLE_PROOF_NAMESPACE,
    MACHINE_CRITERION_NAMESPACE,
    PROOF_NAMESPACE,
    TRANSITION_APPROVAL_NAMESPACE,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedProtectedInputFreeze,
    VerifiedLifecycleTransition,
    VerifiedSignerResult,
    VerifiedWorkUnitTransition,
    authorize_activation_transition,
    authorize_convergence_transition,
    authorize_lifecycle_transition,
    verify_activation_approval,
    verify_activation_proof,
    verify_lifecycle_approval,
    verify_lifecycle_proof,
    verify_signed_criterion_result,
    verify_signed_protected_input_freeze,
    verify_transition_approval,
    verify_verified_transition_proof,
    verify_work_unit_state_context,
    _require_verified as _require_provenance_verified,
)
from .sshsig import SshSigVerificationError, verify_sshsig
from .state_chain_v2 import (
    VerifiedEvidenceAttachmentV2,
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    authorize_evidence_attachment_v2,
    require_verified_state_context_v2,
)


BUNDLE_SCHEMA = "urn:agentapi-doctor:serialized-authorization-bundle:v1alpha2"
BUNDLE_KIND = "SerializedProtectedAuthorizationBundle"
MAX_BUNDLE_BYTES = 80 * 1024 * 1024
MAX_SIGNED_DOCUMENTS = 128

OP_CONVERGENCE = "work-unit-convergence"
OP_READINESS = "work-unit-readiness"
OP_ACTIVATION = "work-unit-activation"
OP_ATTACHMENT = "evidence-attachment"
SUPPORTED_OPERATIONS = {
    OP_CONVERGENCE,
    OP_READINESS,
    OP_ACTIVATION,
    OP_ATTACHMENT,
}

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

VerifiedEventInput = (
    VerifiedWorkUnitTransition
    | VerifiedLifecycleTransition
    | VerifiedEvidenceAttachmentV2
)


@dataclass
class SerializedBundleError(ValueError):
    """Stable, secret-free import failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class VerifiedMachineExecutionProjection:
    """Raw-chain-safe projection derived only from a reverified execution bundle."""

    criterion_id: str
    verification_pair_id: str
    run_pair_digest: str
    execution_bundle_digest: str
    evaluator_dataset_freeze_digest: str
    dataset_catalog_path: str
    dataset_slot_digest: str
    dataset_selection_digest: str | None
    verifier_authority_digest: str


@dataclass(frozen=True)
class VerifiedSerializedAuthorizationBundle:
    """Fresh process-local seals reconstructed from one raw artifact."""

    bundle_digest: str
    bundle_id: str
    operation: str
    source_commit: str
    prior_state_digest: str
    prior_chain_head_digest: str
    freeze: VerifiedProtectedInputFreeze | None
    criterion_results: tuple[VerifiedCriterionResult, ...]
    machine_execution_results: tuple[VerifiedMachineExecutionProjection, ...]
    event_input: VerifiedEventInput
    chain_head_witness: VerifiedChainHeadWitness


_VERIFIED: dict[int, weakref.ReferenceType[Any]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise SerializedBundleError(code, path, message)


def _translate(error: Exception) -> NoReturn:
    code = getattr(error, "code", "authorization_verification_failed")
    path = getattr(error, "path", "authorizationBundle")
    message = getattr(error, "message", str(error))
    _fail(str(code), str(path), str(message))


def _mark_verified(
    value: VerifiedSerializedAuthorizationBundle,
) -> VerifiedSerializedAuthorizationBundle:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if _VERIFIED.get(identity) is reference:
            _VERIFIED.pop(identity, None)

    _VERIFIED[identity] = weakref.ref(value, discard)
    return value


def require_verified_serialized_bundle(
    value: Any, *, path: str = "authorizationBundle"
) -> VerifiedSerializedAuthorizationBundle:
    """Reject copied, reconstructed, or deserialized result dataclasses."""

    reference = _VERIFIED.get(id(value))
    if (
        not isinstance(value, VerifiedSerializedAuthorizationBundle)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact bundle result returned by this verifier",
        )
    if value.operation in {OP_CONVERGENCE, OP_ATTACHMENT}:
        if value.freeze is None:
            _fail("verified_bundle_projection_mismatch", path, "freeze is missing")
        try:
            _require_provenance_verified(
                value.freeze,
                VerifiedProtectedInputFreeze,
                f"{path}.freeze",
            )
            for index, result in enumerate(value.criterion_results):
                _require_provenance_verified(
                    result,
                    VerifiedCriterionResult,
                    f"{path}.criterionResults[{index}]",
                )
        except ProtectedVerificationError as exc:
            _translate(exc)
        result_digests = tuple(
            result.attestation_digest for result in value.criterion_results
        )
        machine_results = {
            result.criterion.criterion_id: result
            for result in value.criterion_results
            if result.criterion.kind == "MACHINE"
        }
        if tuple(
            projection.criterion_id
            for projection in value.machine_execution_results
        ) != tuple(sorted(machine_results)):
            _fail(
                "verified_bundle_projection_mismatch",
                f"{path}.machineExecutionResults",
                "fresh MACHINE execution projection set differs from results",
            )
        for projection in value.machine_execution_results:
            machine_result = machine_results[projection.criterion_id]
            if (
                not projection.verification_pair_id
                or projection.run_pair_digest != machine_result.run_pair_digest
                or projection.run_pair_digest != machine_result.evidence_digest
                or SHA256_RE.fullmatch(
                    projection.evaluator_dataset_freeze_digest
                )
                is None
                or not projection.dataset_catalog_path
                or SHA256_RE.fullmatch(projection.dataset_slot_digest) is None
                or (
                    projection.dataset_selection_digest is not None
                    and SHA256_RE.fullmatch(projection.dataset_selection_digest)
                    is None
                )
                or projection.verifier_authority_digest
                != machine_result.signer.authority_digest
            ):
                _fail(
                    "verified_bundle_projection_mismatch",
                    f"{path}.machineExecutionResults",
                    "execution projection differs from freshly verified result",
                )
        projected_freeze = getattr(value.event_input, "freeze_digest", None)
        if (
            any(
                result.freeze_digest != value.freeze.attestation_digest
                for result in value.criterion_results
            )
            or (
                projected_freeze is not None
                and projected_freeze != value.freeze.attestation_digest
            )
            or getattr(value.event_input, "criterion_result_digests", None)
            != result_digests
        ):
            _fail(
                "verified_bundle_projection_mismatch",
                path,
                "event input differs from freshly verified freeze/results",
            )
    elif (
        value.freeze is not None
        or value.criterion_results
        or value.machine_execution_results
    ):
        _fail(
            "verified_bundle_projection_mismatch",
            path,
            "lifecycle bundle unexpectedly carries criterion evidence",
        )
    return value


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail(
                "duplicate_bundle_key", "authorizationBundle", f"duplicate key: {key}"
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail("invalid_bundle_json", "authorizationBundle", f"non-finite number: {value}")


def _load_bundle(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BUNDLE_BYTES:
        _fail(
            "invalid_bundle_size",
            "authorizationBundle",
            f"bundle must be non-empty bytes no larger than {MAX_BUNDLE_BYTES}",
        )
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except SerializedBundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("invalid_bundle_json", "authorizationBundle", str(exc))
    if not isinstance(value, dict):
        _fail(
            "invalid_bundle_schema",
            "authorizationBundle",
            "top level must be an object",
        )
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        _fail("invalid_bundle_json", "authorizationBundle", str(exc))
    if raw != canonical:
        _fail(
            "noncanonical_bundle",
            "authorizationBundle",
            "bundle bytes must be exact canonical JSON without trailing data",
        )
    return value


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(
            "invalid_bundle_schema", path, "field set differs from the versioned schema"
        )
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_source_commit", path, "expected lowercase 40-hex Git SHA-1")
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("invalid_timestamp", path, "timezone-aware datetime required")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("invalid_timestamp", path, "timestamp must have second precision")
    return normalized


def _current_fields(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> tuple[
    VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    Mapping[str, Any],
    str,
    str,
    int,
    int,
    str,
]:
    try:
        sealed = require_verified_state_context_v2(current)
    except ProtectedVerificationError as exc:
        _translate(exc)
    if isinstance(sealed, VerifiedGenesisAnchorV2):
        return (
            sealed,
            sealed.state_core,
            sealed.state_digest,
            sealed.chain_head_digest,
            sealed.event_count,
            sealed.head_sequence,
            sealed.head_source_commit,
        )
    return (
        sealed,
        sealed.state_core,
        sealed.state_digest,
        sealed.head_digest,
        sealed.event_count,
        sealed.head_sequence,
        sealed.head_source_commit,
    )


def _policy_sshsig_verifier(
    *,
    policy_result: Mapping[str, Any],
    expected_namespace: str,
    required_role: str,
    required_capability: str,
    expected_source_commit: str,
    expected_control_plane_digest: str,
    verification_time: datetime,
) -> Callable[[bytes, Mapping[str, Any], str], VerifiedSignerResult]:
    policy_digest = _digest(policy_result.get("digest"), "policyResult.digest")
    document = policy_result.get("document")
    principals = policy_result.get("principals")
    revoked = policy_result.get("revokedFingerprints")
    if (
        not isinstance(document, dict)
        or document_digest(document) != policy_digest
        or document.get("controlPlaneDigest") != expected_control_plane_digest
        or not isinstance(principals, Mapping)
        or not isinstance(revoked, set)
    ):
        _fail(
            "invalid_policy_result",
            "policyResult",
            "validated policy projection is inconsistent",
        )

    def verify(
        payload: bytes, signature: Mapping[str, Any], namespace: str
    ) -> VerifiedSignerResult:
        descriptor = _exact(
            signature,
            {"scheme", "namespace", "principal", "value"},
            "signature",
        )
        if (
            descriptor["scheme"] != "openssh-sshsig-v1"
            or namespace != expected_namespace
            or descriptor["namespace"] != expected_namespace
        ):
            _fail("signature_namespace_mismatch", "signature", "SSHSIG domain differs")
        principal_name = descriptor["principal"]
        principal = principals.get(principal_name)
        if not isinstance(principal, Mapping):
            _fail(
                "signer_not_allowed", "signature.principal", "principal is not trusted"
            )
        roles = principal.get("roles")
        capabilities = principal.get("capabilities")
        if (required_role not in roles if isinstance(roles, list) else True) or (
            required_capability not in capabilities
            if isinstance(capabilities, list)
            else True
        ):
            _fail(
                "role_not_authorized",
                "signature.principal",
                "role/capability is not granted",
            )
        if principal.get("fingerprint") in revoked:
            _fail("revoked_signer", "signature.principal", "signer key is revoked")
        try:
            valid_from = datetime.strptime(
                principal["validFrom"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            valid_until = datetime.strptime(
                principal["validUntil"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            _fail(
                "invalid_policy_result",
                "policyResult.principals",
                "invalid validity window",
            )
        if not valid_from <= verification_time < valid_until:
            _fail(
                "signer_outside_validity",
                "signature.principal",
                "signer is outside validity",
            )
        try:
            verify_sshsig(
                payload,
                armored_signature=descriptor["value"],
                public_key=principal["publicKey"],
                expected_namespace=expected_namespace,
            )
        except (SshSigVerificationError, KeyError, TypeError) as exc:
            if isinstance(exc, SshSigVerificationError):
                _translate(exc)
            _fail(
                "invalid_policy_result",
                "policyResult.principals",
                "public key is invalid",
            )
        return VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=expected_namespace,
            principal=str(principal_name),
            role=required_role,
            organization=str(principal.get("organization")),
            statement_digest=sha256_bytes(payload),
            authority_digest=policy_digest,
            source_commit=expected_source_commit,
            control_plane_digest=expected_control_plane_digest,
        )

    return verify


def _operation_metadata(
    value: Any,
    *,
    expected_operation: str,
    expected_to_state: str,
    expected_subject: SubjectBinding,
    current_status: str,
    current_state_digest: str,
    current_head_digest: str,
    workflow_execution_commit: str,
    expected_contract_approval_digest: str,
    expected_impact_map_digest: str,
    expected_protected_inputs: Mapping[str, str],
    expected_criteria: Sequence[Mapping[str, Any]],
    expected_prerequisite_units: Sequence[str],
) -> dict[str, Any]:
    operation = _exact(
        value,
        {
            "operationId",
            "type",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "workflowExecutionCommit",
            "contractApprovalDigest",
            "impactMapDigest",
            "protectedInputsDigest",
            "criteriaDigest",
            "prerequisiteUnits",
        },
        "authorizationBundle.operation",
    )
    if (
        not isinstance(operation["operationId"], str)
        or ID_RE.fullmatch(operation["operationId"]) is None
    ):
        _fail(
            "invalid_operation_id",
            "authorizationBundle.operation.operationId",
            "invalid ID",
        )
    if operation["type"] != expected_operation:
        _fail(
            "operation_mismatch",
            "authorizationBundle.operation.type",
            "operation differs",
        )
    subject = {
        "phase": expected_subject.phase,
        "workUnit": expected_subject.work_unit,
        "sourceCommit": expected_subject.source_commit,
        "controlPlaneDigest": expected_subject.control_plane_digest,
        "contractDigest": expected_subject.contract_digest,
    }
    protected_digest = document_digest(
        {"protectedInputs": dict(sorted(expected_protected_inputs.items()))}
    )
    criteria_digest = document_digest({"criteria": list(expected_criteria)})
    exact = {
        "subject": subject,
        "fromState": current_status,
        "toState": expected_to_state,
        "priorStateDigest": current_state_digest,
        "priorChainHeadDigest": current_head_digest,
        "workflowExecutionCommit": workflow_execution_commit,
        "contractApprovalDigest": expected_contract_approval_digest,
        "impactMapDigest": expected_impact_map_digest,
        "protectedInputsDigest": protected_digest,
        "criteriaDigest": criteria_digest,
        "prerequisiteUnits": list(expected_prerequisite_units),
    }
    if any(operation.get(key) != expected for key, expected in exact.items()):
        _fail(
            "operation_binding_mismatch",
            "authorizationBundle.operation",
            "trusted binding differs",
        )
    return operation


def _raw_criterion_identity(value: Any, index: int) -> tuple[str, str, str]:
    path = f"authorizationBundle.criterionResults[{index}]"
    if not isinstance(value, dict) or not isinstance(value.get("body"), dict):
        _fail("invalid_bundle_schema", path, "signed criterion envelope required")
    body = value["body"]
    criterion = body.get("criterion")
    actor = body.get("actor")
    if not isinstance(criterion, dict) or not isinstance(actor, dict):
        _fail("invalid_bundle_schema", path, "criterion and actor are required")
    criterion_id = criterion.get("id")
    kind = criterion.get("kind")
    role = actor.get("role")
    if not all(isinstance(item, str) and item for item in (criterion_id, kind, role)):
        _fail("invalid_bundle_schema", path, "criterion identity is invalid")
    return criterion_id, kind, role


def _raw_evidence_map(
    value: Any,
    *,
    field: str,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_SIGNED_DOCUMENTS:
        _fail(
            "invalid_bundle_schema",
            f"authorizationBundle.{field}",
            "bounded evidence list required",
        )
    result: dict[str, Mapping[str, Any]] = {}
    ids: list[str] = []
    for index, raw in enumerate(value):
        path = f"authorizationBundle.{field}[{index}]"
        entry = _exact(raw, {"criterionId", "evidence"}, path)
        criterion_id = entry["criterionId"]
        if (
            not isinstance(criterion_id, str)
            or ID_RE.fullmatch(criterion_id) is None
            or not isinstance(entry["evidence"], Mapping)
        ):
            _fail("invalid_bundle_schema", path, "criterion ID and evidence object required")
        ids.append(criterion_id)
        result[criterion_id] = entry["evidence"]
    if ids != sorted(set(ids)) or len(result) != len(ids):
        _fail(
            "duplicate_or_unsorted_evidence",
            f"authorizationBundle.{field}",
            "criterion IDs must be sorted and unique",
        )
    return result


def _verify_criterion_results(
    raw_results: Sequence[Any],
    *,
    freeze: Any,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    policy_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
    repo_root: Path,
    workflow_execution_commit: str,
    prior_chain_head_digest: str,
    roster: EffectiveReviewerRoster,
    verification_time: datetime,
    machine_execution_artifacts: Mapping[str, Mapping[str, Any]],
    external_fact_evidence: Mapping[str, Mapping[str, Any]],
    dataset_catalog_bindings: Mapping[str, tuple[str, str]],
    dataset_selection_bindings: Mapping[str, str],
) -> tuple[
    list[VerifiedCriterionResult],
    list[VerifiedMachineExecutionProjection],
]:
    if len(raw_results) > MAX_SIGNED_DOCUMENTS:
        _fail(
            "too_many_signed_documents",
            "authorizationBundle.criterionResults",
            "too many results",
        )
    identities = [
        _raw_criterion_identity(value, index) for index, value in enumerate(raw_results)
    ]
    result_ids = [identity[0] for identity in identities]
    if result_ids != sorted(set(result_ids)):
        _fail(
            "duplicate_or_unsorted_criterion",
            "authorizationBundle.criterionResults",
            "criterion IDs must be sorted and unique",
        )
    machine_ids = {criterion_id for criterion_id, kind, _role in identities if kind == "MACHINE"}
    external_ids = {criterion_id for criterion_id, kind, _role in identities if kind == "EXTERNAL"}
    if set(machine_execution_artifacts) != machine_ids:
        _fail(
            "machine_execution_artifact_set_mismatch",
            "authorizationBundle.machineExecutionArtifacts",
            "every and only MACHINE result requires one raw execution artifact",
        )
    if set(external_fact_evidence) != external_ids:
        _fail(
            "external_fact_evidence_set_mismatch",
            "authorizationBundle.externalFactEvidence",
            "every and only EXTERNAL result requires one raw fact evidence object",
        )
    verified: list[VerifiedCriterionResult] = []
    machine_projections: list[VerifiedMachineExecutionProjection] = []
    for index, (statement, identity) in enumerate(zip(raw_results, identities)):
        criterion_id, kind, role = identity
        try:
            if kind == "MACHINE":
                execution = verify_execution_artifact_bundle(
                    canonical_json_bytes(machine_execution_artifacts[criterion_id]),
                    freeze=freeze,
                    expected_criterion_id=criterion_id,
                )
                body = statement.get("body")
                if (
                    not isinstance(body, Mapping)
                    or body.get("runPair") != dict(execution.run_pair)
                    or body.get("runPairDigest") != execution.run_pair_digest
                    or body.get("evidenceDigest") != execution.run_pair_digest
                ):
                    _fail(
                        "machine_execution_binding_mismatch",
                        f"authorizationBundle.criterionResults[{index}]",
                        "signed MACHINE result differs from raw execution recomputation",
                    )
                verifier = build_oidc_provenance_verifier(
                    current=current,
                    policy_result=policy_result,
                    approved_jwks_snapshot=approved_jwks_snapshot,
                    repo_root=repo_root,
                    current_source_commit=freeze.subject.source_commit,
                    current_workflow_execution_commit=workflow_execution_commit,
                    expected_namespace=MACHINE_CRITERION_NAMESPACE,
                )
                result = verify_signed_criterion_result(
                    statement,
                    freeze=freeze,
                    expected_authority_digest=verifier.authority_digest,
                    signer_verifier=verifier,
                )
            elif kind in {"HUMAN", "EXTERNAL"}:
                namespace = (
                    HUMAN_CRITERION_NAMESPACE
                    if kind == "HUMAN"
                    else EXTERNAL_CRITERION_NAMESPACE
                )
                capability = (
                    "attest-human-result"
                    if kind == "HUMAN"
                    else "attest-external-result"
                )
                authorization = authorize_criterion_signer(
                    roster,
                    principal=statement["body"]["actor"]["principal"],
                    criterion_id=criterion_id,
                    required_role=role,
                    required_capability=capability,
                    at=verification_time,
                )
                verifier = make_provenance_signer_verifier(
                    roster,
                    criterion_id=criterion_id,
                    required_role=role,
                    required_capability=capability,
                    expected_namespace=namespace,
                    expected_source_commit=freeze.subject.source_commit,
                    expected_control_plane_digest=freeze.subject.control_plane_digest,
                    verification_time=verification_time,
                )
                fact_verifier = (
                    (
                        build_p00_community_fact_verifier(
                            criterion_id,
                            canonical_json_bytes(
                                external_fact_evidence[criterion_id]
                            ),
                            reviewer_roster=roster,
                            policy_result=policy_result,
                            expected_policy_digest=_digest(
                                policy_result.get("digest"),
                                "policyResult.digest",
                            ),
                            expected_prior_chain_head_digest=prior_chain_head_digest,
                            verification_time=verification_time,
                        )
                        if criterion_id in COMMUNITY_FACT_CRITERIA
                        else build_p00_external_fact_verifier(
                            criterion_id,
                            canonical_json_bytes(
                                external_fact_evidence[criterion_id]
                            ),
                        )
                    )
                    if kind == "EXTERNAL"
                    else None
                )
                result = verify_signed_criterion_result(
                    statement,
                    freeze=freeze,
                    expected_authority_digest=roster.authority_digest,
                    signer_verifier=verifier,
                    fact_verifier=fact_verifier,
                    criterion_authorization=authorization,
                )
            else:
                _fail(
                    "unsupported_criterion_kind",
                    f"authorizationBundle.criterionResults[{index}]",
                    "P00 serialized bundles support MACHINE/HUMAN/EXTERNAL only",
                )
        except (
            OidcProvenanceError,
            ProtectedVerificationError,
            SshSigVerificationError,
            ExecutionArtifactError,
            ExternalFactError,
        ) as exc:
            _translate(exc)
        verified.append(result)
        if kind == "MACHINE":
            catalog_binding = dataset_catalog_bindings.get(criterion_id)
            if catalog_binding is None:
                _fail(
                    "dataset_binding_incomplete",
                    f"authorizationBundle.criterionResults[{index}]",
                    "MACHINE criterion lacks an approved dataset catalog slot",
                )
            machine_projections.append(
                VerifiedMachineExecutionProjection(
                    criterion_id=criterion_id,
                    verification_pair_id=execution.run_pair["verificationPairId"],
                    run_pair_digest=execution.run_pair_digest,
                    execution_bundle_digest=execution.bundle_digest,
                    evaluator_dataset_freeze_digest=(
                        execution.evaluator_dataset_freeze_digest
                    ),
                    dataset_catalog_path=catalog_binding[0],
                    dataset_slot_digest=catalog_binding[1],
                    dataset_selection_digest=dataset_selection_bindings.get(
                        criterion_id
                    ),
                    verifier_authority_digest=result.signer.authority_digest,
                )
            )
    return verified, machine_projections


def verify_serialized_authorization_bundle(
    raw_artifact: bytes,
    *,
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
    policy_result: Mapping[str, Any],
    approved_jwks_snapshot: Mapping[str, Any],
    repo_root: Path,
    current_workflow_execution_commit: str,
    expected_operation: str,
    expected_to_state: str,
    control_context: VerifiedWorkUnitControlContext,
    verification_time: datetime,
) -> VerifiedSerializedAuthorizationBundle:
    """Re-verify one canonical raw bundle into fresh post-writer seals.

    Only P00 work-unit operations are supported by this revision.  Phase
    aggregate bundles fail explicitly until their multisignature importer is
    separately implemented and approved.
    """

    if expected_operation not in SUPPORTED_OPERATIONS:
        _fail(
            "unsupported_operation", "expectedOperation", "operation is not implemented"
        )
    try:
        sealed_context = require_verified_work_unit_control_context(control_context)
    except Exception as exc:
        if hasattr(exc, "code"):
            _translate(exc)
        raise
    expected_subject = sealed_context.subject
    expected_contract_approval_digest = sealed_context.contract_approval_digest
    expected_impact_map_digest = sealed_context.impact_map_digest
    expected_protected_inputs = dict(sealed_context.protected_inputs)
    expected_criteria = criterion_documents(sealed_context.criteria)
    expected_prerequisite_units = sealed_context.prerequisite_units
    if expected_subject.phase != "P00":
        _fail(
            "unsupported_phase", "expectedSubject.phase", "v1alpha1 supports only P00"
        )
    workflow_commit = _commit(
        current_workflow_execution_commit, "currentWorkflowExecutionCommit"
    )
    if expected_subject.source_commit != workflow_commit:
        _fail(
            "source_workflow_commit_mismatch",
            "expectedSubject.sourceCommit",
            "protected operation source must equal current workflow commit",
        )
    for value, path in (
        (expected_subject.control_plane_digest, "expectedSubject.controlPlaneDigest"),
        (expected_subject.contract_digest, "expectedSubject.contractDigest"),
        (expected_contract_approval_digest, "expectedContractApprovalDigest"),
        (expected_impact_map_digest, "expectedImpactMapDigest"),
    ):
        _digest(value, path)
    now = _utc(verification_time, "verificationTime")
    (
        sealed_current,
        state_core,
        state_digest,
        head_digest,
        event_count,
        head_sequence,
        head_source_commit,
    ) = _current_fields(current)
    if state_core.get("controlPlaneDigest") != expected_subject.control_plane_digest:
        _fail("control_plane_digest_mismatch", "current", "current state differs")
    try:
        state_context = verify_work_unit_state_context(
            dict(state_core),
            expected_state_digest=state_digest,
            expected_chain_head_digest=head_digest,
            expected_control_plane_digest=expected_subject.control_plane_digest,
            phase=expected_subject.phase,
            work_unit=expected_subject.work_unit,
            expected_status=(
                state_core["phases"][expected_subject.phase]["workUnits"][
                    expected_subject.work_unit
                ]["status"]
            ),
            expected_contract_digest=expected_subject.contract_digest,
            prerequisite_units=tuple(expected_prerequisite_units),
        )
    except (ProtectedVerificationError, KeyError, TypeError) as exc:
        if isinstance(exc, ProtectedVerificationError):
            _translate(exc)
        _fail("invalid_current_state", "current", "work-unit state is unavailable")
    document = _load_bundle(raw_artifact)
    envelope = _exact(
        document,
        {
            "schemaVersion",
            "kind",
            "bundleId",
            "operation",
            "chainHeadWitness",
            "delegations",
            "revocations",
            "protectedInputFreeze",
            "criterionResults",
            "lateBoundDatasetSelections",
            "machineExecutionArtifacts",
            "externalFactEvidence",
            "proof",
            "approval",
            "bundleDigest",
        },
        "authorizationBundle",
    )
    if envelope["schemaVersion"] != BUNDLE_SCHEMA or envelope["kind"] != BUNDLE_KIND:
        _fail(
            "invalid_bundle_schema",
            "authorizationBundle",
            "unsupported bundle revision",
        )
    if (
        not isinstance(envelope["bundleId"], str)
        or ID_RE.fullmatch(envelope["bundleId"]) is None
    ):
        _fail("invalid_bundle_id", "authorizationBundle.bundleId", "invalid bundle ID")
    bundle_digest = document_digest(envelope, omit_field="bundleDigest")
    if envelope["bundleDigest"] != bundle_digest:
        _fail(
            "bundle_digest_mismatch",
            "authorizationBundle.bundleDigest",
            "digest mismatch",
        )
    delegations = envelope["delegations"]
    revocations = envelope["revocations"]
    raw_results = envelope["criterionResults"]
    raw_dataset_selections = envelope["lateBoundDatasetSelections"]
    machine_execution_artifacts = _raw_evidence_map(
        envelope["machineExecutionArtifacts"], field="machineExecutionArtifacts"
    )
    external_fact_evidence = _raw_evidence_map(
        envelope["externalFactEvidence"], field="externalFactEvidence"
    )
    if any(
        not isinstance(values, list) or len(values) > MAX_SIGNED_DOCUMENTS
        for values in (
            delegations,
            revocations,
            raw_results,
            raw_dataset_selections,
        )
    ):
        _fail(
            "invalid_bundle_schema",
            "authorizationBundle",
            "signed document lists are bounded",
        )
    policy_digest = _digest(policy_result.get("digest"), "policyResult.digest")
    try:
        witness = verify_chain_head_witness(
            envelope["chainHeadWitness"],
            policy_result=policy_result,
            expected_prior_chain_head_digest=head_digest,
            expected_prior_state_digest=state_digest,
            expected_prior_event_count=event_count,
            expected_prior_head_sequence=head_sequence,
            expected_prior_source_commit=head_source_commit,
            expected_control_plane_digest=expected_subject.control_plane_digest,
            expected_trust_policy_digest=policy_digest,
            now=now,
        )
        roster = build_effective_reviewer_roster(
            policy_result=policy_result,
            delegations=delegations,
            revocations=revocations,
            expected_policy_digest=policy_digest,
            expected_control_plane_digest=expected_subject.control_plane_digest,
            expected_source_commit=workflow_commit,
            expected_prior_chain_head_digest=head_digest,
            now=now,
        )
    except ProtectedVerificationError as exc:
        _translate(exc)
    try:
        if expected_operation in {OP_CONVERGENCE, OP_ATTACHMENT}:
            sealed_context = finalize_late_bound_dataset_context(
                base_context=sealed_context,
                raw_selections=raw_dataset_selections,
                roster=roster,
                verification_time=now,
            )
        elif raw_dataset_selections:
            _fail(
                "unexpected_dataset_selection",
                "authorizationBundle.lateBoundDatasetSelections",
                "readiness/activation do not consume dataset selections",
            )
    except ProtectedVerificationError as exc:
        _translate(exc)
    except Exception as exc:
        if hasattr(exc, "code"):
            _translate(exc)
        raise
    expected_subject = sealed_context.subject
    expected_contract_approval_digest = sealed_context.contract_approval_digest
    expected_impact_map_digest = sealed_context.impact_map_digest
    expected_protected_inputs = dict(sealed_context.protected_inputs)
    expected_criteria = criterion_documents(sealed_context.criteria)
    expected_prerequisite_units = sealed_context.prerequisite_units
    operation = _operation_metadata(
        envelope["operation"],
        expected_operation=expected_operation,
        expected_to_state=expected_to_state,
        expected_subject=expected_subject,
        current_status=state_context.status,
        current_state_digest=state_digest,
        current_head_digest=head_digest,
        workflow_execution_commit=workflow_commit,
        expected_contract_approval_digest=expected_contract_approval_digest,
        expected_impact_map_digest=expected_impact_map_digest,
        expected_protected_inputs=expected_protected_inputs,
        expected_criteria=expected_criteria,
        expected_prerequisite_units=expected_prerequisite_units,
    )
    if expected_operation == OP_READINESS and expected_to_state != "READY":
        _fail("operation_mismatch", "expectedToState", "readiness must target READY")
    if expected_operation == OP_ACTIVATION and expected_to_state != "ACTIVE":
        _fail("operation_mismatch", "expectedToState", "activation must target ACTIVE")
    if expected_operation == OP_ATTACHMENT and expected_to_state != state_context.status:
        _fail(
            "operation_mismatch",
            "expectedToState",
            "evidence attachment cannot change authoritative state",
        )
    freeze_signer = _policy_sshsig_verifier(
        policy_result=policy_result,
        expected_namespace=FREEZE_NAMESPACE,
        required_role="independent-reviewer",
        required_capability="freeze-protected-input",
        expected_source_commit=workflow_commit,
        expected_control_plane_digest=expected_subject.control_plane_digest,
        verification_time=now,
    )
    if expected_operation == OP_READINESS:
        approval_namespace = LIFECYCLE_APPROVAL_NAMESPACE
    elif expected_operation == OP_ACTIVATION:
        approval_namespace = ACTIVATION_APPROVAL_NAMESPACE
    else:
        approval_namespace = TRANSITION_APPROVAL_NAMESPACE
    approval_signer = _policy_sshsig_verifier(
        policy_result=policy_result,
        expected_namespace=approval_namespace,
        required_role="independent-reviewer",
        required_capability="approve-transition",
        expected_source_commit=workflow_commit,
        expected_control_plane_digest=expected_subject.control_plane_digest,
        verification_time=now,
    )
    verified_freeze: VerifiedProtectedInputFreeze | None = None
    verified_results: list[VerifiedCriterionResult] = []
    verified_machine_execution_results: list[
        VerifiedMachineExecutionProjection
    ] = []
    try:
        if expected_operation in {OP_CONVERGENCE, OP_ATTACHMENT}:
            if envelope["protectedInputFreeze"] is None:
                _fail(
                    "missing_protected_input_freeze",
                    "authorizationBundle",
                    "freeze is required",
                )
            freeze = verify_signed_protected_input_freeze(
                envelope["protectedInputFreeze"],
                expected_subject=expected_subject,
                expected_contract_approval_digest=expected_contract_approval_digest,
                expected_protected_inputs=expected_protected_inputs,
                expected_criteria=expected_criteria,
                expected_authority_digest=policy_digest,
                signer_verifier=freeze_signer,
            )
            results, machine_results = _verify_criterion_results(
                raw_results,
                freeze=freeze,
                current=sealed_current,
                policy_result=policy_result,
                approved_jwks_snapshot=approved_jwks_snapshot,
                repo_root=repo_root,
                workflow_execution_commit=workflow_commit,
                prior_chain_head_digest=head_digest,
                roster=roster,
                verification_time=now,
                machine_execution_artifacts=machine_execution_artifacts,
                external_fact_evidence=external_fact_evidence,
                dataset_catalog_bindings={
                    criterion_id: (catalog_path, slot_digest)
                    for criterion_id, catalog_path, slot_digest in (
                        sealed_context.dataset_catalog_bindings
                    )
                },
                dataset_selection_bindings=dict(
                    sealed_context.dataset_selection_bindings
                ),
            )
            verified_freeze = freeze
            verified_results = results
            verified_machine_execution_results = machine_results
            if expected_operation == OP_ATTACHMENT:
                if envelope["proof"] is not None or envelope["approval"] is not None:
                    _fail(
                        "unexpected_attachment_authorization",
                        "authorizationBundle",
                        "v1alpha1 attachments carry freeze/results only",
                    )
                event_input = authorize_evidence_attachment_v2(
                    freeze=freeze,
                    criterion_results=results,
                )
            else:
                if envelope["proof"] is None or envelope["approval"] is None:
                    _fail(
                        "missing_transition_authorization",
                        "authorizationBundle",
                        "proof/approval required",
                    )
                proof_verifier = build_oidc_provenance_verifier(
                    current=sealed_current,
                    policy_result=policy_result,
                    approved_jwks_snapshot=approved_jwks_snapshot,
                    repo_root=repo_root,
                    current_source_commit=workflow_commit,
                    current_workflow_execution_commit=workflow_commit,
                    expected_namespace=PROOF_NAMESPACE,
                )
                proof = verify_verified_transition_proof(
                    envelope["proof"],
                    freeze=freeze,
                    criterion_results=results,
                    state_context=state_context,
                    expected_to_state=expected_to_state,
                    expected_authority_digest=proof_verifier.authority_digest,
                    signer_verifier=proof_verifier,
                )
                approval = verify_transition_approval(
                    envelope["approval"],
                    proof=proof,
                    expected_authority_digest=policy_digest,
                    signer_verifier=approval_signer,
                    now=now,
                )
                event_input = authorize_convergence_transition(
                    state_context=state_context,
                    freeze=freeze,
                    criterion_results=results,
                    proof=proof,
                    approval=approval,
                )
        elif expected_operation == OP_READINESS:
            if (
                envelope["protectedInputFreeze"] is not None
                or raw_results
                or machine_execution_artifacts
                or external_fact_evidence
                or envelope["proof"] is None
                or envelope["approval"] is None
            ):
                _fail(
                    "invalid_readiness_bundle",
                    "authorizationBundle",
                    "readiness requires only proof/approval",
                )
            proof_verifier = build_oidc_provenance_verifier(
                current=sealed_current,
                policy_result=policy_result,
                approved_jwks_snapshot=approved_jwks_snapshot,
                repo_root=repo_root,
                current_source_commit=workflow_commit,
                current_workflow_execution_commit=workflow_commit,
                expected_namespace=LIFECYCLE_PROOF_NAMESPACE,
            )
            proof = verify_lifecycle_proof(
                envelope["proof"],
                state_context=state_context,
                expected_subject=expected_subject,
                expected_to_state=expected_to_state,
                expected_contract_approval_digest=expected_contract_approval_digest,
                expected_impact_map_digest=expected_impact_map_digest,
                expected_authority_digest=proof_verifier.authority_digest,
                signer_verifier=proof_verifier,
            )
            approval = verify_lifecycle_approval(
                envelope["approval"],
                proof=proof,
                expected_authority_digest=policy_digest,
                signer_verifier=approval_signer,
                now=now,
            )
            event_input = authorize_lifecycle_transition(
                state_context=state_context,
                proof=proof,
                approval=approval,
            )
        else:
            if (
                envelope["protectedInputFreeze"] is not None
                or raw_results
                or machine_execution_artifacts
                or external_fact_evidence
                or envelope["proof"] is None
                or envelope["approval"] is None
            ):
                _fail(
                    "invalid_activation_bundle",
                    "authorizationBundle",
                    "activation requires only proof/approval",
                )
            proof_verifier = build_oidc_provenance_verifier(
                current=sealed_current,
                policy_result=policy_result,
                approved_jwks_snapshot=approved_jwks_snapshot,
                repo_root=repo_root,
                current_source_commit=workflow_commit,
                current_workflow_execution_commit=workflow_commit,
                expected_namespace=ACTIVATION_PROOF_NAMESPACE,
            )
            proof = verify_activation_proof(
                envelope["proof"],
                state_context=state_context,
                expected_subject=expected_subject,
                expected_contract_approval_digest=expected_contract_approval_digest,
                expected_impact_map_digest=expected_impact_map_digest,
                expected_authority_digest=proof_verifier.authority_digest,
                signer_verifier=proof_verifier,
            )
            approval = verify_activation_approval(
                envelope["approval"],
                proof=proof,
                expected_authority_digest=policy_digest,
                signer_verifier=approval_signer,
                now=now,
            )
            event_input = authorize_activation_transition(
                state_context=state_context,
                proof=proof,
                approval=approval,
            )
    except (
        OidcProvenanceError,
        ProtectedVerificationError,
        SshSigVerificationError,
    ) as exc:
        _translate(exc)
    result = VerifiedSerializedAuthorizationBundle(
        bundle_digest=bundle_digest,
        bundle_id=envelope["bundleId"],
        operation=operation["type"],
        source_commit=workflow_commit,
        prior_state_digest=state_digest,
        prior_chain_head_digest=head_digest,
        freeze=verified_freeze,
        criterion_results=tuple(verified_results),
        machine_execution_results=tuple(verified_machine_execution_results),
        event_input=event_input,
        chain_head_witness=witness,
    )
    return _mark_verified(result)


__all__ = [
    "BUNDLE_KIND",
    "BUNDLE_SCHEMA",
    "MAX_BUNDLE_BYTES",
    "OP_ACTIVATION",
    "OP_ATTACHMENT",
    "OP_CONVERGENCE",
    "OP_READINESS",
    "SerializedBundleError",
    "VerifiedSerializedAuthorizationBundle",
    "VerifiedMachineExecutionProjection",
    "require_verified_serialized_bundle",
    "verify_serialized_authorization_bundle",
]
