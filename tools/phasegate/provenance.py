"""Strict provenance verification for protected convergence transitions.

The module validates immutable, digest-bound statements.  Cryptographic signer
verification is deliberately injected as a frozen :class:`VerifiedSignerResult`
or callback so a protected workflow can use GitHub OIDC without pretending it
owns an SSH key.  Human review may use the existing pinned SSH trust policy.

EXTERNAL and TIME statements are intentionally *not* treated as proof of their
claimed fact.  A valid generic signature only establishes who made the claim;
an independent fact verifier must additionally validate it before a transition
proof can consume it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence
import re
import weakref

from .digest import canonical_json_bytes, sha256_bytes
from .protected import (
    ALLOWED_TRANSITIONS,
    _exact_keys,
    _fail,
    _now_utc,
    _parse_utc,
    _require_commit,
    _require_nonempty,
    _require_sha256,
    _validate_state_invariants,
    document_digest,
)
from .sshsig import verify_sshsig


FREEZE_SCHEMA = "urn:agentapi-doctor:protected-input-freeze:v1alpha1"
FREEZE_KIND = "SignedProtectedInputFreeze"
CRITERION_SCHEMA = "urn:agentapi-doctor:criterion-result:v1alpha1"
CRITERION_KIND = "SignedCriterionResult"
PROOF_SCHEMA = "urn:agentapi-doctor:transition-proof:v1alpha1"
PROOF_KIND = "VerifiedTransitionProof"
TRANSITION_APPROVAL_SCHEMA = "urn:agentapi-doctor:transition-approval:v1alpha1"
TRANSITION_APPROVAL_KIND = "TransitionApproval"
ACTIVATION_PROOF_SCHEMA = "urn:agentapi-doctor:activation-proof:v1alpha1"
ACTIVATION_PROOF_KIND = "ProtectedActivationProof"
ACTIVATION_APPROVAL_SCHEMA = "urn:agentapi-doctor:activation-approval:v1alpha1"
ACTIVATION_APPROVAL_KIND = "ActivationApproval"
LIFECYCLE_PROOF_SCHEMA = "urn:agentapi-doctor:lifecycle-proof:v1alpha1"
LIFECYCLE_PROOF_KIND = "ProtectedLifecycleProof"
LIFECYCLE_APPROVAL_SCHEMA = "urn:agentapi-doctor:lifecycle-approval:v1alpha1"
LIFECYCLE_APPROVAL_KIND = "LifecycleApproval"

PHASE_FREEZE_SCHEMA = "urn:agentapi-doctor:phase-protected-input-freeze:v1alpha1"
PHASE_FREEZE_KIND = "SignedPhaseProtectedInputFreeze"
PHASE_CRITERION_SCHEMA = "urn:agentapi-doctor:phase-criterion-result:v1alpha1"
PHASE_CRITERION_KIND = "SignedPhaseCriterionResult"
PHASE_PROOF_SCHEMA = "urn:agentapi-doctor:phase-transition-proof:v1alpha1"
PHASE_PROOF_KIND = "VerifiedPhaseTransitionProof"
PHASE_APPROVAL_SCHEMA = "urn:agentapi-doctor:phase-transition-approval:v1alpha1"
PHASE_APPROVAL_KIND = "PhaseTransitionApproval"
PHASE_GO_NOGO_SCHEMA = "urn:agentapi-doctor:phase-go-no-go-authorization:v1alpha1"
PHASE_GO_NOGO_KIND = "PhaseGoNoGoAuthorizationSignature"

FREEZE_NAMESPACE = "agentapi-doctor/protected-input-freeze/v1"
MACHINE_CRITERION_NAMESPACE = "agentapi-doctor/criterion-result/machine/v1"
EXTERNAL_CRITERION_NAMESPACE = "agentapi-doctor/criterion-result/external/v1"
TIME_CRITERION_NAMESPACE = "agentapi-doctor/criterion-result/time/v1"
HUMAN_CRITERION_NAMESPACE = "agentapi-doctor/criterion-result/human/v1"
CRITERION_NAMESPACES = {
    "MACHINE": MACHINE_CRITERION_NAMESPACE,
    "EXTERNAL": EXTERNAL_CRITERION_NAMESPACE,
    "TIME": TIME_CRITERION_NAMESPACE,
    "HUMAN": HUMAN_CRITERION_NAMESPACE,
}
PROOF_NAMESPACE = "agentapi-doctor/transition-proof/v1"
TRANSITION_APPROVAL_NAMESPACE = "agentapi-doctor/transition-approval/v1"
ACTIVATION_PROOF_NAMESPACE = "agentapi-doctor/activation-proof/v1"
ACTIVATION_APPROVAL_NAMESPACE = "agentapi-doctor/activation-approval/v1"
LIFECYCLE_PROOF_NAMESPACE = "agentapi-doctor/lifecycle-proof/v1"
LIFECYCLE_APPROVAL_NAMESPACE = "agentapi-doctor/lifecycle-approval/v1"
PHASE_FREEZE_NAMESPACE = "agentapi-doctor/phase-protected-input-freeze/v1"
PHASE_CRITERION_NAMESPACES = {
    "MACHINE": "agentapi-doctor/phase-criterion-result/machine/v1",
    "EXTERNAL": "agentapi-doctor/phase-criterion-result/external/v1",
    "TIME": "agentapi-doctor/phase-criterion-result/time/v1",
    "HUMAN": "agentapi-doctor/phase-criterion-result/human/v1",
}
PHASE_PROOF_NAMESPACE = "agentapi-doctor/phase-transition-proof/v1"
PHASE_APPROVAL_NAMESPACE = "agentapi-doctor/phase-transition-approval/v1"
PHASE_GO_NOGO_NAMESPACE = "agentapi-doctor/phase-go-no-go-authorization/v1"

KINDS = ("MACHINE", "EXTERNAL", "TIME", "HUMAN")
EVALUATOR_STATUS_BY_KIND = {
    "MACHINE": "implemented",
    "HUMAN": "human-only",
    "EXTERNAL": "external-only",
    "TIME": "time-only",
}
SIGNER_SCHEMES = {
    "openssh-sshsig-v1",
    "github-actions-oidc-jwt-rs256-v1",
}
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:+/=,-]{0,255}$")
PHASE_RE = re.compile(r"^P[0-9]{2}$")
UNIT_RE = re.compile(r"^(P[0-9]{2})\.W[0-9]{2}$")

PROTECTED_INPUT_FIELDS = {
    "planDigest",
    "supportLockDigest",
    "toolchainDigest",
    "dependencySetDigest",
    "gateRunnerDigest",
    "evaluatorSetDigest",
    "metricDefinitionsDigest",
    "protectedAcceptanceDigest",
}
CRITERION_FIELDS = {
    "id",
    "kind",
    "evaluator",
    "evaluatorDigest",
    "evaluatorStatus",
    "evidenceSchema",
    "evidenceSchemaDigest",
    "datasetDigest",
    "thresholdDigest",
}


@dataclass(frozen=True)
class SubjectBinding:
    phase: str
    work_unit: str
    source_commit: str
    control_plane_digest: str
    contract_digest: str


@dataclass(frozen=True)
class PhaseSubject:
    """Aggregate subject.  Deliberately has no synthetic ``work_unit`` field."""

    phase: str
    source_commit: str
    control_plane_digest: str
    aggregate_contract_digest: str


@dataclass(frozen=True)
class CriterionBinding:
    criterion_id: str
    kind: str
    evaluator: str
    evaluator_digest: str
    evidence_schema: str
    evidence_schema_digest: str
    dataset_digest: str
    threshold_digest: str
    evaluator_status: str = "implemented"


@dataclass(frozen=True)
class VerifiedSignerResult:
    """Read-only result produced by a cryptographic identity verifier."""

    scheme: str
    namespace: str
    principal: str
    role: str
    organization: str
    statement_digest: str
    authority_digest: str
    source_commit: str
    control_plane_digest: str


@dataclass(frozen=True)
class VerifiedCriterionAuthorization:
    """Identity-sealed one-signer authorization for one exact criterion."""

    authorization_digest: str
    criterion_id: str
    principal: str
    organization: str
    role: str
    capability: str
    authority_digest: str
    delegation_digest: str | None


@dataclass(frozen=True)
class VerifiedProtectedInputFreeze:
    attestation_digest: str
    statement_digest: str
    freeze_id: str
    subject: SubjectBinding
    contract_approval_digest: str
    protected_inputs: tuple[tuple[str, str], ...]
    criteria: tuple[CriterionBinding, ...]
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedCriterionResult:
    attestation_digest: str
    statement_digest: str
    result_id: str
    freeze_digest: str
    subject: SubjectBinding
    criterion: CriterionBinding
    outcome: str
    evidence_digest: str
    run_pair_digest: str | None
    signature_verified: bool
    fact_status: str
    criterion_satisfied: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedTransitionProofResult:
    attestation_digest: str
    statement_digest: str
    proof_id: str
    freeze_digest: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    criterion_results: tuple[tuple[str, str, str, str], ...]
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedTransitionApprovalResult:
    attestation_digest: str
    statement_digest: str
    approval_id: str
    proof_digest: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    decision: str
    authorized: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class PrerequisiteStateBinding:
    phase: str
    work_unit: str
    status: str
    state_digest: str
    contract_digest: str
    source_commit: str
    approval_digest: str


@dataclass(frozen=True)
class VerifiedWorkUnitStateContext:
    state_digest: str
    chain_head_digest: str
    control_plane_digest: str
    phase: str
    work_unit: str
    status: str
    contract_digest: str
    recorded_source_commit: str | None
    prerequisites: tuple[PrerequisiteStateBinding, ...]
    phase_unit_statuses: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class VerifiedLifecycleProofResult:
    attestation_digest: str
    statement_digest: str
    proof_id: str
    transition_type: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    contract_approval_digest: str
    impact_map_digest: str
    prerequisites: tuple[PrerequisiteStateBinding, ...]
    reason_code: str
    reason: str
    blocker_resolution_digest: str | None
    invalidation_kind: str | None
    invalidation_digest: str | None
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedLifecycleApprovalResult:
    attestation_digest: str
    statement_digest: str
    approval_id: str
    proof_digest: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    decision: str
    authorized: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class PhaseUnitStateBinding:
    work_unit: str
    status: str
    contract_digest: str
    source_commit: str | None
    approval_digest: str | None


@dataclass(frozen=True)
class VerifiedPhaseStateContext:
    state_digest: str
    chain_head_digest: str
    control_plane_digest: str
    phase: str
    status: str
    aggregate_contract_digest: str
    base_commit: str
    units: tuple[PhaseUnitStateBinding, ...]


@dataclass(frozen=True)
class VerifiedPhaseProtectedInputFreeze:
    attestation_digest: str
    statement_digest: str
    freeze_id: str
    subject: PhaseSubject
    aggregate_contract_approval_digest: str
    unit_contract_digests: tuple[tuple[str, str], ...]
    protected_inputs: tuple[tuple[str, str], ...]
    criteria: tuple[CriterionBinding, ...]
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedPhaseCriterionResult:
    attestation_digest: str
    statement_digest: str
    result_id: str
    freeze_digest: str
    subject: PhaseSubject
    criterion: CriterionBinding
    outcome: str
    evidence_digest: str
    run_pair_digest: str | None
    signature_verified: bool
    fact_status: str
    criterion_satisfied: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedPhaseTransitionProofResult:
    attestation_digest: str
    statement_digest: str
    proof_id: str
    freeze_digest: str
    subject: PhaseSubject
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    unit_states: tuple[PhaseUnitStateBinding, ...]
    criterion_results: tuple[tuple[str, str, str, str], ...]
    deferred_go_nogo_criterion_id: str | None
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedPhaseTransitionApprovalResult:
    attestation_digest: str
    statement_digest: str
    approval_id: str
    proof_digest: str
    subject: PhaseSubject
    from_state: str
    to_state: str
    decision: str
    authorized: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedPhaseGoNoGoAuthorization:
    authorization_digest: str
    proof_digest: str
    subject: PhaseSubject
    criterion_id: str
    decision: str
    signature_digests: tuple[str, ...]
    signers: tuple[VerifiedSignerResult, ...]


@dataclass(frozen=True)
class VerifiedPhaseTransition:
    transition_type: str
    subject: PhaseSubject
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    freeze_digest: str
    proof_digest: str
    approval_digest: str
    go_nogo_authorization_digest: str | None
    evidence_digest: str
    criterion_result_digests: tuple[str, ...]
    unit_states: tuple[PhaseUnitStateBinding, ...]


@dataclass(frozen=True)
class VerifiedActivationProofResult:
    attestation_digest: str
    statement_digest: str
    proof_id: str
    subject: SubjectBinding
    prior_state_digest: str
    prior_chain_head_digest: str
    contract_approval_digest: str
    impact_map_digest: str
    prerequisites: tuple[PrerequisiteStateBinding, ...]
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedActivationApprovalResult:
    attestation_digest: str
    statement_digest: str
    approval_id: str
    proof_digest: str
    subject: SubjectBinding
    decision: str
    authorized: bool
    signer: VerifiedSignerResult


@dataclass(frozen=True)
class VerifiedWorkUnitTransition:
    transition_type: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    proof_digest: str
    approval_digest: str
    evidence_digest: str
    criterion_result_digests: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedLifecycleTransition:
    transition_type: str
    subject: SubjectBinding
    from_state: str
    to_state: str
    prior_state_digest: str
    prior_chain_head_digest: str
    contract_approval_digest: str
    impact_map_digest: str
    prerequisites: tuple[PrerequisiteStateBinding, ...]
    reason_code: str
    reason: str
    blocker_resolution_digest: str | None
    invalidation_kind: str | None
    invalidation_digest: str | None
    proof_digest: str
    approval_digest: str


_VERIFIED_OBJECTS: dict[int, weakref.ReferenceType[Any]] = {}


def _mark_verified(value: Any) -> Any:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if _VERIFIED_OBJECTS.get(identity) is reference:
            _VERIFIED_OBJECTS.pop(identity, None)

    _VERIFIED_OBJECTS[identity] = weakref.ref(value, discard)
    return value


def _require_verified(value: Any, expected_type: type, path: str) -> None:
    reference = _VERIFIED_OBJECTS.get(id(value))
    if (
        not isinstance(value, expected_type)
        or reference is None
        or reference() is not value
    ):
        _fail(
            "unverified_internal_result",
            path,
            "transition inputs must be exact objects returned by this verifier",
        )


def verify_criterion_authorization(
    authorization: Any,
    *,
    expected_criterion_id: str,
    expected_kind: str,
    expected_authority_digest: str,
    authorization_adapter: CriterionAuthorizationAdapter | None = None,
) -> VerifiedCriterionAuthorization:
    """Seal a delegation/static-policy criterion grant without a module cycle.

    A :mod:`delegation` ``CriterionScopedAuthorization`` is checked through its
    originating module's private identity registry via a lazy import.  Other
    policy implementations must provide a trusted adapter which both validates
    their own identity seal and returns the same exact projection.
    """

    criterion_id = _require_nonempty(
        expected_criterion_id, "external.expectedCriterionId", maximum=256
    )
    if expected_kind not in KINDS or expected_kind == "MACHINE":
        _fail(
            "invalid_criterion_authorization",
            "external.expectedKind",
            "only HUMAN/EXTERNAL/TIME identities require criterion grants",
        )
    authority_digest = _require_sha256(
        expected_authority_digest, "external.expectedAuthorityDigest"
    )
    projection: Mapping[str, Any]
    try:
        from . import delegation as delegation_module

        is_delegation = type(authorization) is delegation_module.CriterionScopedAuthorization
    except (ImportError, AttributeError):
        is_delegation = False
        delegation_module = None  # type: ignore[assignment]
    if is_delegation:
        assert delegation_module is not None
        delegation_module._require_verified(
            authorization,
            delegation_module.CriterionScopedAuthorization,
            "criterionAuthorization",
        )
        projection = {
            "criterionId": authorization.criterion_id,
            "principal": authorization.principal,
            "organization": authorization.organization,
            "role": authorization.role,
            "capability": authorization.capability,
            "authorityDigest": authorization.authority_digest,
            "delegationDigest": authorization.delegation_digest,
        }
        if authorization_adapter is not None:
            _fail(
                "invalid_criterion_authorization",
                "criterionAuthorization",
                "delegation grants do not use a second adapter",
            )
    else:
        if authorization_adapter is None:
            _fail(
                "unverified_internal_result",
                "criterionAuthorization",
                "non-delegation grants require an identity-validating policy adapter",
            )
        projection = authorization_adapter(authorization)
    fields = _exact_keys(
        projection,
        {
            "criterionId",
            "principal",
            "organization",
            "role",
            "capability",
            "authorityDigest",
            "delegationDigest",
        },
        "criterionAuthorization",
    )
    if fields["criterionId"] != criterion_id:
        _fail("criterion_not_authorized", "criterionAuthorization.criterionId", "grant is for another criterion")
    principal = fields["principal"]
    if not isinstance(principal, str) or PRINCIPAL_RE.fullmatch(principal) is None:
        _fail("invalid_principal", "criterionAuthorization.principal", "invalid exact principal")
    organization = _require_nonempty(fields["organization"], "criterionAuthorization.organization", maximum=256)
    role = _require_nonempty(fields["role"], "criterionAuthorization.role", maximum=256)
    required_capability = {
        "HUMAN": "attest-human-result",
        "EXTERNAL": "attest-external-result",
        "TIME": "attest-time-result",
    }[expected_kind]
    if fields["capability"] != required_capability:
        _fail("capability_not_authorized", "criterionAuthorization.capability", "capability differs from criterion kind")
    if fields["authorityDigest"] != authority_digest:
        _fail("authority_digest_mismatch", "criterionAuthorization.authorityDigest", "grant belongs to another authority")
    delegation_digest = fields["delegationDigest"]
    if delegation_digest is not None:
        delegation_digest = _require_sha256(
            delegation_digest, "criterionAuthorization.delegationDigest"
        )
    sealed_document = {
        "criterionId": criterion_id,
        "principal": principal,
        "organization": organization,
        "role": role,
        "capability": required_capability,
        "authorityDigest": authority_digest,
        "delegationDigest": delegation_digest,
    }
    return _mark_verified(
        VerifiedCriterionAuthorization(
            authorization_digest=sha256_bytes(canonical_json_bytes(sealed_document)),
            criterion_id=criterion_id,
            principal=principal,
            organization=organization,
            role=role,
            capability=required_capability,
            authority_digest=authority_digest,
            delegation_digest=delegation_digest,
        )
    )


def _resolve_criterion_authorization(
    authorization: Any,
    *,
    criterion: CriterionBinding,
    expected_authority_digest: str,
    authorization_adapter: CriterionAuthorizationAdapter | None,
) -> VerifiedCriterionAuthorization | None:
    if authorization is None:
        if authorization_adapter is not None:
            _fail("invalid_criterion_authorization", "criterionAuthorization", "adapter has no authorization")
        return None
    if isinstance(authorization, VerifiedCriterionAuthorization):
        _require_verified(
            authorization, VerifiedCriterionAuthorization, "criterionAuthorization"
        )
        sealed = authorization
    else:
        sealed = verify_criterion_authorization(
            authorization,
            expected_criterion_id=criterion.criterion_id,
            expected_kind=criterion.kind,
            expected_authority_digest=expected_authority_digest,
            authorization_adapter=authorization_adapter,
        )
    if (
        sealed.criterion_id != criterion.criterion_id
        or sealed.authority_digest != expected_authority_digest
    ):
        _fail("criterion_not_authorized", "criterionAuthorization", "grant binding differs")
    return sealed


SignerVerifier = Callable[
    [bytes, Mapping[str, Any], str], VerifiedSignerResult
]
FactVerifier = Callable[
    [Mapping[str, Any], VerifiedCriterionResult], Mapping[str, Any]
]
PhaseFactVerifier = Callable[
    [Mapping[str, Any], VerifiedPhaseCriterionResult], Mapping[str, Any]
]
CriterionAuthorizationAdapter = Callable[[Any], Mapping[str, Any]]


def _subject_document(subject: SubjectBinding) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "workUnit": subject.work_unit,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "contractDigest": subject.contract_digest,
    }


def _validate_subject(value: Any, path: str) -> SubjectBinding:
    body = _exact_keys(
        value,
        {
            "phase",
            "workUnit",
            "sourceCommit",
            "controlPlaneDigest",
            "contractDigest",
        },
        path,
    )
    phase = body["phase"]
    unit = body["workUnit"]
    match = UNIT_RE.fullmatch(unit) if isinstance(unit, str) else None
    if not isinstance(phase, str) or not PHASE_RE.fullmatch(phase):
        _fail("invalid_phase", f"{path}.phase", "expected P followed by two digits")
    if match is None or match.group(1) != phase:
        _fail("invalid_work_unit", f"{path}.workUnit", "work unit must belong to phase")
    return SubjectBinding(
        phase=phase,
        work_unit=unit,
        source_commit=_require_commit(body["sourceCommit"], f"{path}.sourceCommit"),
        control_plane_digest=_require_sha256(
            body["controlPlaneDigest"], f"{path}.controlPlaneDigest"
        ),
        contract_digest=_require_sha256(
            body["contractDigest"], f"{path}.contractDigest"
        ),
    )


def _validate_expected_subject(
    actual: SubjectBinding, expected: SubjectBinding, path: str
) -> None:
    if actual != expected:
        _fail(
            "subject_binding_mismatch",
            path,
            "phase/work-unit/source/control-plane/contract binding differs",
        )


def _phase_subject_document(subject: PhaseSubject) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "aggregateContractDigest": subject.aggregate_contract_digest,
    }


def _validate_phase_subject(value: Any, path: str) -> PhaseSubject:
    body = _exact_keys(
        value,
        {
            "phase",
            "sourceCommit",
            "controlPlaneDigest",
            "aggregateContractDigest",
        },
        path,
    )
    phase = body["phase"]
    if not isinstance(phase, str) or PHASE_RE.fullmatch(phase) is None:
        _fail("invalid_phase", f"{path}.phase", "expected P followed by two digits")
    return PhaseSubject(
        phase=phase,
        source_commit=_require_commit(body["sourceCommit"], f"{path}.sourceCommit"),
        control_plane_digest=_require_sha256(
            body["controlPlaneDigest"], f"{path}.controlPlaneDigest"
        ),
        aggregate_contract_digest=_require_sha256(
            body["aggregateContractDigest"], f"{path}.aggregateContractDigest"
        ),
    )


def _validate_expected_phase_subject(
    actual: PhaseSubject, expected: PhaseSubject, path: str
) -> None:
    if actual != expected:
        _fail(
            "phase_subject_binding_mismatch",
            path,
            "phase/source/control-plane/aggregate-contract binding differs",
        )


def _criterion_document(criterion: CriterionBinding) -> dict[str, str]:
    return {
        "id": criterion.criterion_id,
        "kind": criterion.kind,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "evaluatorStatus": criterion.evaluator_status,
        "evidenceSchema": criterion.evidence_schema,
        "evidenceSchemaDigest": criterion.evidence_schema_digest,
        "datasetDigest": criterion.dataset_digest,
        "thresholdDigest": criterion.threshold_digest,
    }


def _validate_criterion(value: Any, path: str) -> CriterionBinding:
    body = _exact_keys(value, CRITERION_FIELDS, path)
    criterion_id = _require_nonempty(body["id"], f"{path}.id", maximum=256)
    kind = body["kind"]
    if kind not in KINDS:
        _fail("invalid_criterion_kind", f"{path}.kind", "unsupported criterion kind")
    evaluator = _require_nonempty(
        body["evaluator"], f"{path}.evaluator", maximum=1024
    )
    if "://" not in evaluator:
        _fail("invalid_evaluator", f"{path}.evaluator", "evaluator must be a named URI")
    expected_status = EVALUATOR_STATUS_BY_KIND[kind]
    if body["evaluatorStatus"] != expected_status:
        _fail(
            "evaluator_not_implemented",
            f"{path}.evaluatorStatus",
            f"{kind} requires exact protected status {expected_status}",
        )
    evidence_schema = _require_nonempty(
        body["evidenceSchema"], f"{path}.evidenceSchema", maximum=1024
    )
    if "://" not in evidence_schema:
        _fail(
            "invalid_evidence_schema",
            f"{path}.evidenceSchema",
            "evidence schema must be a named URI",
        )
    return CriterionBinding(
        criterion_id=criterion_id,
        kind=kind,
        evaluator=evaluator,
        evaluator_digest=_require_sha256(
            body["evaluatorDigest"], f"{path}.evaluatorDigest"
        ),
        evidence_schema=evidence_schema,
        evidence_schema_digest=_require_sha256(
            body["evidenceSchemaDigest"], f"{path}.evidenceSchemaDigest"
        ),
        dataset_digest=_require_sha256(
            body["datasetDigest"], f"{path}.datasetDigest"
        ),
        threshold_digest=_require_sha256(
            body["thresholdDigest"], f"{path}.thresholdDigest"
        ),
        evaluator_status=expected_status,
    )


def _validate_criterion_set(values: Any, path: str) -> tuple[CriterionBinding, ...]:
    if not isinstance(values, list) or not values:
        _fail("invalid_criterion_set", path, "at least one criterion is required")
    result = tuple(
        _validate_criterion(value, f"{path}[{index}]")
        for index, value in enumerate(values)
    )
    ids = [item.criterion_id for item in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        _fail(
            "invalid_criterion_set",
            path,
            "criteria must be sorted by unique criterion ID",
        )
    return result


def _validate_protected_inputs(value: Any, path: str) -> tuple[tuple[str, str], ...]:
    body = _exact_keys(value, PROTECTED_INPUT_FIELDS, path)
    return tuple(
        (name, _require_sha256(body[name], f"{path}.{name}"))
        for name in sorted(PROTECTED_INPUT_FIELDS)
    )


def _validate_actor(value: Any, path: str) -> dict[str, str]:
    actor = _exact_keys(value, {"principal", "role", "organization"}, path)
    principal = actor["principal"]
    if not isinstance(principal, str) or not PRINCIPAL_RE.fullmatch(principal):
        _fail("invalid_principal", f"{path}.principal", "invalid exact principal")
    for field in ("role", "organization"):
        _require_nonempty(actor[field], f"{path}.{field}", maximum=256)
    return actor


def _signed_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def _validate_signature_descriptor(
    value: Any, namespace: str, path: str
) -> dict[str, str]:
    signature = _exact_keys(value, {"scheme", "namespace", "principal", "value"}, path)
    if signature["scheme"] not in SIGNER_SCHEMES:
        _fail("unsupported_signature_scheme", f"{path}.scheme", "unsupported signer scheme")
    if signature["namespace"] != namespace:
        _fail(
            "signature_namespace_mismatch",
            f"{path}.namespace",
            "signature cannot be replayed across statement domains",
        )
    principal = signature["principal"]
    if not isinstance(principal, str) or not PRINCIPAL_RE.fullmatch(principal):
        _fail("invalid_principal", f"{path}.principal", "invalid exact principal")
    raw = signature["value"]
    if not isinstance(raw, str) or not raw or len(raw) > 65536 or "\x00" in raw:
        _fail("malformed_signature", f"{path}.value", "invalid bounded signature value")
    return signature


def _validate_envelope(
    value: Any, *, schema: str, kind: str, namespace: str, path: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], str, bytes, str]:
    envelope = _exact_keys(
        value,
        {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
        path,
    )
    if envelope["schemaVersion"] != schema or envelope["kind"] != kind:
        _fail("invalid_statement_schema", path, "schemaVersion or kind mismatch")
    if not isinstance(envelope["body"], dict):
        _fail("invalid_schema", f"{path}.body", "must be an object")
    signature = _validate_signature_descriptor(
        envelope["signature"], namespace, f"{path}.signature"
    )
    attestation_digest = document_digest(envelope, omit_field="attestationDigest")
    if envelope["attestationDigest"] != attestation_digest:
        _fail(
            "attestation_digest_mismatch",
            f"{path}.attestationDigest",
            "digest does not cover the exact signed envelope",
        )
    payload = _signed_payload(envelope)
    return (
        envelope,
        envelope["body"],
        signature,
        attestation_digest,
        payload,
        sha256_bytes(payload),
    )


def _resolve_signer(
    *,
    payload: bytes,
    statement_digest: str,
    signature: Mapping[str, Any],
    namespace: str,
    body: Mapping[str, Any],
    subject: SubjectBinding | PhaseSubject,
    expected_role: str,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None,
    signer_verifier: SignerVerifier | None,
) -> VerifiedSignerResult:
    if (verified_signer_result is None) == (signer_verifier is None):
        _fail(
            "signer_verification_required",
            "signature",
            "provide exactly one frozen signer result or verifier callback",
        )
    result = (
        signer_verifier(payload, signature, namespace)
        if signer_verifier is not None
        else verified_signer_result
    )
    if not isinstance(result, VerifiedSignerResult):
        _fail(
            "invalid_signer_verification",
            "signature",
            "signer verifier must return VerifiedSignerResult",
        )
    actor = _validate_actor(body.get("actor"), "body.actor")
    authority = _require_sha256(body.get("authorityDigest"), "body.authorityDigest")
    _require_sha256(expected_authority_digest, "external.expectedAuthorityDigest")
    expected = {
        "scheme": signature["scheme"],
        "namespace": namespace,
        "principal": signature["principal"],
        "role": expected_role,
        "organization": actor["organization"],
        "statement_digest": statement_digest,
        "authority_digest": expected_authority_digest,
        "source_commit": subject.source_commit,
        "control_plane_digest": subject.control_plane_digest,
    }
    observed = {
        "scheme": result.scheme,
        "namespace": result.namespace,
        "principal": result.principal,
        "role": result.role,
        "organization": result.organization,
        "statement_digest": result.statement_digest,
        "authority_digest": result.authority_digest,
        "source_commit": result.source_commit,
        "control_plane_digest": result.control_plane_digest,
    }
    if actor["principal"] != result.principal or actor["role"] != result.role:
        _fail("actor_principal_mismatch", "body.actor", "actor differs from verified signer")
    if authority != expected_authority_digest or observed != expected:
        _fail(
            "signer_binding_mismatch",
            "signature",
            "verified identity, role, authority, statement, source, or control binding differs",
        )
    return result


def verify_ssh_reviewer_signature(
    statement: bytes,
    signature: str,
    principal_public_key: str,
    expected_namespace: str,
) -> Mapping[str, str]:
    """Verify reviewer SSHSIG bytes without interpreting an authorization policy.

    The R3 policy verifier must select the principal key, role, and namespace
    before calling this cryptographic primitive.  The semantic verifier then
    consumes a :class:`VerifiedSignerResult` built by that trusted caller.
    """

    verified = verify_sshsig(
        payload=statement,
        armored_signature=signature,
        public_key=principal_public_key,
        expected_namespace=expected_namespace,
    )
    return {
        "scheme": "openssh-sshsig-v1",
        "namespace": verified["namespace"],
        "hashAlgorithm": verified["hashAlgorithm"],
    }


def _prerequisite_document(value: PrerequisiteStateBinding) -> dict[str, str]:
    return {
        "phase": value.phase,
        "workUnit": value.work_unit,
        "status": value.status,
        "stateDigest": value.state_digest,
        "contractDigest": value.contract_digest,
        "sourceCommit": value.source_commit,
        "approvalDigest": value.approval_digest,
    }


def verify_work_unit_state_context(
    state_core: Any,
    *,
    expected_state_digest: str,
    expected_chain_head_digest: str,
    expected_control_plane_digest: str,
    phase: str,
    work_unit: str,
    expected_status: str,
    expected_contract_digest: str,
    prerequisite_units: Sequence[str] = (),
) -> VerifiedWorkUnitStateContext:
    """Derive a sealed work-unit context from one externally pinned state core.

    ``state_core`` is the exact canonical core replayed by the protected state
    verifier, not the generated view wrapper.  No caller-supplied evidence or
    result registry is accepted.
    """

    _require_sha256(expected_state_digest, "external.expectedStateDigest")
    _require_sha256(expected_chain_head_digest, "external.expectedChainHeadDigest")
    _require_sha256(
        expected_control_plane_digest, "external.expectedControlPlaneDigest"
    )
    _require_sha256(expected_contract_digest, "external.expectedContractDigest")
    if not isinstance(state_core, dict):
        _fail("invalid_state", "state", "state core must be an object")
    if document_digest(state_core) != expected_state_digest:
        _fail("state_digest_mismatch", "state", "state differs from the external pin")
    if state_core.get("controlPlaneDigest") != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "state.controlPlaneDigest",
            "state belongs to another control-plane revision",
        )
    _validate_state_invariants(state_core)
    if not isinstance(phase, str) or not PHASE_RE.fullmatch(phase):
        _fail("invalid_phase", "phase", "invalid phase ID")
    match = UNIT_RE.fullmatch(work_unit) if isinstance(work_unit, str) else None
    if match is None or match.group(1) != phase:
        _fail("invalid_work_unit", "workUnit", "work unit does not belong to phase")
    phases = state_core.get("phases")
    phase_state = phases.get(phase) if isinstance(phases, dict) else None
    units = phase_state.get("workUnits") if isinstance(phase_state, dict) else None
    unit_state = units.get(work_unit) if isinstance(units, dict) else None
    if not isinstance(unit_state, dict):
        _fail("unknown_work_unit", "state", "target work unit is absent")
    if unit_state.get("status") != expected_status:
        _fail("state_status_mismatch", "state", "target is not in the expected state")
    if unit_state.get("contractDigest") != expected_contract_digest:
        _fail("contract_digest_mismatch", "state", "target contract differs")
    recorded_source = unit_state.get("sourceCommit")
    if recorded_source is not None:
        _require_commit(recorded_source, "state.workUnit.sourceCommit")
    if expected_status == "READY" and state_core.get("activeWorkUnit") is not None:
        _fail(
            "active_work_unit_conflict",
            "state.activeWorkUnit",
            "activation requires no other ACTIVE work unit",
        )
    phase_unit_statuses: list[tuple[str, str]] = []
    for unit_id, candidate in sorted(units.items()):
        if not isinstance(candidate, dict) or candidate.get("status") not in ALLOWED_TRANSITIONS:
            _fail(
                "invalid_state",
                f"state.phases.{phase}.workUnits.{unit_id}",
                "every phase work unit must have a recognized status",
            )
        phase_unit_statuses.append((unit_id, candidate["status"]))
    target_number = int(work_unit.rsplit("W", 1)[1])
    earlier_same_phase = {
        unit_id
        for unit_id, _ in phase_unit_statuses
        if UNIT_RE.fullmatch(unit_id)
        and unit_id.startswith(phase + ".W")
        and int(unit_id.rsplit("W", 1)[1]) < target_number
    }
    declared = list(prerequisite_units)
    if any(not isinstance(item, str) for item in declared):
        _fail(
            "invalid_prerequisite_set",
            "prerequisiteUnits",
            "prerequisites must be work-unit IDs",
        )
    requested = sorted(set(declared) | earlier_same_phase)
    if (
        any(not isinstance(item, str) or UNIT_RE.fullmatch(item) is None for item in requested)
        or requested != sorted(set(requested))
        or work_unit in requested
    ):
        _fail(
            "invalid_prerequisite_set",
            "prerequisiteUnits",
            "prerequisites must be sorted, unique work units excluding the target",
        )
    prerequisites: list[PrerequisiteStateBinding] = []
    for prerequisite_unit in requested:
        prerequisite_phase = prerequisite_unit.split(".", 1)[0]
        predecessor_phase = phases.get(prerequisite_phase) if isinstance(phases, dict) else None
        predecessor_units = (
            predecessor_phase.get("workUnits")
            if isinstance(predecessor_phase, dict)
            else None
        )
        predecessor = (
            predecessor_units.get(prerequisite_unit)
            if isinstance(predecessor_units, dict)
            else None
        )
        if not isinstance(predecessor, dict) or predecessor.get("status") != "CONVERGED":
            _fail(
                "prerequisite_not_converged",
                f"state.{prerequisite_unit}",
                "every declared prerequisite must be CONVERGED",
            )
        contract_digest = _require_sha256(
            predecessor.get("contractDigest"),
            f"state.{prerequisite_unit}.contractDigest",
        )
        source_commit = _require_commit(
            predecessor.get("sourceCommit"),
            f"state.{prerequisite_unit}.sourceCommit",
        )
        approval_digest = _require_sha256(
            predecessor.get("approvalDigest"),
            f"state.{prerequisite_unit}.approvalDigest",
        )
        prerequisites.append(
            PrerequisiteStateBinding(
                phase=prerequisite_phase,
                work_unit=prerequisite_unit,
                status="CONVERGED",
                state_digest=expected_state_digest,
                contract_digest=contract_digest,
                source_commit=source_commit,
                approval_digest=approval_digest,
            )
        )
    return _mark_verified(
        VerifiedWorkUnitStateContext(
            state_digest=expected_state_digest,
            chain_head_digest=expected_chain_head_digest,
            control_plane_digest=expected_control_plane_digest,
            phase=phase,
            work_unit=work_unit,
            status=expected_status,
            contract_digest=expected_contract_digest,
            recorded_source_commit=recorded_source,
            prerequisites=tuple(prerequisites),
            phase_unit_statuses=tuple(phase_unit_statuses),
        )
    )


def _phase_unit_state_document(value: PhaseUnitStateBinding) -> dict[str, Any]:
    return {
        "workUnit": value.work_unit,
        "status": value.status,
        "contractDigest": value.contract_digest,
        "sourceCommit": value.source_commit,
        "approvalDigest": value.approval_digest,
    }


def verify_phase_state_context(
    state_core: Any,
    *,
    expected_state_digest: str,
    expected_chain_head_digest: str,
    expected_control_plane_digest: str,
    phase: str,
    expected_status: str,
    expected_aggregate_contract_digest: str,
) -> VerifiedPhaseStateContext:
    """Seal an aggregate state without representing the phase as a work unit."""

    _require_sha256(expected_state_digest, "external.expectedStateDigest")
    _require_sha256(expected_chain_head_digest, "external.expectedChainHeadDigest")
    _require_sha256(expected_control_plane_digest, "external.expectedControlPlaneDigest")
    _require_sha256(
        expected_aggregate_contract_digest,
        "external.expectedAggregateContractDigest",
    )
    if not isinstance(state_core, dict):
        _fail("invalid_state", "state", "state core must be an object")
    if document_digest(state_core) != expected_state_digest:
        _fail("state_digest_mismatch", "state", "state differs from external pin")
    if state_core.get("controlPlaneDigest") != expected_control_plane_digest:
        _fail("control_plane_digest_mismatch", "state", "state belongs to another control plane")
    _validate_state_invariants(state_core)
    if not isinstance(phase, str) or PHASE_RE.fullmatch(phase) is None:
        _fail("invalid_phase", "phase", "invalid phase ID")
    phases = state_core.get("phases")
    phase_state = phases.get(phase) if isinstance(phases, dict) else None
    if not isinstance(phase_state, dict):
        _fail("unknown_phase", "state", "aggregate phase is absent")
    if phase_state.get("status") != expected_status:
        _fail("state_status_mismatch", "state", "phase is not in expected state")
    if expected_status not in ALLOWED_TRANSITIONS:
        _fail("invalid_state", "state", "phase has an unrecognized status")
    if phase_state.get("aggregateContractDigest") != expected_aggregate_contract_digest:
        _fail("contract_digest_mismatch", "state", "aggregate contract differs")
    if phase_state.get("controlPlaneDigest") != expected_control_plane_digest:
        _fail("control_plane_digest_mismatch", "state", "phase control plane differs")
    base_commit = _require_commit(phase_state.get("baseCommit"), "state.phase.baseCommit")
    raw_units = phase_state.get("workUnits")
    if not isinstance(raw_units, dict) or not raw_units:
        _fail("invalid_state", "state.phase.workUnits", "phase units must be an object")
    if phase == "P00":
        required = {f"P00.W0{index}" for index in range(1, 6)}
        if set(raw_units) != required:
            _fail(
                "phase_unit_set_mismatch",
                "state.phase.workUnits",
                "P00 aggregate requires exactly P00.W01 through P00.W05",
            )
    units: list[PhaseUnitStateBinding] = []
    for unit_id, raw_unit in sorted(raw_units.items()):
        match = UNIT_RE.fullmatch(unit_id) if isinstance(unit_id, str) else None
        if match is None or match.group(1) != phase or not isinstance(raw_unit, dict):
            _fail("invalid_work_unit", "state.phase.workUnits", "invalid aggregate unit")
        status = raw_unit.get("status")
        if status not in ALLOWED_TRANSITIONS:
            _fail("invalid_state", f"state.phase.workUnits.{unit_id}.status", "unknown status")
        source = raw_unit.get("sourceCommit")
        approval = raw_unit.get("approvalDigest")
        if source is not None:
            source = _require_commit(source, f"state.phase.workUnits.{unit_id}.sourceCommit")
        if approval is not None:
            approval = _require_sha256(approval, f"state.phase.workUnits.{unit_id}.approvalDigest")
        if status == "CONVERGED" and (source is None or approval is None):
            _fail(
                "incomplete_converged_unit",
                f"state.phase.workUnits.{unit_id}",
                "CONVERGED unit requires source and approval",
            )
        units.append(
            PhaseUnitStateBinding(
                work_unit=unit_id,
                status=status,
                contract_digest=_require_sha256(
                    raw_unit.get("contractDigest"),
                    f"state.phase.workUnits.{unit_id}.contractDigest",
                ),
                source_commit=source,
                approval_digest=approval,
            )
        )
    return _mark_verified(
        VerifiedPhaseStateContext(
            state_digest=expected_state_digest,
            chain_head_digest=expected_chain_head_digest,
            control_plane_digest=expected_control_plane_digest,
            phase=phase,
            status=expected_status,
            aggregate_contract_digest=expected_aggregate_contract_digest,
            base_commit=base_commit,
            units=tuple(units),
        )
    )


def verify_signed_phase_protected_input_freeze(
    statement: Any,
    *,
    expected_subject: PhaseSubject,
    expected_aggregate_contract_approval_digest: str,
    expected_unit_contract_digests: Mapping[str, str],
    expected_protected_inputs: Mapping[str, str],
    expected_criteria: Sequence[Mapping[str, Any]],
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedPhaseProtectedInputFreeze:
    """Verify an independently signed aggregate input freeze."""

    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=PHASE_FREEZE_SCHEMA,
        kind=PHASE_FREEZE_KIND,
        namespace=PHASE_FREEZE_NAMESPACE,
        path="phaseFreeze",
    )
    body = _exact_keys(
        body,
        {
            "freezeId",
            "subject",
            "aggregateContractApprovalDigest",
            "unitContractDigests",
            "protectedInputs",
            "criteria",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "phaseFreeze.body",
    )
    freeze_id = _require_nonempty(body["freezeId"], "phaseFreeze.body.freezeId")
    subject = _validate_phase_subject(body["subject"], "phaseFreeze.body.subject")
    _validate_expected_phase_subject(subject, expected_subject, "phaseFreeze.body.subject")
    approval_digest = _require_sha256(
        expected_aggregate_contract_approval_digest,
        "external.expectedAggregateContractApprovalDigest",
    )
    if body["aggregateContractApprovalDigest"] != approval_digest:
        _fail("contract_approval_digest_mismatch", "phaseFreeze.body.aggregateContractApprovalDigest", "approval pin differs")
    if not isinstance(expected_unit_contract_digests, Mapping):
        _fail("invalid_unit_contract_set", "external.expectedUnitContractDigests", "mapping required")
    unit_contracts = tuple(
        sorted(
            (
                unit_id,
                _require_sha256(digest_value, f"external.expectedUnitContractDigests.{unit_id}"),
            )
            for unit_id, digest_value in expected_unit_contract_digests.items()
        )
    )
    if not unit_contracts or body["unitContractDigests"] != dict(unit_contracts):
        _fail("unit_contract_binding_mismatch", "phaseFreeze.body.unitContractDigests", "unit contract set differs")
    protected_inputs = _validate_protected_inputs(
        body["protectedInputs"], "phaseFreeze.body.protectedInputs"
    )
    expected_inputs = tuple(
        (name, _require_sha256(expected_protected_inputs.get(name), f"external.expectedProtectedInputs.{name}"))
        for name in sorted(PROTECTED_INPUT_FIELDS)
    )
    if protected_inputs != expected_inputs:
        _fail("protected_input_mismatch", "phaseFreeze.body.protectedInputs", "protected input set differs")
    criteria = _validate_criterion_set(body["criteria"], "phaseFreeze.body.criteria")
    expected_catalog = _validate_criterion_set(list(expected_criteria), "external.expectedCriteria")
    if criteria != expected_catalog:
        _fail("criterion_binding_mismatch", "phaseFreeze.body.criteria", "criterion catalog differs")
    if subject.phase == "P00":
        go_nogo = [
            item for item in criteria if item.criterion_id == "P00-H-GO-NOGO"
        ]
        if len(go_nogo) != 1 or go_nogo[0].kind != "HUMAN":
            _fail("missing_go_nogo_criterion", "phaseFreeze.body.criteria", "P00 aggregate must freeze P00-H-GO-NOGO as HUMAN")
    _parse_utc(body["issuedAt"], "phaseFreeze.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=PHASE_FREEZE_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedPhaseProtectedInputFreeze(
            attestation_digest=digest,
            statement_digest=statement_digest,
            freeze_id=freeze_id,
            subject=subject,
            aggregate_contract_approval_digest=approval_digest,
            unit_contract_digests=unit_contracts,
            protected_inputs=protected_inputs,
            criteria=criteria,
            signer=signer,
        )
    )


def _lifecycle_transition_type(from_state: str, to_state: str) -> str:
    if to_state not in ALLOWED_TRANSITIONS.get(from_state, ()):
        _fail(
            "illegal_state_transition",
            "lifecycleProof.body",
            f"transition {from_state}->{to_state} is not allowed",
        )
    if from_state in {"NOT_STARTED", "REJECTED"} and to_state == "READY":
        return "READINESS"
    if from_state == "BLOCKED" and to_state == "ACTIVE":
        return "RESUME"
    if to_state == "SUPERSEDED":
        return "SUPERSESSION"
    if to_state in {"BLOCKED", "REJECTED"}:
        return "INVALIDATION"
    _fail(
        "unsupported_lifecycle_transition",
        "lifecycleProof.body",
        "activation and convergence transitions use their dedicated proof types",
    )


def _validate_lifecycle_semantics(
    *,
    transition_type: str,
    from_state: str,
    to_state: str,
    blocker_resolution_digest: Any,
    invalidation_kind: Any,
    invalidation_digest: Any,
    path: str,
) -> tuple[str | None, str | None, str | None]:
    blocker: str | None = None
    invalidation: str | None = None
    invalidation_evidence: str | None = None
    if transition_type == "READINESS":
        if any(
            value is not None
            for value in (
                blocker_resolution_digest,
                invalidation_kind,
                invalidation_digest,
            )
        ):
            _fail("unexpected_lifecycle_evidence", path, "readiness has no blocker/invalidation")
    elif transition_type == "RESUME":
        blocker = _require_sha256(
            blocker_resolution_digest, f"{path}.blockerResolutionDigest"
        )
        if invalidation_kind is not None or invalidation_digest is not None:
            _fail("unexpected_lifecycle_evidence", path, "resume only consumes blocker resolution")
    elif transition_type == "INVALIDATION":
        if blocker_resolution_digest is not None:
            _fail("unexpected_lifecycle_evidence", path, "invalidation is not a resume")
        if invalidation_kind not in {"IMPACT", "CONTROL"}:
            _fail(
                "invalid_invalidation_kind",
                f"{path}.invalidationKind",
                "only IMPACT or CONTROL invalidation is authorized",
            )
        invalidation = invalidation_kind
        invalidation_evidence = _require_sha256(
            invalidation_digest, f"{path}.invalidationDigest"
        )
        if to_state == "BLOCKED" and from_state != "ACTIVE":
            _fail("invalid_invalidation_target", path, "only ACTIVE invalidation becomes BLOCKED")
        if to_state == "REJECTED" and from_state == "ACTIVE":
            _fail("invalid_invalidation_target", path, "ACTIVE invalidation must become BLOCKED")
        if from_state == "CONVERGED" and to_state != "REJECTED":
            _fail("invalid_invalidation_target", path, "CONVERGED can only reopen as REJECTED")
    else:
        if blocker_resolution_digest is not None:
            _fail("unexpected_lifecycle_evidence", path, "supersession is not a resume")
        if invalidation_kind != "SUPERSESSION":
            _fail(
                "invalid_supersession_evidence",
                f"{path}.invalidationKind",
                "supersession must identify its replacement evidence",
            )
        invalidation = invalidation_kind
        invalidation_evidence = _require_sha256(
            invalidation_digest, f"{path}.invalidationDigest"
        )
    return blocker, invalidation, invalidation_evidence


def verify_lifecycle_proof(
    statement: Any,
    *,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    expected_to_state: str,
    expected_contract_approval_digest: str,
    expected_impact_map_digest: str,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedLifecycleProofResult:
    """Verify readiness, resume, invalidation, or supersession evidence."""

    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    contract_approval = _require_sha256(
        expected_contract_approval_digest, "external.expectedContractApprovalDigest"
    )
    impact_map = _require_sha256(
        expected_impact_map_digest, "external.expectedImpactMapDigest"
    )
    if (
        expected_subject.phase != state_context.phase
        or expected_subject.work_unit != state_context.work_unit
        or expected_subject.control_plane_digest != state_context.control_plane_digest
        or expected_subject.contract_digest != state_context.contract_digest
    ):
        _fail("state_subject_mismatch", "stateContext", "subject differs from verified state")
    transition_type = _lifecycle_transition_type(
        state_context.status, expected_to_state
    )
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=LIFECYCLE_PROOF_SCHEMA,
        kind=LIFECYCLE_PROOF_KIND,
        namespace=LIFECYCLE_PROOF_NAMESPACE,
        path="lifecycleProof",
    )
    body = _exact_keys(
        body,
        {
            "proofId",
            "transitionType",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractApprovalDigest",
            "impactMapDigest",
            "prerequisites",
            "reasonCode",
            "reason",
            "blockerResolutionDigest",
            "invalidationKind",
            "invalidationDigest",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "lifecycleProof.body",
    )
    proof_id = _require_nonempty(body["proofId"], "lifecycleProof.body.proofId")
    if (
        body["transitionType"] != transition_type
        or body["fromState"] != state_context.status
        or body["toState"] != expected_to_state
    ):
        _fail("transition_replay", "lifecycleProof.body", "proof is for another lifecycle transition")
    subject = _validate_subject(body["subject"], "lifecycleProof.body.subject")
    _validate_expected_subject(subject, expected_subject, "lifecycleProof.body.subject")
    if (
        body["priorStateDigest"] != state_context.state_digest
        or body["priorChainHeadDigest"] != state_context.chain_head_digest
    ):
        _fail("transition_state_replay", "lifecycleProof.body", "proof targets another state/head")
    if body["contractApprovalDigest"] != contract_approval:
        _fail("contract_approval_digest_mismatch", "lifecycleProof.body.contractApprovalDigest", "approval pin differs")
    if body["impactMapDigest"] != impact_map:
        _fail("impact_map_digest_mismatch", "lifecycleProof.body.impactMapDigest", "impact-map pin differs")
    expected_prerequisites = [
        _prerequisite_document(item) for item in state_context.prerequisites
    ]
    if body["prerequisites"] != expected_prerequisites:
        _fail("prerequisite_binding_mismatch", "lifecycleProof.body.prerequisites", "prerequisite projection differs")
    if transition_type == "READINESS":
        preceding = {
            unit_id: status
            for unit_id, status in state_context.phase_unit_statuses
            if unit_id < state_context.work_unit
        }
        if any(status != "CONVERGED" for status in preceding.values()):
            _fail("prerequisite_not_converged", "stateContext", "all earlier phase units must be CONVERGED")
    reason_code = _require_nonempty(body["reasonCode"], "lifecycleProof.body.reasonCode")
    reason = _require_nonempty(body["reason"], "lifecycleProof.body.reason")
    blocker, invalidation, invalidation_evidence = _validate_lifecycle_semantics(
        transition_type=transition_type,
        from_state=state_context.status,
        to_state=expected_to_state,
        blocker_resolution_digest=body["blockerResolutionDigest"],
        invalidation_kind=body["invalidationKind"],
        invalidation_digest=body["invalidationDigest"],
        path="lifecycleProof.body",
    )
    _parse_utc(body["issuedAt"], "lifecycleProof.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=LIFECYCLE_PROOF_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="protected-workflow",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedLifecycleProofResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            proof_id=proof_id,
            transition_type=transition_type,
            subject=subject,
            from_state=state_context.status,
            to_state=expected_to_state,
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            contract_approval_digest=contract_approval,
            impact_map_digest=impact_map,
            prerequisites=state_context.prerequisites,
            reason_code=reason_code,
            reason=reason,
            blocker_resolution_digest=blocker,
            invalidation_kind=invalidation,
            invalidation_digest=invalidation_evidence,
            signer=signer,
        )
    )


def _lifecycle_projection(proof: VerifiedLifecycleProofResult) -> dict[str, Any]:
    return {
        "transitionType": proof.transition_type,
        "subject": _subject_document(proof.subject),
        "fromState": proof.from_state,
        "toState": proof.to_state,
        "priorStateDigest": proof.prior_state_digest,
        "priorChainHeadDigest": proof.prior_chain_head_digest,
        "contractApprovalDigest": proof.contract_approval_digest,
        "impactMapDigest": proof.impact_map_digest,
        "prerequisites": [_prerequisite_document(item) for item in proof.prerequisites],
        "reasonCode": proof.reason_code,
        "reason": proof.reason,
        "blockerResolutionDigest": proof.blocker_resolution_digest,
        "invalidationKind": proof.invalidation_kind,
        "invalidationDigest": proof.invalidation_digest,
    }


def verify_lifecycle_approval(
    statement: Any,
    *,
    proof: VerifiedLifecycleProofResult,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    now: datetime | None = None,
) -> VerifiedLifecycleApprovalResult:
    """Verify an independent, exact-proof lifecycle authorization."""

    _require_verified(proof, VerifiedLifecycleProofResult, "lifecycleProof")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=LIFECYCLE_APPROVAL_SCHEMA,
        kind=LIFECYCLE_APPROVAL_KIND,
        namespace=LIFECYCLE_APPROVAL_NAMESPACE,
        path="lifecycleApproval",
    )
    body = _exact_keys(
        body,
        {
            "approvalId",
            "proofDigest",
            *_lifecycle_projection(proof).keys(),
            "decision",
            "approvalReason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "lifecycleApproval.body",
    )
    approval_id = _require_nonempty(body["approvalId"], "lifecycleApproval.body.approvalId")
    if body["proofDigest"] != proof.attestation_digest:
        _fail("proof_digest_mismatch", "lifecycleApproval.body.proofDigest", "approval targets another proof")
    projection = _lifecycle_projection(proof)
    if any(body[key] != value for key, value in projection.items()):
        _fail("lifecycle_approval_replay", "lifecycleApproval.body", "approval projection differs")
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail("invalid_approval_decision", "lifecycleApproval.body.decision", "must be APPROVE/REJECT")
    _require_nonempty(body["approvalReason"], "lifecycleApproval.body.approvalReason")
    conflict = _exact_keys(
        body["conflictOfInterest"],
        {"independent", "statement"},
        "lifecycleApproval.body.conflictOfInterest",
    )
    if conflict["independent"] is not True:
        _fail("reviewer_not_independent", "lifecycleApproval.body.conflictOfInterest", "independence required")
    _require_nonempty(conflict["statement"], "lifecycleApproval.body.conflictOfInterest.statement")
    issued_at = _parse_utc(body["issuedAt"], "lifecycleApproval.body.issuedAt")
    valid_until = _parse_utc(body["validUntil"], "lifecycleApproval.body.validUntil")
    verification_time = _now_utc(now)
    if issued_at >= valid_until or not issued_at <= verification_time < valid_until:
        _fail("approval_outside_validity", "lifecycleApproval.body", "approval is not currently valid")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=LIFECYCLE_APPROVAL_NAMESPACE,
        body=body,
        subject=proof.subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedLifecycleApprovalResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            approval_id=approval_id,
            proof_digest=proof.attestation_digest,
            subject=proof.subject,
            from_state=proof.from_state,
            to_state=proof.to_state,
            decision=body["decision"],
            authorized=body["decision"] == "APPROVE",
            signer=signer,
        )
    )


def authorize_lifecycle_transition(
    *,
    state_context: VerifiedWorkUnitStateContext,
    proof: VerifiedLifecycleProofResult,
    approval: VerifiedLifecycleApprovalResult,
) -> VerifiedLifecycleTransition:
    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    _require_verified(proof, VerifiedLifecycleProofResult, "lifecycleProof")
    _require_verified(approval, VerifiedLifecycleApprovalResult, "lifecycleApproval")
    if (
        proof.from_state != state_context.status
        or proof.prior_state_digest != state_context.state_digest
        or proof.prior_chain_head_digest != state_context.chain_head_digest
        or proof.subject.phase != state_context.phase
        or proof.subject.work_unit != state_context.work_unit
        or proof.subject.control_plane_digest != state_context.control_plane_digest
        or proof.subject.contract_digest != state_context.contract_digest
        or proof.prerequisites != state_context.prerequisites
    ):
        _fail("lifecycle_proof_replay", "lifecycleProof", "proof does not bind exact verified state")
    if (
        not approval.authorized
        or approval.decision != "APPROVE"
        or approval.proof_digest != proof.attestation_digest
        or approval.subject != proof.subject
        or approval.from_state != proof.from_state
        or approval.to_state != proof.to_state
    ):
        _fail("lifecycle_not_approved", "lifecycleApproval", "exact proof lacks independent APPROVE")
    return _mark_verified(
        VerifiedLifecycleTransition(
            transition_type=proof.transition_type,
            subject=proof.subject,
            from_state=proof.from_state,
            to_state=proof.to_state,
            prior_state_digest=proof.prior_state_digest,
            prior_chain_head_digest=proof.prior_chain_head_digest,
            contract_approval_digest=proof.contract_approval_digest,
            impact_map_digest=proof.impact_map_digest,
            prerequisites=proof.prerequisites,
            reason_code=proof.reason_code,
            reason=proof.reason,
            blocker_resolution_digest=proof.blocker_resolution_digest,
            invalidation_kind=proof.invalidation_kind,
            invalidation_digest=proof.invalidation_digest,
            proof_digest=proof.attestation_digest,
            approval_digest=approval.attestation_digest,
        )
    )


def verify_signed_protected_input_freeze(
    statement: Any,
    *,
    expected_subject: SubjectBinding,
    expected_contract_approval_digest: str,
    expected_protected_inputs: Mapping[str, str],
    expected_criteria: Sequence[Mapping[str, Any]],
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedProtectedInputFreeze:
    """Verify the exact independently approved protected-input freeze."""

    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=FREEZE_SCHEMA,
        kind=FREEZE_KIND,
        namespace=FREEZE_NAMESPACE,
        path="freeze",
    )
    body = _exact_keys(
        body,
        {
            "freezeId",
            "subject",
            "contractApprovalDigest",
            "protectedInputs",
            "criteria",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "freeze.body",
    )
    freeze_id = _require_nonempty(body["freezeId"], "freeze.body.freezeId", maximum=256)
    subject = _validate_subject(body["subject"], "freeze.body.subject")
    _validate_expected_subject(subject, expected_subject, "freeze.body.subject")
    contract_approval = _require_sha256(
        body["contractApprovalDigest"], "freeze.body.contractApprovalDigest"
    )
    _require_sha256(expected_contract_approval_digest, "external.expectedContractApprovalDigest")
    if contract_approval != expected_contract_approval_digest:
        _fail("contract_approval_digest_mismatch", "freeze.body", "approval differs")
    protected_inputs = _validate_protected_inputs(
        body["protectedInputs"], "freeze.body.protectedInputs"
    )
    expected_inputs = _validate_protected_inputs(
        dict(expected_protected_inputs), "external.expectedProtectedInputs"
    )
    if protected_inputs != expected_inputs:
        _fail("protected_input_mismatch", "freeze.body.protectedInputs", "freeze replaced")
    criteria = _validate_criterion_set(body["criteria"], "freeze.body.criteria")
    expected = _validate_criterion_set(list(expected_criteria), "external.expectedCriteria")
    if criteria != expected:
        _fail(
            "contract_criterion_mismatch",
            "freeze.body.criteria",
            "criterion/evaluator/dataset contract projection differs",
        )
    _parse_utc(body["issuedAt"], "freeze.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=FREEZE_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    return _mark_verified(VerifiedProtectedInputFreeze(
        attestation_digest=digest,
        statement_digest=statement_digest,
        freeze_id=freeze_id,
        subject=subject,
        contract_approval_digest=contract_approval,
        protected_inputs=protected_inputs,
        criteria=criteria,
        signer=signer,
    ))


def verify_activation_proof(
    statement: Any,
    *,
    state_context: VerifiedWorkUnitStateContext,
    expected_subject: SubjectBinding,
    expected_contract_approval_digest: str,
    expected_impact_map_digest: str,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedActivationProofResult:
    """Verify workflow provenance for one explicit READY -> ACTIVE request."""

    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    if state_context.status != "READY":
        _fail("invalid_activation_state", "stateContext", "activation requires READY")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=ACTIVATION_PROOF_SCHEMA,
        kind=ACTIVATION_PROOF_KIND,
        namespace=ACTIVATION_PROOF_NAMESPACE,
        path="activationProof",
    )
    body = _exact_keys(
        body,
        {
            "proofId",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractApprovalDigest",
            "impactMapDigest",
            "prerequisites",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "activationProof.body",
    )
    proof_id = _require_nonempty(
        body["proofId"], "activationProof.body.proofId", maximum=256
    )
    subject = _validate_subject(body["subject"], "activationProof.body.subject")
    _validate_expected_subject(subject, expected_subject, "activationProof.body.subject")
    if (
        subject.phase != state_context.phase
        or subject.work_unit != state_context.work_unit
        or subject.control_plane_digest != state_context.control_plane_digest
        or subject.contract_digest != state_context.contract_digest
    ):
        _fail(
            "activation_subject_mismatch",
            "activationProof.body.subject",
            "target differs from the verified READY state",
        )
    if body["fromState"] != "READY" or body["toState"] != "ACTIVE":
        _fail("invalid_activation_transition", "activationProof.body", "expected READY -> ACTIVE")
    if (
        body["priorStateDigest"] != state_context.state_digest
        or body["priorChainHeadDigest"] != state_context.chain_head_digest
    ):
        _fail(
            "activation_state_replay",
            "activationProof.body",
            "activation proof is for another state or chain head",
        )
    contract_approval_digest = _require_sha256(
        body["contractApprovalDigest"],
        "activationProof.body.contractApprovalDigest",
    )
    _require_sha256(
        expected_contract_approval_digest,
        "external.expectedContractApprovalDigest",
    )
    if contract_approval_digest != expected_contract_approval_digest:
        _fail(
            "contract_approval_digest_mismatch",
            "activationProof.body.contractApprovalDigest",
            "activation uses another contract approval",
        )
    impact_map_digest = _require_sha256(
        body["impactMapDigest"], "activationProof.body.impactMapDigest"
    )
    _require_sha256(expected_impact_map_digest, "external.expectedImpactMapDigest")
    if impact_map_digest != expected_impact_map_digest:
        _fail("impact_map_digest_mismatch", "activationProof.body", "impact map differs")
    expected_prerequisites = [
        _prerequisite_document(item) for item in state_context.prerequisites
    ]
    if body["prerequisites"] != expected_prerequisites:
        _fail(
            "prerequisite_binding_mismatch",
            "activationProof.body.prerequisites",
            "activation prerequisite projection is not exact",
        )
    _parse_utc(body["issuedAt"], "activationProof.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=ACTIVATION_PROOF_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="protected-workflow",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    return _mark_verified(
        VerifiedActivationProofResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            proof_id=proof_id,
            subject=subject,
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            contract_approval_digest=contract_approval_digest,
            impact_map_digest=impact_map_digest,
            prerequisites=state_context.prerequisites,
            signer=signer,
        )
    )


def verify_activation_approval(
    statement: Any,
    *,
    proof: VerifiedActivationProofResult,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    now: datetime | None = None,
) -> VerifiedActivationApprovalResult:
    """Verify the independent decision authorizing one exact activation proof."""

    _require_verified(proof, VerifiedActivationProofResult, "activationProof")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=ACTIVATION_APPROVAL_SCHEMA,
        kind=ACTIVATION_APPROVAL_KIND,
        namespace=ACTIVATION_APPROVAL_NAMESPACE,
        path="activationApproval",
    )
    body = _exact_keys(
        body,
        {
            "approvalId",
            "proofDigest",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "contractApprovalDigest",
            "impactMapDigest",
            "prerequisites",
            "decision",
            "reason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "activationApproval.body",
    )
    approval_id = _require_nonempty(
        body["approvalId"], "activationApproval.body.approvalId", maximum=256
    )
    if body["proofDigest"] != proof.attestation_digest:
        _fail("proof_digest_mismatch", "activationApproval.body", "approval proof differs")
    subject = _validate_subject(body["subject"], "activationApproval.body.subject")
    _validate_expected_subject(subject, proof.subject, "activationApproval.body.subject")
    expected = {
        "fromState": "READY",
        "toState": "ACTIVE",
        "priorStateDigest": proof.prior_state_digest,
        "priorChainHeadDigest": proof.prior_chain_head_digest,
        "contractApprovalDigest": proof.contract_approval_digest,
        "impactMapDigest": proof.impact_map_digest,
        "prerequisites": [
            _prerequisite_document(item) for item in proof.prerequisites
        ],
    }
    if any(body[key] != value for key, value in expected.items()):
        _fail(
            "activation_approval_binding_mismatch",
            "activationApproval.body",
            "approval is for another activation subject/state/prerequisite set",
        )
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail("invalid_approval_decision", "activationApproval.body.decision", "must be APPROVE/REJECT")
    _require_nonempty(body["reason"], "activationApproval.body.reason")
    conflict = _exact_keys(
        body["conflictOfInterest"],
        {"independent", "statement"},
        "activationApproval.body.conflictOfInterest",
    )
    if conflict["independent"] is not True:
        _fail("reviewer_not_independent", "activationApproval.body", "independence required")
    _require_nonempty(conflict["statement"], "activationApproval.body.conflictOfInterest.statement")
    issued_at = _parse_utc(body["issuedAt"], "activationApproval.body.issuedAt")
    valid_until = _parse_utc(body["validUntil"], "activationApproval.body.validUntil")
    verification_time = _now_utc(now)
    if issued_at >= valid_until or not issued_at <= verification_time < valid_until:
        _fail("approval_outside_validity", "activationApproval.body", "approval is not valid")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=ACTIVATION_APPROVAL_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    return _mark_verified(
        VerifiedActivationApprovalResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            approval_id=approval_id,
            proof_digest=proof.attestation_digest,
            subject=subject,
            decision=body["decision"],
            authorized=body["decision"] == "APPROVE",
            signer=signer,
        )
    )


def _validate_run_pair(
    value: Any,
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion: CriterionBinding,
    outcome: str,
    path: str,
) -> str:
    pair = _exact_keys(value, {"verificationPairId", "runA", "runB"}, path)
    _require_nonempty(pair["verificationPairId"], f"{path}.verificationPairId", maximum=256)
    inputs = dict(freeze.protected_inputs)
    contract_digest = (
        freeze.subject.contract_digest
        if isinstance(freeze.subject, SubjectBinding)
        else freeze.subject.aggregate_contract_digest
    )
    runs: list[dict[str, Any]] = []
    run_fields = {
        "label",
        "environmentClass",
        "environmentDigest",
        "sourceCommit",
        "controlPlaneDigest",
        "contractDigest",
        "planDigest",
        "supportLockDigest",
        "dependencySetDigest",
        "toolchainDigest",
        "gateRunnerDigest",
        "evaluatorSetDigest",
        "metricDefinitionsDigest",
        "protectedAcceptanceDigest",
        "evaluatorDigest",
        "datasetDigest",
        "sourceDirtyBeforeRun",
        "cleanCheckout",
        "startedAt",
        "finishedAt",
        "commands",
        "deterministicResultSetDigest",
        "runEvidenceDigest",
    }
    for name, label, environment, clean in (
        ("runA", "A", "development-isolated", False),
        ("runB", "B", "clean-checkout-offline", True),
    ):
        run = _exact_keys(pair[name], run_fields, f"{path}.{name}")
        actual_digest = document_digest(run, omit_field="runEvidenceDigest")
        if run["runEvidenceDigest"] != actual_digest:
            _fail("run_evidence_digest_mismatch", f"{path}.{name}", "run digest mismatch")
        expected = {
            "label": label,
            "environmentClass": environment,
            "sourceCommit": freeze.subject.source_commit,
            "controlPlaneDigest": freeze.subject.control_plane_digest,
            "contractDigest": contract_digest,
            "planDigest": inputs["planDigest"],
            "supportLockDigest": inputs["supportLockDigest"],
            "dependencySetDigest": inputs["dependencySetDigest"],
            "toolchainDigest": inputs["toolchainDigest"],
            "gateRunnerDigest": inputs["gateRunnerDigest"],
            "evaluatorSetDigest": inputs["evaluatorSetDigest"],
            "metricDefinitionsDigest": inputs["metricDefinitionsDigest"],
            "protectedAcceptanceDigest": inputs["protectedAcceptanceDigest"],
            "evaluatorDigest": criterion.evaluator_digest,
            "datasetDigest": criterion.dataset_digest,
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": clean,
        }
        if any(run[key] != expected_value for key, expected_value in expected.items()):
            _fail(
                "run_binding_mismatch",
                f"{path}.{name}",
                "Run A/B source/control/contract/input/evaluator/dataset binding differs",
            )
        _require_sha256(run["environmentDigest"], f"{path}.{name}.environmentDigest")
        started_at = _parse_utc(run["startedAt"], f"{path}.{name}.startedAt")
        finished_at = _parse_utc(run["finishedAt"], f"{path}.{name}.finishedAt")
        if started_at >= finished_at:
            _fail(
                "invalid_run_time",
                f"{path}.{name}",
                "startedAt must precede finishedAt",
            )
        commands = run["commands"]
        if not isinstance(commands, list) or not commands:
            _fail("missing_run_commands", f"{path}.{name}.commands", "at least one command is required")
        any_semantic_assertion = False
        all_success = True
        for index, command_value in enumerate(commands):
            command_path = f"{path}.{name}.commands[{index}]"
            command = _exact_keys(
                command_value,
                {
                    "command",
                    "exitCode",
                    "durationMs",
                    "summary",
                    "logDigest",
                    "artifactManifestDigest",
                },
                command_path,
            )
            _require_nonempty(command["command"], f"{command_path}.command", maximum=4096)
            exit_code = command["exitCode"]
            duration_ms = command["durationMs"]
            if isinstance(exit_code, bool) or not isinstance(exit_code, int):
                _fail("invalid_run_command", f"{command_path}.exitCode", "must be an integer")
            if (
                isinstance(duration_ms, bool)
                or not isinstance(duration_ms, int)
                or duration_ms < 0
            ):
                _fail("invalid_run_command", f"{command_path}.durationMs", "must be a non-negative integer")
            summary = _exact_keys(
                command["summary"], {"passed", "failed", "skipped"}, f"{command_path}.summary"
            )
            for field in ("passed", "failed", "skipped"):
                count = summary[field]
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    _fail("invalid_run_summary", f"{command_path}.summary.{field}", "must be a non-negative integer")
            any_semantic_assertion = any_semantic_assertion or summary["passed"] > 0
            all_success = all_success and exit_code == 0 and summary["failed"] == 0
            _require_sha256(command["logDigest"], f"{command_path}.logDigest")
            _require_sha256(
                command["artifactManifestDigest"],
                f"{command_path}.artifactManifestDigest",
            )
        if outcome == "PASS" and (not all_success or not any_semantic_assertion):
            _fail(
                "machine_run_not_successful",
                f"{path}.{name}.commands",
                "PASS requires successful commands with at least one semantic assertion",
            )
        _require_sha256(
            run["deterministicResultSetDigest"],
            f"{path}.{name}.deterministicResultSetDigest",
        )
        runs.append(run)
    if runs[0]["deterministicResultSetDigest"] != runs[1]["deterministicResultSetDigest"]:
        _fail(
            "deterministic_result_mismatch",
            path,
            "Run A and Run B deterministic result sets differ",
        )
    return document_digest(pair)


def verify_signed_criterion_result(
    statement: Any,
    *,
    freeze: VerifiedProtectedInputFreeze,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    fact_verifier: FactVerifier | None = None,
    criterion_authorization: Any = None,
    criterion_authorization_adapter: CriterionAuthorizationAdapter | None = None,
) -> VerifiedCriterionResult:
    """Verify a criterion result; EXTERNAL/TIME remain incomplete by default."""

    _require_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
    raw_body = statement.get("body") if isinstance(statement, dict) else None
    raw_criterion = raw_body.get("criterion") if isinstance(raw_body, dict) else None
    raw_kind = raw_criterion.get("kind") if isinstance(raw_criterion, dict) else None
    namespace = CRITERION_NAMESPACES.get(raw_kind)
    if namespace is None:
        _fail(
            "invalid_criterion_kind",
            "criterionResult.body.criterion.kind",
            "cannot select a signature domain for this criterion kind",
        )
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=CRITERION_SCHEMA,
        kind=CRITERION_KIND,
        namespace=namespace,
        path="criterionResult",
    )
    body = _exact_keys(
        body,
        {
            "resultId",
            "freezeDigest",
            "subject",
            "criterion",
            "outcome",
            "evidenceDigest",
            "runPair",
            "runPairDigest",
            "humanReview",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "criterionResult.body",
    )
    result_id = _require_nonempty(body["resultId"], "criterionResult.body.resultId", maximum=256)
    if body["freezeDigest"] != freeze.attestation_digest:
        _fail("freeze_digest_mismatch", "criterionResult.body.freezeDigest", "freeze replaced")
    subject = _validate_subject(body["subject"], "criterionResult.body.subject")
    _validate_expected_subject(subject, freeze.subject, "criterionResult.body.subject")
    criterion = _validate_criterion(body["criterion"], "criterionResult.body.criterion")
    catalog = {item.criterion_id: item for item in freeze.criteria}
    if catalog.get(criterion.criterion_id) != criterion:
        _fail(
            "criterion_binding_mismatch",
            "criterionResult.body.criterion",
            "criterion/evaluator/dataset differs from frozen contract",
        )
    authorization: VerifiedCriterionAuthorization | None = None
    if criterion.kind == "MACHINE":
        if criterion_authorization is not None or criterion_authorization_adapter is not None:
            _fail("unexpected_criterion_authorization", "criterionAuthorization", "MACHINE is authorized by protected workflow identity")
    else:
        authorization = _resolve_criterion_authorization(
            criterion_authorization,
            criterion=criterion,
            expected_authority_digest=expected_authority_digest,
            authorization_adapter=criterion_authorization_adapter,
        )
    evidence_digest = _require_sha256(
        body["evidenceDigest"], "criterionResult.body.evidenceDigest"
    )
    run_pair_digest: str | None = None
    if criterion.kind == "MACHINE":
        if body["outcome"] not in {"PASS", "FAIL"}:
            _fail("invalid_criterion_outcome", "criterionResult.body.outcome", "MACHINE requires PASS/FAIL")
        run_pair_digest = _validate_run_pair(
            body["runPair"],
            freeze=freeze,
            criterion=criterion,
            outcome=body["outcome"],
            path="criterionResult.body.runPair",
        )
        if body["runPairDigest"] != run_pair_digest or evidence_digest != run_pair_digest:
            _fail("run_pair_digest_mismatch", "criterionResult.body", "result must bind exact Run A/B pair")
        if body["humanReview"] is not None:
            _fail("unexpected_human_review", "criterionResult.body.humanReview", "only HUMAN uses review metadata")
        role = "protected-workflow"
    elif criterion.kind == "HUMAN":
        if body["outcome"] not in {"APPROVE", "REJECT"}:
            _fail("invalid_criterion_outcome", "criterionResult.body.outcome", "HUMAN requires APPROVE/REJECT")
        if body["runPair"] is not None or body["runPairDigest"] is not None:
            _fail("unexpected_run_pair", "criterionResult.body.runPair", "only MACHINE uses Run A/B")
        review = _exact_keys(
            body["humanReview"],
            {"reason", "conflictOfInterest"},
            "criterionResult.body.humanReview",
        )
        _require_nonempty(review["reason"], "criterionResult.body.humanReview.reason")
        conflict = _exact_keys(
            review["conflictOfInterest"],
            {"independent", "statement"},
            "criterionResult.body.humanReview.conflictOfInterest",
        )
        if conflict["independent"] is not True:
            _fail(
                "reviewer_not_independent",
                "criterionResult.body.humanReview.conflictOfInterest",
                "HUMAN evidence requires an affirmative independence declaration",
            )
        _require_nonempty(
            conflict["statement"],
            "criterionResult.body.humanReview.conflictOfInterest.statement",
        )
        role = authorization.role if authorization is not None else "independent-reviewer"
    else:
        if body["outcome"] != "ATTESTED":
            _fail(
                "external_fact_not_verified",
                "criterionResult.body.outcome",
                "EXTERNAL/TIME generic signatures may only say ATTESTED",
            )
        if body["runPair"] is not None or body["runPairDigest"] is not None:
            _fail("unexpected_run_pair", "criterionResult.body.runPair", "only MACHINE uses Run A/B")
        if body["humanReview"] is not None:
            _fail("unexpected_human_review", "criterionResult.body.humanReview", "only HUMAN uses review metadata")
        role = (
            authorization.role
            if authorization is not None
            else "external-attestor"
            if criterion.kind == "EXTERNAL"
            else "time-attestor"
        )
    _parse_utc(body["issuedAt"], "criterionResult.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=namespace,
        body=body,
        subject=subject,
        expected_role=role,
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    if authorization is not None and (
        signer.principal != authorization.principal
        or signer.role != authorization.role
        or signer.organization != authorization.organization
        or signer.authority_digest != authorization.authority_digest
    ):
        _fail(
            "criterion_authorization_mismatch",
            "criterionAuthorization",
            "verified signer differs from exact criterion grant",
        )
    provisional = VerifiedCriterionResult(
        attestation_digest=digest,
        statement_digest=statement_digest,
        result_id=result_id,
        freeze_digest=freeze.attestation_digest,
        subject=subject,
        criterion=criterion,
        outcome=body["outcome"],
        evidence_digest=evidence_digest,
        run_pair_digest=run_pair_digest,
        signature_verified=True,
        fact_status="not_applicable",
        criterion_satisfied=(
            body["outcome"] == "PASS"
            if criterion.kind == "MACHINE"
            else body["outcome"] == "APPROVE"
            if criterion.kind == "HUMAN"
            else False
        ),
        signer=signer,
    )
    if criterion.kind not in {"EXTERNAL", "TIME"}:
        return _mark_verified(provisional)
    if fact_verifier is None:
        return _mark_verified(VerifiedCriterionResult(
            **{
                **provisional.__dict__,
                "fact_status": "signature_verified_fact_unverified",
                "criterion_satisfied": False,
            }
        ))
    fact = _exact_keys(
        fact_verifier(envelope, provisional),
        {
            "status",
            "kind",
            "criterionId",
            "attestationDigest",
            "evaluator",
            "evaluatorDigest",
            "datasetDigest",
            "factEvidenceDigest",
            "factVerifierDigest",
            "sourceCommit",
            "controlPlaneDigest",
            "contractDigest",
            "satisfied",
        },
        "factVerification",
    )
    exact = {
        "status": "verified",
        "kind": criterion.kind,
        "criterionId": criterion.criterion_id,
        "attestationDigest": digest,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "datasetDigest": criterion.dataset_digest,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "contractDigest": subject.contract_digest,
    }
    if any(fact[key] != value for key, value in exact.items()):
        _fail("external_fact_binding_mismatch", "factVerification", "independent fact proof differs")
    _require_sha256(fact["factEvidenceDigest"], "factVerification.factEvidenceDigest")
    _require_sha256(fact["factVerifierDigest"], "factVerification.factVerifierDigest")
    if not isinstance(fact["satisfied"], bool):
        _fail("invalid_external_fact", "factVerification.satisfied", "must be boolean")
    return _mark_verified(VerifiedCriterionResult(
        **{
            **provisional.__dict__,
            "fact_status": "independently_verified",
            "criterion_satisfied": fact["satisfied"],
        }
    ))


def _required_criterion_kinds(
    from_state: str, to_state: str, freeze: VerifiedProtectedInputFreeze
) -> set[str]:
    available = {item.kind for item in freeze.criteria}
    transition = (from_state, to_state)
    if transition == ("ACTIVE", "MACHINE_CONVERGED"):
        return {"MACHINE"}
    if transition == ("MACHINE_CONVERGED", "WAITING_EXTERNAL"):
        if not available & {"EXTERNAL", "TIME"}:
            _fail("invalid_transition_proof", "proof.body", "no external/time gate is pending")
        return {"MACHINE"}
    if transition == ("MACHINE_CONVERGED", "REVIEW_PENDING"):
        if not available & {"HUMAN"} or available & {"EXTERNAL", "TIME"}:
            _fail("invalid_transition_proof", "proof.body", "criterion kinds do not permit review pending")
        return {"MACHINE"}
    if transition == ("WAITING_EXTERNAL", "REVIEW_PENDING"):
        if not available & {"HUMAN"}:
            _fail("invalid_transition_proof", "proof.body", "no human gate is pending")
        return available - {"HUMAN"}
    if to_state == "CONVERGED" and from_state in {
        "MACHINE_CONVERGED",
        "WAITING_EXTERNAL",
        "REVIEW_PENDING",
    }:
        return available
    _fail("unsupported_transition_proof", "proof.body", "not a convergence transition")


def verify_verified_transition_proof(
    statement: Any,
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_results: Sequence[VerifiedCriterionResult],
    state_context: VerifiedWorkUnitStateContext,
    expected_to_state: str,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedTransitionProofResult:
    """Verify a signed transition proof with an exact, complete criterion set."""

    _require_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    if (
        state_context.phase != freeze.subject.phase
        or state_context.work_unit != freeze.subject.work_unit
        or state_context.control_plane_digest != freeze.subject.control_plane_digest
        or state_context.contract_digest != freeze.subject.contract_digest
    ):
        _fail(
            "state_subject_mismatch",
            "stateContext",
            "verified state context belongs to another unit/control/contract",
        )
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=PROOF_SCHEMA,
        kind=PROOF_KIND,
        namespace=PROOF_NAMESPACE,
        path="proof",
    )
    body = _exact_keys(
        body,
        {
            "proofId",
            "freezeDigest",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "criterionResults",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "proof.body",
    )
    proof_id = _require_nonempty(body["proofId"], "proof.body.proofId", maximum=256)
    if body["freezeDigest"] != freeze.attestation_digest:
        _fail("freeze_digest_mismatch", "proof.body.freezeDigest", "proof uses another freeze")
    subject = _validate_subject(body["subject"], "proof.body.subject")
    _validate_expected_subject(subject, freeze.subject, "proof.body.subject")
    if body["fromState"] != state_context.status or body["toState"] != expected_to_state:
        _fail("transition_replay", "proof.body", "proof is for another transition")
    if (
        body["priorStateDigest"] != state_context.state_digest
        or body["priorChainHeadDigest"] != state_context.chain_head_digest
    ):
        _fail(
            "transition_state_replay",
            "proof.body",
            "proof was issued for another authoritative state or chain head",
        )
    required_kinds = _required_criterion_kinds(
        state_context.status, expected_to_state, freeze
    )
    required_ids = {
        item.criterion_id for item in freeze.criteria if item.kind in required_kinds
    }
    if not isinstance(body["criterionResults"], list):
        _fail("invalid_criterion_results", "proof.body.criterionResults", "must be an array")
    supplied: list[tuple[str, str, str, str]] = []
    for index, item in enumerate(body["criterionResults"]):
        entry = _exact_keys(
            item,
            {"criterionId", "kind", "resultDigest", "evidenceDigest"},
            f"proof.body.criterionResults[{index}]",
        )
        supplied.append(
            (
                entry["criterionId"],
                entry["kind"],
                _require_sha256(entry["resultDigest"], f"proof.body.criterionResults[{index}].resultDigest"),
                _require_sha256(entry["evidenceDigest"], f"proof.body.criterionResults[{index}].evidenceDigest"),
            )
        )
    if [item[0] for item in supplied] != sorted(required_ids) or len(supplied) != len(required_ids):
        _fail(
            "incomplete_criterion_set",
            "proof.body.criterionResults",
            "missing, duplicate, extra, or unordered criterion result",
        )
    results = list(criterion_results)
    for index, result in enumerate(results):
        _require_verified(
            result, VerifiedCriterionResult, f"criterionResults[{index}]"
        )
    result_ids = [item.criterion.criterion_id for item in results]
    if len(set(result_ids)) != len(result_ids) or set(result_ids) != required_ids:
        _fail("incomplete_criterion_set", "criterionResults", "verified result set is not exact")
    by_id = {item.criterion.criterion_id: item for item in results}
    expected_entries: list[tuple[str, str, str, str]] = []
    for criterion_id in sorted(required_ids):
        result = by_id[criterion_id]
        if result.freeze_digest != freeze.attestation_digest or result.subject != freeze.subject:
            _fail("criterion_result_replay", "criterionResults", "result is from another freeze/subject")
        if not result.criterion_satisfied:
            code = (
                "external_fact_not_verified"
                if result.criterion.kind in {"EXTERNAL", "TIME"}
                else "criterion_not_satisfied"
            )
            _fail(code, "criterionResults", f"{criterion_id} is not independently satisfied")
        expected_entries.append(
            (
                criterion_id,
                result.criterion.kind,
                result.attestation_digest,
                result.evidence_digest,
            )
        )
    if supplied != expected_entries:
        _fail("criterion_result_binding_mismatch", "proof.body.criterionResults", "proof projection differs")
    _parse_utc(body["issuedAt"], "proof.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=PROOF_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="protected-workflow",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    return _mark_verified(VerifiedTransitionProofResult(
        attestation_digest=digest,
        statement_digest=statement_digest,
        proof_id=proof_id,
        freeze_digest=freeze.attestation_digest,
        subject=subject,
        from_state=state_context.status,
        to_state=expected_to_state,
        prior_state_digest=state_context.state_digest,
        prior_chain_head_digest=state_context.chain_head_digest,
        criterion_results=tuple(expected_entries),
        signer=signer,
    ))


def verify_transition_approval(
    statement: Any,
    *,
    proof: VerifiedTransitionProofResult,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    now: datetime | None = None,
) -> VerifiedTransitionApprovalResult:
    """Verify a commit/proof-bound independent transition decision."""

    _require_verified(proof, VerifiedTransitionProofResult, "proof")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=TRANSITION_APPROVAL_SCHEMA,
        kind=TRANSITION_APPROVAL_KIND,
        namespace=TRANSITION_APPROVAL_NAMESPACE,
        path="transitionApproval",
    )
    body = _exact_keys(
        body,
        {
            "approvalId",
            "proofDigest",
            "freezeDigest",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "criterionResults",
            "decision",
            "reason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "transitionApproval.body",
    )
    approval_id = _require_nonempty(body["approvalId"], "transitionApproval.body.approvalId", maximum=256)
    if body["proofDigest"] != proof.attestation_digest:
        _fail("proof_digest_mismatch", "transitionApproval.body.proofDigest", "approval replayed for another proof")
    if body["freezeDigest"] != proof.freeze_digest:
        _fail("freeze_digest_mismatch", "transitionApproval.body.freezeDigest", "approval uses another freeze")
    subject = _validate_subject(body["subject"], "transitionApproval.body.subject")
    _validate_expected_subject(subject, proof.subject, "transitionApproval.body.subject")
    if body["fromState"] != proof.from_state or body["toState"] != proof.to_state:
        _fail("transition_replay", "transitionApproval.body", "approval is for another transition")
    if (
        body["priorStateDigest"] != proof.prior_state_digest
        or body["priorChainHeadDigest"] != proof.prior_chain_head_digest
    ):
        _fail(
            "transition_state_replay",
            "transitionApproval.body",
            "approval is for another state or chain head",
        )
    expected_projection = [
        {
            "criterionId": criterion_id,
            "kind": kind,
            "resultDigest": result_digest,
            "evidenceDigest": evidence_digest,
        }
        for criterion_id, kind, result_digest, evidence_digest in proof.criterion_results
    ]
    if body["criterionResults"] != expected_projection:
        _fail("criterion_result_binding_mismatch", "transitionApproval.body.criterionResults", "approval proof projection differs")
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail("invalid_approval_decision", "transitionApproval.body.decision", "must be APPROVE/REJECT")
    _require_nonempty(body["reason"], "transitionApproval.body.reason")
    conflict = _exact_keys(
        body["conflictOfInterest"],
        {"independent", "statement"},
        "transitionApproval.body.conflictOfInterest",
    )
    if conflict["independent"] is not True:
        _fail("reviewer_not_independent", "transitionApproval.body.conflictOfInterest", "independence required")
    _require_nonempty(conflict["statement"], "transitionApproval.body.conflictOfInterest.statement")
    issued_at = _parse_utc(body["issuedAt"], "transitionApproval.body.issuedAt")
    valid_until = _parse_utc(body["validUntil"], "transitionApproval.body.validUntil")
    verification_time = _now_utc(now)
    if issued_at >= valid_until or not issued_at <= verification_time < valid_until:
        _fail("approval_outside_validity", "transitionApproval.body", "approval is not currently valid")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=TRANSITION_APPROVAL_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    return _mark_verified(VerifiedTransitionApprovalResult(
        attestation_digest=digest,
        statement_digest=statement_digest,
        approval_id=approval_id,
        proof_digest=proof.attestation_digest,
        subject=subject,
        from_state=proof.from_state,
        to_state=proof.to_state,
        decision=body["decision"],
        authorized=body["decision"] == "APPROVE",
        signer=signer,
    ))


def authorize_activation_transition(
    *,
    state_context: VerifiedWorkUnitStateContext,
    proof: VerifiedActivationProofResult,
    approval: VerifiedActivationApprovalResult,
) -> VerifiedWorkUnitTransition:
    """Authorize one ordinary READY -> ACTIVE transition from sealed results."""

    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    _require_verified(proof, VerifiedActivationProofResult, "activationProof")
    _require_verified(approval, VerifiedActivationApprovalResult, "activationApproval")
    if state_context.status != "READY":
        _fail("invalid_activation_state", "stateContext", "activation requires READY")
    if (
        proof.subject.phase != state_context.phase
        or proof.subject.work_unit != state_context.work_unit
        or proof.subject.control_plane_digest != state_context.control_plane_digest
        or proof.subject.contract_digest != state_context.contract_digest
        or proof.prior_state_digest != state_context.state_digest
        or proof.prior_chain_head_digest != state_context.chain_head_digest
        or proof.prerequisites != state_context.prerequisites
    ):
        _fail(
            "activation_proof_replay",
            "activationProof",
            "proof does not bind the exact verified READY state",
        )
    if (
        not approval.authorized
        or approval.decision != "APPROVE"
        or approval.proof_digest != proof.attestation_digest
        or approval.subject != proof.subject
    ):
        _fail(
            "activation_not_approved",
            "activationApproval",
            "exact activation proof lacks an independent APPROVE decision",
        )
    return _mark_verified(
        VerifiedWorkUnitTransition(
            transition_type="ACTIVATION",
            subject=proof.subject,
            from_state="READY",
            to_state="ACTIVE",
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            proof_digest=proof.attestation_digest,
            approval_digest=approval.attestation_digest,
            evidence_digest=proof.attestation_digest,
            criterion_result_digests=(),
        )
    )


def authorize_convergence_transition(
    *,
    state_context: VerifiedWorkUnitStateContext,
    freeze: VerifiedProtectedInputFreeze,
    criterion_results: Sequence[VerifiedCriterionResult],
    proof: VerifiedTransitionProofResult,
    approval: VerifiedTransitionApprovalResult,
) -> VerifiedWorkUnitTransition:
    """Authorize a convergence transition without a caller-controlled registry."""

    _require_verified(state_context, VerifiedWorkUnitStateContext, "stateContext")
    _require_verified(freeze, VerifiedProtectedInputFreeze, "freeze")
    _require_verified(proof, VerifiedTransitionProofResult, "proof")
    _require_verified(approval, VerifiedTransitionApprovalResult, "approval")
    results = list(criterion_results)
    for index, result in enumerate(results):
        _require_verified(result, VerifiedCriterionResult, f"criterionResults[{index}]")
    if (
        proof.subject != freeze.subject
        or proof.freeze_digest != freeze.attestation_digest
        or proof.from_state != state_context.status
        or proof.prior_state_digest != state_context.state_digest
        or proof.prior_chain_head_digest != state_context.chain_head_digest
        or proof.subject.phase != state_context.phase
        or proof.subject.work_unit != state_context.work_unit
        or proof.subject.control_plane_digest != state_context.control_plane_digest
        or proof.subject.contract_digest != state_context.contract_digest
    ):
        _fail(
            "convergence_proof_replay",
            "proof",
            "proof/freeze/state unit, commit, control, contract, or chain binding differs",
        )
    actual_projection = sorted(
        (
            result.criterion.criterion_id,
            result.criterion.kind,
            result.attestation_digest,
            result.evidence_digest,
        )
        for result in results
    )
    if tuple(actual_projection) != proof.criterion_results:
        _fail(
            "criterion_result_binding_mismatch",
            "criterionResults",
            "transition did not consume the exact verified proof result set",
        )
    if any(
        result.freeze_digest != freeze.attestation_digest
        or result.subject != freeze.subject
        or not result.criterion_satisfied
        for result in results
    ):
        _fail(
            "criterion_result_replay",
            "criterionResults",
            "criterion result is stale, cross-unit, cross-commit, or unsatisfied",
        )
    if (
        not approval.authorized
        or approval.decision != "APPROVE"
        or approval.proof_digest != proof.attestation_digest
        or approval.subject != proof.subject
        or approval.from_state != proof.from_state
        or approval.to_state != proof.to_state
    ):
        _fail(
            "convergence_not_approved",
            "approval",
            "exact convergence proof lacks an independent APPROVE decision",
        )
    return _mark_verified(
        VerifiedWorkUnitTransition(
            transition_type="CONVERGENCE",
            subject=proof.subject,
            from_state=proof.from_state,
            to_state=proof.to_state,
            prior_state_digest=proof.prior_state_digest,
            prior_chain_head_digest=proof.prior_chain_head_digest,
            proof_digest=proof.attestation_digest,
            approval_digest=approval.attestation_digest,
            evidence_digest=proof.attestation_digest,
            criterion_result_digests=tuple(item[2] for item in proof.criterion_results),
        )
    )


def verify_signed_phase_criterion_result(
    statement: Any,
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    fact_verifier: PhaseFactVerifier | None = None,
    criterion_authorization: Any = None,
    criterion_authorization_adapter: CriterionAuthorizationAdapter | None = None,
) -> VerifiedPhaseCriterionResult:
    """Verify aggregate evidence without introducing a fake work-unit subject."""

    _require_verified(freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze")
    raw_body = statement.get("body") if isinstance(statement, dict) else None
    raw_criterion = raw_body.get("criterion") if isinstance(raw_body, dict) else None
    raw_kind = raw_criterion.get("kind") if isinstance(raw_criterion, dict) else None
    namespace = PHASE_CRITERION_NAMESPACES.get(raw_kind)
    if namespace is None:
        _fail("invalid_criterion_kind", "phaseCriterionResult.body.criterion.kind", "unsupported criterion kind")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=PHASE_CRITERION_SCHEMA,
        kind=PHASE_CRITERION_KIND,
        namespace=namespace,
        path="phaseCriterionResult",
    )
    body = _exact_keys(
        body,
        {
            "resultId",
            "freezeDigest",
            "subject",
            "criterion",
            "outcome",
            "evidenceDigest",
            "runPair",
            "runPairDigest",
            "humanReview",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "phaseCriterionResult.body",
    )
    result_id = _require_nonempty(body["resultId"], "phaseCriterionResult.body.resultId")
    if body["freezeDigest"] != freeze.attestation_digest:
        _fail("freeze_digest_mismatch", "phaseCriterionResult.body.freezeDigest", "freeze replaced")
    subject = _validate_phase_subject(body["subject"], "phaseCriterionResult.body.subject")
    _validate_expected_phase_subject(subject, freeze.subject, "phaseCriterionResult.body.subject")
    criterion = _validate_criterion(body["criterion"], "phaseCriterionResult.body.criterion")
    catalog = {item.criterion_id: item for item in freeze.criteria}
    if catalog.get(criterion.criterion_id) != criterion:
        _fail("criterion_binding_mismatch", "phaseCriterionResult.body.criterion", "criterion differs from freeze")
    if subject.phase == "P00" and criterion.criterion_id == "P00-H-GO-NOGO":
        _fail(
            "go_nogo_requires_multisign",
            "phaseCriterionResult.body.criterion",
            "P00-H-GO-NOGO cannot be satisfied by a single generic HUMAN result",
        )
    authorization: VerifiedCriterionAuthorization | None = None
    if criterion.kind == "MACHINE":
        if criterion_authorization is not None or criterion_authorization_adapter is not None:
            _fail("unexpected_criterion_authorization", "criterionAuthorization", "MACHINE is authorized by protected workflow identity")
    else:
        authorization = _resolve_criterion_authorization(
            criterion_authorization,
            criterion=criterion,
            expected_authority_digest=expected_authority_digest,
            authorization_adapter=criterion_authorization_adapter,
        )
    evidence_digest = _require_sha256(body["evidenceDigest"], "phaseCriterionResult.body.evidenceDigest")
    run_pair_digest: str | None = None
    if criterion.kind == "MACHINE":
        if body["outcome"] not in {"PASS", "FAIL"}:
            _fail("invalid_criterion_outcome", "phaseCriterionResult.body.outcome", "MACHINE requires PASS/FAIL")
        run_pair_digest = _validate_run_pair(
            body["runPair"],
            freeze=freeze,
            criterion=criterion,
            outcome=body["outcome"],
            path="phaseCriterionResult.body.runPair",
        )
        if body["runPairDigest"] != run_pair_digest or evidence_digest != run_pair_digest:
            _fail("run_pair_digest_mismatch", "phaseCriterionResult.body", "result must bind exact Run A/B")
        if body["humanReview"] is not None:
            _fail("unexpected_human_review", "phaseCriterionResult.body.humanReview", "only HUMAN uses review metadata")
        role = "protected-workflow"
    elif criterion.kind == "HUMAN":
        if body["outcome"] not in {"APPROVE", "REJECT"}:
            _fail("invalid_criterion_outcome", "phaseCriterionResult.body.outcome", "HUMAN requires APPROVE/REJECT")
        if body["runPair"] is not None or body["runPairDigest"] is not None:
            _fail("unexpected_run_pair", "phaseCriterionResult.body.runPair", "only MACHINE uses Run A/B")
        review = _exact_keys(
            body["humanReview"],
            {"reason", "conflictOfInterest"},
            "phaseCriterionResult.body.humanReview",
        )
        conflict = _exact_keys(
            review["conflictOfInterest"],
            {"independent", "statement"},
            "phaseCriterionResult.body.humanReview.conflictOfInterest",
        )
        _require_nonempty(review["reason"], "phaseCriterionResult.body.humanReview.reason")
        if conflict["independent"] is not True:
            _fail("reviewer_not_independent", "phaseCriterionResult.body.humanReview", "independence required")
        _require_nonempty(conflict["statement"], "phaseCriterionResult.body.humanReview.conflictOfInterest.statement")
        role = authorization.role if authorization is not None else "independent-reviewer"
    else:
        if body["outcome"] != "ATTESTED":
            _fail("external_fact_not_verified", "phaseCriterionResult.body.outcome", "EXTERNAL/TIME only attest a claim")
        if body["runPair"] is not None or body["runPairDigest"] is not None or body["humanReview"] is not None:
            _fail("unexpected_criterion_metadata", "phaseCriterionResult.body", "EXTERNAL/TIME cannot carry run/review metadata")
        role = (
            authorization.role
            if authorization is not None
            else "external-attestor"
            if criterion.kind == "EXTERNAL"
            else "time-attestor"
        )
    _parse_utc(body["issuedAt"], "phaseCriterionResult.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=namespace,
        body=body,
        subject=subject,
        expected_role=role,
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    if authorization is not None and (
        signer.principal != authorization.principal
        or signer.role != authorization.role
        or signer.organization != authorization.organization
        or signer.authority_digest != authorization.authority_digest
    ):
        _fail("criterion_authorization_mismatch", "criterionAuthorization", "verified signer differs from exact criterion grant")
    provisional = VerifiedPhaseCriterionResult(
        attestation_digest=digest,
        statement_digest=statement_digest,
        result_id=result_id,
        freeze_digest=freeze.attestation_digest,
        subject=subject,
        criterion=criterion,
        outcome=body["outcome"],
        evidence_digest=evidence_digest,
        run_pair_digest=run_pair_digest,
        signature_verified=True,
        fact_status="not_applicable",
        criterion_satisfied=(
            body["outcome"] == "PASS"
            if criterion.kind == "MACHINE"
            else body["outcome"] == "APPROVE"
            if criterion.kind == "HUMAN"
            else False
        ),
        signer=signer,
    )
    if criterion.kind not in {"EXTERNAL", "TIME"}:
        return _mark_verified(provisional)
    if fact_verifier is None:
        return _mark_verified(
            VerifiedPhaseCriterionResult(
                **{
                    **provisional.__dict__,
                    "fact_status": "signature_verified_fact_unverified",
                    "criterion_satisfied": False,
                }
            )
        )
    fact = _exact_keys(
        fact_verifier(envelope, provisional),
        {
            "status",
            "kind",
            "criterionId",
            "attestationDigest",
            "evaluator",
            "evaluatorDigest",
            "datasetDigest",
            "factEvidenceDigest",
            "factVerifierDigest",
            "sourceCommit",
            "controlPlaneDigest",
            "aggregateContractDigest",
            "satisfied",
        },
        "phaseFactVerification",
    )
    exact = {
        "status": "verified",
        "kind": criterion.kind,
        "criterionId": criterion.criterion_id,
        "attestationDigest": digest,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "datasetDigest": criterion.dataset_digest,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "aggregateContractDigest": subject.aggregate_contract_digest,
    }
    if any(fact[key] != value for key, value in exact.items()):
        _fail("external_fact_binding_mismatch", "phaseFactVerification", "independent fact proof differs")
    _require_sha256(fact["factEvidenceDigest"], "phaseFactVerification.factEvidenceDigest")
    _require_sha256(fact["factVerifierDigest"], "phaseFactVerification.factVerifierDigest")
    if not isinstance(fact["satisfied"], bool):
        _fail("invalid_external_fact", "phaseFactVerification.satisfied", "must be boolean")
    return _mark_verified(
        VerifiedPhaseCriterionResult(
            **{
                **provisional.__dict__,
                "fact_status": "independently_verified",
                "criterion_satisfied": fact["satisfied"],
            }
        )
    )


def _required_phase_criterion_ids(
    from_state: str,
    to_state: str,
    freeze: VerifiedPhaseProtectedInputFreeze,
) -> tuple[set[str], str | None]:
    available = {item.kind for item in freeze.criteria}
    by_kind = {
        kind: {item.criterion_id for item in freeze.criteria if item.kind == kind}
        for kind in KINDS
    }
    deferred = (
        "P00-H-GO-NOGO"
        if freeze.subject.phase == "P00"
        and any(item.criterion_id == "P00-H-GO-NOGO" for item in freeze.criteria)
        and to_state == "CONVERGED"
        else None
    )
    transition = (from_state, to_state)
    if transition == ("ACTIVE", "MACHINE_CONVERGED"):
        return by_kind["MACHINE"], None
    if transition == ("MACHINE_CONVERGED", "WAITING_EXTERNAL"):
        if not available & {"EXTERNAL", "TIME"}:
            _fail("invalid_transition_proof", "phaseProof.body", "no external/time gate is pending")
        return by_kind["MACHINE"], None
    if transition == ("MACHINE_CONVERGED", "REVIEW_PENDING"):
        if "HUMAN" not in available or available & {"EXTERNAL", "TIME"}:
            _fail("invalid_transition_proof", "phaseProof.body", "criterion kinds do not permit review pending")
        return by_kind["MACHINE"], None
    if transition == ("WAITING_EXTERNAL", "REVIEW_PENDING"):
        if "HUMAN" not in available:
            _fail("invalid_transition_proof", "phaseProof.body", "no human gate is pending")
        return set().union(*(by_kind[kind] for kind in ("MACHINE", "EXTERNAL", "TIME"))), None
    if to_state == "CONVERGED" and from_state in {
        "MACHINE_CONVERGED",
        "WAITING_EXTERNAL",
        "REVIEW_PENDING",
    }:
        required = {item.criterion_id for item in freeze.criteria}
        if deferred is not None:
            required.remove(deferred)
        return required, deferred
    _fail("unsupported_transition_proof", "phaseProof.body", "not an aggregate convergence transition")


def verify_phase_transition_proof(
    statement: Any,
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_results: Sequence[VerifiedPhaseCriterionResult],
    state_context: VerifiedPhaseStateContext,
    expected_to_state: str,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
) -> VerifiedPhaseTransitionProofResult:
    """Verify a phase aggregate proof bound to five converged P00 units."""

    _require_verified(freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze")
    _require_verified(state_context, VerifiedPhaseStateContext, "phaseStateContext")
    if (
        freeze.subject.phase != state_context.phase
        or freeze.subject.control_plane_digest != state_context.control_plane_digest
        or freeze.subject.aggregate_contract_digest != state_context.aggregate_contract_digest
    ):
        _fail("state_subject_mismatch", "phaseStateContext", "aggregate subject differs from state")
    if expected_to_state not in ALLOWED_TRANSITIONS.get(state_context.status, ()):
        _fail("illegal_state_transition", "phaseProof.body", "aggregate transition is not allowed")
    if any(unit.status != "CONVERGED" for unit in state_context.units):
        _fail("phase_aggregate_incomplete", "phaseStateContext.units", "every phase work unit must be CONVERGED")
    frozen_contracts = dict(freeze.unit_contract_digests)
    if frozen_contracts != {unit.work_unit: unit.contract_digest for unit in state_context.units}:
        _fail("unit_contract_binding_mismatch", "phaseStateContext.units", "state unit contracts differ from freeze")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=PHASE_PROOF_SCHEMA,
        kind=PHASE_PROOF_KIND,
        namespace=PHASE_PROOF_NAMESPACE,
        path="phaseProof",
    )
    body = _exact_keys(
        body,
        {
            "proofId",
            "freezeDigest",
            "subject",
            "fromState",
            "toState",
            "priorStateDigest",
            "priorChainHeadDigest",
            "unitStates",
            "criterionResults",
            "deferredGoNoGoCriterionId",
            "issuedAt",
            "actor",
            "authorityDigest",
        },
        "phaseProof.body",
    )
    proof_id = _require_nonempty(body["proofId"], "phaseProof.body.proofId")
    if body["freezeDigest"] != freeze.attestation_digest:
        _fail("freeze_digest_mismatch", "phaseProof.body.freezeDigest", "proof uses another freeze")
    subject = _validate_phase_subject(body["subject"], "phaseProof.body.subject")
    _validate_expected_phase_subject(subject, freeze.subject, "phaseProof.body.subject")
    if body["fromState"] != state_context.status or body["toState"] != expected_to_state:
        _fail("transition_replay", "phaseProof.body", "proof is for another transition")
    if body["priorStateDigest"] != state_context.state_digest or body["priorChainHeadDigest"] != state_context.chain_head_digest:
        _fail("transition_state_replay", "phaseProof.body", "proof targets another state/head")
    expected_units = [_phase_unit_state_document(unit) for unit in state_context.units]
    if body["unitStates"] != expected_units:
        _fail("phase_unit_binding_mismatch", "phaseProof.body.unitStates", "unit projection differs")
    required_ids, deferred = _required_phase_criterion_ids(
        state_context.status, expected_to_state, freeze
    )
    if body["deferredGoNoGoCriterionId"] != deferred:
        _fail("go_nogo_binding_mismatch", "phaseProof.body.deferredGoNoGoCriterionId", "deferred gate differs")
    if not isinstance(body["criterionResults"], list):
        _fail("invalid_criterion_results", "phaseProof.body.criterionResults", "must be an array")
    supplied: list[tuple[str, str, str, str]] = []
    for index, raw in enumerate(body["criterionResults"]):
        entry = _exact_keys(
            raw,
            {"criterionId", "kind", "resultDigest", "evidenceDigest"},
            f"phaseProof.body.criterionResults[{index}]",
        )
        supplied.append(
            (
                entry["criterionId"],
                entry["kind"],
                _require_sha256(entry["resultDigest"], f"phaseProof.body.criterionResults[{index}].resultDigest"),
                _require_sha256(entry["evidenceDigest"], f"phaseProof.body.criterionResults[{index}].evidenceDigest"),
            )
        )
    if [entry[0] for entry in supplied] != sorted(required_ids) or len(supplied) != len(required_ids):
        _fail("incomplete_criterion_set", "phaseProof.body.criterionResults", "result set is missing, extra, duplicate, or unordered")
    results = list(criterion_results)
    for index, result in enumerate(results):
        _require_verified(result, VerifiedPhaseCriterionResult, f"phaseCriterionResults[{index}]")
    ids = [result.criterion.criterion_id for result in results]
    if len(set(ids)) != len(ids) or set(ids) != required_ids:
        _fail("incomplete_criterion_set", "phaseCriterionResults", "verified result set is not exact")
    by_id = {result.criterion.criterion_id: result for result in results}
    expected_entries: list[tuple[str, str, str, str]] = []
    for criterion_id in sorted(required_ids):
        result = by_id[criterion_id]
        if result.freeze_digest != freeze.attestation_digest or result.subject != freeze.subject:
            _fail("criterion_result_replay", "phaseCriterionResults", "result belongs to another aggregate")
        if not result.criterion_satisfied:
            code = "external_fact_not_verified" if result.criterion.kind in {"EXTERNAL", "TIME"} else "criterion_not_satisfied"
            _fail(code, "phaseCriterionResults", f"{criterion_id} is not satisfied")
        expected_entries.append((criterion_id, result.criterion.kind, result.attestation_digest, result.evidence_digest))
    if supplied != expected_entries:
        _fail("criterion_result_binding_mismatch", "phaseProof.body.criterionResults", "proof projection differs")
    _parse_utc(body["issuedAt"], "phaseProof.body.issuedAt")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=PHASE_PROOF_NAMESPACE,
        body=body,
        subject=subject,
        expected_role="protected-workflow",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedPhaseTransitionProofResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            proof_id=proof_id,
            freeze_digest=freeze.attestation_digest,
            subject=subject,
            from_state=state_context.status,
            to_state=expected_to_state,
            prior_state_digest=state_context.state_digest,
            prior_chain_head_digest=state_context.chain_head_digest,
            unit_states=state_context.units,
            criterion_results=tuple(expected_entries),
            deferred_go_nogo_criterion_id=deferred,
            signer=signer,
        )
    )


def _phase_proof_projection(
    proof: VerifiedPhaseTransitionProofResult,
) -> dict[str, Any]:
    return {
        "freezeDigest": proof.freeze_digest,
        "subject": _phase_subject_document(proof.subject),
        "fromState": proof.from_state,
        "toState": proof.to_state,
        "priorStateDigest": proof.prior_state_digest,
        "priorChainHeadDigest": proof.prior_chain_head_digest,
        "unitStates": [_phase_unit_state_document(unit) for unit in proof.unit_states],
        "criterionResults": [
            {
                "criterionId": criterion_id,
                "kind": kind,
                "resultDigest": result_digest,
                "evidenceDigest": evidence_digest,
            }
            for criterion_id, kind, result_digest, evidence_digest in proof.criterion_results
        ],
        "deferredGoNoGoCriterionId": proof.deferred_go_nogo_criterion_id,
    }


def verify_phase_transition_approval(
    statement: Any,
    *,
    proof: VerifiedPhaseTransitionProofResult,
    expected_authority_digest: str,
    verified_signer_result: VerifiedSignerResult | None = None,
    signer_verifier: SignerVerifier | None = None,
    now: datetime | None = None,
) -> VerifiedPhaseTransitionApprovalResult:
    """Verify an independent decision over the exact aggregate proof."""

    _require_verified(proof, VerifiedPhaseTransitionProofResult, "phaseProof")
    envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
        statement,
        schema=PHASE_APPROVAL_SCHEMA,
        kind=PHASE_APPROVAL_KIND,
        namespace=PHASE_APPROVAL_NAMESPACE,
        path="phaseApproval",
    )
    projection = _phase_proof_projection(proof)
    body = _exact_keys(
        body,
        {
            "approvalId",
            "proofDigest",
            *projection.keys(),
            "decision",
            "reason",
            "conflictOfInterest",
            "issuedAt",
            "validUntil",
            "actor",
            "authorityDigest",
        },
        "phaseApproval.body",
    )
    approval_id = _require_nonempty(body["approvalId"], "phaseApproval.body.approvalId")
    if body["proofDigest"] != proof.attestation_digest:
        _fail("proof_digest_mismatch", "phaseApproval.body.proofDigest", "approval targets another proof")
    if any(body[key] != value for key, value in projection.items()):
        _fail("phase_approval_replay", "phaseApproval.body", "approval projection differs")
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail("invalid_approval_decision", "phaseApproval.body.decision", "must be APPROVE/REJECT")
    _require_nonempty(body["reason"], "phaseApproval.body.reason")
    conflict = _exact_keys(
        body["conflictOfInterest"],
        {"independent", "statement"},
        "phaseApproval.body.conflictOfInterest",
    )
    if conflict["independent"] is not True:
        _fail("reviewer_not_independent", "phaseApproval.body.conflictOfInterest", "independence required")
    _require_nonempty(conflict["statement"], "phaseApproval.body.conflictOfInterest.statement")
    issued_at = _parse_utc(body["issuedAt"], "phaseApproval.body.issuedAt")
    valid_until = _parse_utc(body["validUntil"], "phaseApproval.body.validUntil")
    verification_time = _now_utc(now)
    if issued_at >= valid_until or not issued_at <= verification_time < valid_until:
        _fail("approval_outside_validity", "phaseApproval.body", "approval is not currently valid")
    signer = _resolve_signer(
        payload=payload,
        statement_digest=statement_digest,
        signature=signature,
        namespace=PHASE_APPROVAL_NAMESPACE,
        body=body,
        subject=proof.subject,
        expected_role="independent-reviewer",
        expected_authority_digest=expected_authority_digest,
        verified_signer_result=verified_signer_result,
        signer_verifier=signer_verifier,
    )
    del envelope
    return _mark_verified(
        VerifiedPhaseTransitionApprovalResult(
            attestation_digest=digest,
            statement_digest=statement_digest,
            approval_id=approval_id,
            proof_digest=proof.attestation_digest,
            subject=proof.subject,
            from_state=proof.from_state,
            to_state=proof.to_state,
            decision=body["decision"],
            authorized=body["decision"] == "APPROVE",
            signer=signer,
        )
    )


def verify_phase_go_nogo_authorization(
    statements: Sequence[Any],
    *,
    proof: VerifiedPhaseTransitionProofResult,
    expected_authority_digest: str,
    verified_signer_results: Sequence[VerifiedSignerResult] | None = None,
    signer_verifiers: Sequence[SignerVerifier] | None = None,
    now: datetime | None = None,
) -> VerifiedPhaseGoNoGoAuthorization:
    """Require two real, organization-separated P00 GO/NOGO authorities."""

    _require_verified(proof, VerifiedPhaseTransitionProofResult, "phaseProof")
    documents = list(statements)
    if len(documents) != 2:
        _fail("go_nogo_threshold_not_met", "goNoGo", "exactly two signed authorizations are required")
    if (verified_signer_results is None) == (signer_verifiers is None):
        _fail("signer_verification_required", "goNoGo", "provide one signer verification collection")
    verifiers: list[VerifiedSignerResult | SignerVerifier] = list(
        verified_signer_results if verified_signer_results is not None else signer_verifiers or ()
    )
    if len(verifiers) != 2:
        _fail("go_nogo_threshold_not_met", "goNoGo", "one cryptographic verifier per signature is required")
    if (
        proof.subject.phase != "P00"
        or proof.to_state != "CONVERGED"
        or proof.deferred_go_nogo_criterion_id != "P00-H-GO-NOGO"
    ):
        _fail("go_nogo_binding_mismatch", "phaseProof", "authorization is only for final P00 convergence")
    digests: list[str] = []
    signers: list[VerifiedSignerResult] = []
    authorization_ids: set[str] = set()
    verification_time = _now_utc(now)
    for index, (statement, verifier) in enumerate(zip(documents, verifiers)):
        path = f"goNoGo[{index}]"
        envelope, body, signature, digest, payload, statement_digest = _validate_envelope(
            statement,
            schema=PHASE_GO_NOGO_SCHEMA,
            kind=PHASE_GO_NOGO_KIND,
            namespace=PHASE_GO_NOGO_NAMESPACE,
            path=path,
        )
        body = _exact_keys(
            body,
            {
                "authorizationId",
                "proofDigest",
                "freezeDigest",
                "subject",
                "fromState",
                "toState",
                "priorStateDigest",
                "priorChainHeadDigest",
                "criterionId",
                "decision",
                "reason",
                "conflictOfInterest",
                "issuedAt",
                "validUntil",
                "actor",
                "authorityDigest",
            },
            f"{path}.body",
        )
        authorization_id = _require_nonempty(body["authorizationId"], f"{path}.body.authorizationId")
        if authorization_id in authorization_ids:
            _fail("go_nogo_signature_replay", f"{path}.body.authorizationId", "authorization ID reused")
        authorization_ids.add(authorization_id)
        subject = _validate_phase_subject(body["subject"], f"{path}.body.subject")
        exact = {
            "proofDigest": proof.attestation_digest,
            "freezeDigest": proof.freeze_digest,
            "fromState": proof.from_state,
            "toState": proof.to_state,
            "priorStateDigest": proof.prior_state_digest,
            "priorChainHeadDigest": proof.prior_chain_head_digest,
            "criterionId": "P00-H-GO-NOGO",
            "decision": "APPROVE",
        }
        if any(body[key] != value for key, value in exact.items()):
            _fail("go_nogo_binding_mismatch", f"{path}.body", "signature targets another proof/state/decision")
        _validate_expected_phase_subject(subject, proof.subject, f"{path}.body.subject")
        _require_nonempty(body["reason"], f"{path}.body.reason")
        conflict = _exact_keys(
            body["conflictOfInterest"],
            {"independent", "statement"},
            f"{path}.body.conflictOfInterest",
        )
        if not isinstance(conflict["independent"], bool):
            _fail("invalid_conflict_declaration", f"{path}.body.conflictOfInterest.independent", "must be boolean")
        _require_nonempty(conflict["statement"], f"{path}.body.conflictOfInterest.statement")
        actor = _validate_actor(body["actor"], f"{path}.body.actor")
        role = actor["role"]
        if role not in {"authorized-maintainer", "independent-external-reviewer"}:
            _fail("unauthorized_go_nogo_role", f"{path}.body.actor.role", "role is not a P00 GO/NOGO authority")
        if role == "independent-external-reviewer" and conflict["independent"] is not True:
            _fail("reviewer_not_independent", f"{path}.body.conflictOfInterest", "external reviewer must affirm independence")
        issued_at = _parse_utc(body["issuedAt"], f"{path}.body.issuedAt")
        valid_until = _parse_utc(body["validUntil"], f"{path}.body.validUntil")
        if issued_at >= valid_until or not issued_at <= verification_time < valid_until:
            _fail("approval_outside_validity", f"{path}.body", "authorization is not currently valid")
        signer = _resolve_signer(
            payload=payload,
            statement_digest=statement_digest,
            signature=signature,
            namespace=PHASE_GO_NOGO_NAMESPACE,
            body=body,
            subject=subject,
            expected_role=role,
            expected_authority_digest=expected_authority_digest,
            verified_signer_result=verifier if isinstance(verifier, VerifiedSignerResult) else None,
            signer_verifier=verifier if callable(verifier) else None,
        )
        digests.append(digest)
        signers.append(signer)
        del envelope
    if {signer.role for signer in signers} != {
        "authorized-maintainer",
        "independent-external-reviewer",
    }:
        _fail("go_nogo_role_threshold_not_met", "goNoGo", "both required roles must sign")
    if len({signer.principal for signer in signers}) != 2:
        _fail("go_nogo_principal_not_distinct", "goNoGo", "signers must be distinct principals")
    if len({signer.organization for signer in signers}) != 2:
        _fail("go_nogo_organization_not_distinct", "goNoGo", "signers must be distinct organizations")
    ordered_digests = tuple(sorted(digests))
    authorization_digest = sha256_bytes(
        canonical_json_bytes(
            {
                "kind": "VerifiedPhaseGoNoGoAuthorization",
                "proofDigest": proof.attestation_digest,
                "subject": _phase_subject_document(proof.subject),
                "criterionId": "P00-H-GO-NOGO",
                "decision": "APPROVE",
                "signatureDigests": list(ordered_digests),
            }
        )
    )
    return _mark_verified(
        VerifiedPhaseGoNoGoAuthorization(
            authorization_digest=authorization_digest,
            proof_digest=proof.attestation_digest,
            subject=proof.subject,
            criterion_id="P00-H-GO-NOGO",
            decision="APPROVE",
            signature_digests=ordered_digests,
            signers=tuple(sorted(signers, key=lambda signer: signer.role)),
        )
    )


def authorize_phase_transition(
    *,
    state_context: VerifiedPhaseStateContext,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_results: Sequence[VerifiedPhaseCriterionResult],
    proof: VerifiedPhaseTransitionProofResult,
    approval: VerifiedPhaseTransitionApprovalResult,
    go_nogo_authorization: VerifiedPhaseGoNoGoAuthorization | None = None,
) -> VerifiedPhaseTransition:
    """Authorize a phase aggregate transition from sealed aggregate inputs."""

    _require_verified(state_context, VerifiedPhaseStateContext, "phaseStateContext")
    _require_verified(freeze, VerifiedPhaseProtectedInputFreeze, "phaseFreeze")
    _require_verified(proof, VerifiedPhaseTransitionProofResult, "phaseProof")
    _require_verified(approval, VerifiedPhaseTransitionApprovalResult, "phaseApproval")
    results = list(criterion_results)
    for index, result in enumerate(results):
        _require_verified(result, VerifiedPhaseCriterionResult, f"phaseCriterionResults[{index}]")
    if (
        proof.subject != freeze.subject
        or proof.freeze_digest != freeze.attestation_digest
        or proof.from_state != state_context.status
        or proof.prior_state_digest != state_context.state_digest
        or proof.prior_chain_head_digest != state_context.chain_head_digest
        or proof.subject.phase != state_context.phase
        or proof.subject.control_plane_digest != state_context.control_plane_digest
        or proof.subject.aggregate_contract_digest != state_context.aggregate_contract_digest
        or proof.unit_states != state_context.units
    ):
        _fail("phase_proof_replay", "phaseProof", "proof/freeze/state aggregate binding differs")
    expected_projection = tuple(
        sorted(
            (
                result.criterion.criterion_id,
                result.criterion.kind,
                result.attestation_digest,
                result.evidence_digest,
            )
            for result in results
        )
    )
    if expected_projection != proof.criterion_results:
        _fail("criterion_result_binding_mismatch", "phaseCriterionResults", "proof did not consume exact results")
    if any(
        result.freeze_digest != freeze.attestation_digest
        or result.subject != freeze.subject
        or not result.criterion_satisfied
        for result in results
    ):
        _fail("criterion_result_replay", "phaseCriterionResults", "result is stale, cross-aggregate, or unsatisfied")
    if (
        not approval.authorized
        or approval.decision != "APPROVE"
        or approval.proof_digest != proof.attestation_digest
        or approval.subject != proof.subject
        or approval.from_state != proof.from_state
        or approval.to_state != proof.to_state
    ):
        _fail("phase_not_approved", "phaseApproval", "exact aggregate proof lacks independent APPROVE")
    go_digest: str | None = None
    if proof.subject.phase == "P00" and proof.to_state == "CONVERGED":
        if go_nogo_authorization is None:
            _fail("go_nogo_threshold_not_met", "goNoGo", "P00 convergence requires two-role authorization")
        _require_verified(go_nogo_authorization, VerifiedPhaseGoNoGoAuthorization, "goNoGo")
        if (
            go_nogo_authorization.proof_digest != proof.attestation_digest
            or go_nogo_authorization.subject != proof.subject
            or go_nogo_authorization.criterion_id != "P00-H-GO-NOGO"
            or go_nogo_authorization.decision != "APPROVE"
        ):
            _fail("go_nogo_binding_mismatch", "goNoGo", "authorization belongs to another proof")
        go_digest = go_nogo_authorization.authorization_digest
    elif go_nogo_authorization is not None:
        _fail("unexpected_go_nogo_authorization", "goNoGo", "GO/NOGO is only consumed by final P00 convergence")
    return _mark_verified(
        VerifiedPhaseTransition(
            transition_type="PHASE_AGGREGATE",
            subject=proof.subject,
            from_state=proof.from_state,
            to_state=proof.to_state,
            prior_state_digest=proof.prior_state_digest,
            prior_chain_head_digest=proof.prior_chain_head_digest,
            freeze_digest=freeze.attestation_digest,
            proof_digest=proof.attestation_digest,
            approval_digest=approval.attestation_digest,
            go_nogo_authorization_digest=go_digest,
            evidence_digest=proof.attestation_digest,
            criterion_result_digests=tuple(item[2] for item in proof.criterion_results),
            unit_states=proof.unit_states,
        )
    )
