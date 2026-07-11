"""Raw, independently reverified P00 community EXTERNAL facts.

Canonical evidence contains raw reviewer delegations, revocations, and SSHSIG
statements.  Every FactVerifier invocation rebuilds the effective roster and
reverifies those documents; caller-provided booleans, counts, and digests are
never treated as facts.

Normative sources: Plan section 29.4 and the exact P00.W02/P00.W05 contracts
and gates.  ``execution/protected-verifier/trust-policy.yaml`` remains the only
identity and reviewer-delegation authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
from typing import Any, NoReturn

from .delegation import (
    EffectiveReviewerPrincipal,
    EffectiveReviewerRoster,
    _require_verified,
    authorize_criterion_signer,
)
from .digest import canonical_json_bytes, sha256_bytes
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    EXTERNAL_CRITERION_NAMESPACE,
    CriterionBinding,
    SubjectBinding,
    VerifiedCriterionResult,
)
from .sshsig import SshSigVerificationError, verify_sshsig


EVIDENCE_SCHEMA = "urn:agentapi-doctor:p00-community-fact-evidence:v1alpha1"
EVIDENCE_KIND = "P00CommunityFactEvidence"
STATEMENT_SCHEMA = "urn:agentapi-doctor:p00-community-fact-statement:v1alpha1"

OUTREACH = "P00-X-OUTREACH"
DESIGN_PARTNERS = "P00-X-DESIGN-PARTNERS"
REVIEW = "P00-X-REVIEW"

OUTREACH_KIND = "OutreachDispatchReceipt"
DESIGN_PARTNER_KIND = "DesignPartnerWillingness"
REVIEW_KIND = "IndependentExternalReviewFeedback"

OUTREACH_NAMESPACE = "agentapi-doctor/community-fact/outreach/v1"
DESIGN_PARTNER_NAMESPACE = "agentapi-doctor/community-fact/design-partner/v1"
REVIEW_NAMESPACE = "agentapi-doctor/community-fact/external-review/v1"

CRITERION_SPECS: dict[str, dict[str, str]] = {
    OUTREACH: {
        "phase": "P00",
        "workUnit": "P00.W02",
        "evaluator": "attestation://upstream/outreach/v1",
        "evidenceSchema": "evidence-schema://attestation/external-review/v1",
        "statementKind": OUTREACH_KIND,
        "namespace": OUTREACH_NAMESPACE,
    },
    DESIGN_PARTNERS: {
        "phase": "P00",
        "workUnit": "P00.W02",
        "evaluator": "attestation://review/design-partners/v1",
        "evidenceSchema": "evidence-schema://attestation/design-partners/v1",
        "statementKind": DESIGN_PARTNER_KIND,
        "namespace": DESIGN_PARTNER_NAMESPACE,
    },
    REVIEW: {
        "phase": "P00",
        "workUnit": "P00.W05",
        "evaluator": "attestation://review/external-feedback/v1",
        "evidenceSchema": "evidence-schema://attestation/external-review/v1",
        "statementKind": REVIEW_KIND,
        "namespace": REVIEW_NAMESPACE,
    },
}
SUPPORTED_CRITERIA = frozenset(CRITERION_SPECS)

FACT_VERIFIER_SPEC = {
    "schemaVersion": "urn:agentapi-doctor:p00-community-fact-verifier:v1alpha1",
    "kind": "P00CommunityFactVerifier",
    "criteria": {
        OUTREACH: {
            "threshold": (
                "one SENT dispatch with a DELIVERED receipt, jointly signed by "
                "a static authorized maintainer and the delegated external recipient"
            ),
            "sources": [
                "agentapi-doctor-Plan.md section 34 P00-X-OUTREACH",
                "execution/work-units/P00.W02.yaml P00-X-OUTREACH",
                "execution/gates/p00/P00.W02.yaml P00-X-OUTREACH",
            ],
        },
        DESIGN_PARTNERS: {
            "threshold": (
                "three distinct delegated principals and organizations, each "
                "signing explicit REVIEW/TRY willingness"
            ),
            "sources": [
                "agentapi-doctor-Plan.md section 34 P00-X-DESIGN-PARTNERS",
                "execution/work-units/P00.W02.yaml P00-X-DESIGN-PARTNERS",
                "execution/gates/p00/P00.W02.yaml P00-X-DESIGN-PARTNERS",
            ],
        },
        REVIEW: {
            "threshold": (
                "one independent-external-reviewer with independent COI and "
                "substantive feedback, plus a distinct external-attestor on the "
                "outer criterion result"
            ),
            "sources": [
                "agentapi-doctor-Plan.md section 34 P00-X-REVIEW",
                "execution/work-units/P00.W05.yaml P00-X-REVIEW",
                "execution/gates/p00/P00.W05.yaml P00-X-REVIEW",
            ],
        },
    },
    "identityAuthority": (
        "execution/protected-verifier/trust-policy.yaml reviewerDelegation"
    ),
    "authorizationInput": (
        "fresh identity-sealed EffectiveReviewerRoster rebuilt by the outer "
        "serialized importer from its complete delegation/revocation lists"
    ),
    "rawEvidenceAuthorizationLists": "forbidden",
    "signatureNamespaces": {
        OUTREACH: OUTREACH_NAMESPACE,
        DESIGN_PARTNERS: DESIGN_PARTNER_NAMESPACE,
        REVIEW: REVIEW_NAMESPACE,
    },
}
FACT_VERIFIER_DIGEST = sha256_bytes(canonical_json_bytes(FACT_VERIFIER_SPEC))

MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_STATEMENTS = 32
MAX_FEEDBACK_ITEMS = 32
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CHANNELS = frozenset({"email", "github", "matrix", "other-reviewed"})
COMMITMENTS = frozenset({"REVIEW", "TRY", "REVIEW_AND_TRY"})

FactVerifier = Callable[[Mapping[str, Any], VerifiedCriterionResult], Mapping[str, Any]]


class CommunityFactError(ProtectedVerificationError):
    """Stable, secret-free community fact verification failure."""


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise CommunityFactError(code, path, message)


def _exact(value: Any, fields: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(
            "invalid_community_fact_schema",
            path,
            "field set differs from the versioned schema",
        )
    return value


def _text(
    value: Any,
    path: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
) -> str:
    if (
        not isinstance(value, str)
        or len(value.strip()) < minimum
        or len(value) > maximum
        or "\x00" in value
    ):
        _fail("invalid_community_fact", path, "invalid bounded non-empty string")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        _fail("invalid_community_fact", path, "invalid bounded identifier")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_community_fact_digest", path, "invalid SHA-256 digest")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_community_fact_source", path, "invalid Git commit")
    return value


def _time(value: Any, path: str) -> datetime:
    raw = _text(value, path, maximum=64)
    if UTC_RE.fullmatch(raw) is None:
        _fail(
            "invalid_community_fact_time",
            path,
            "timestamp must be second-precision RFC3339 UTC",
        )
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _fail("invalid_community_fact_time", path, "invalid timestamp")
    if parsed.tzinfo is None:
        _fail("invalid_community_fact_time", path, "timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _fixed_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(
            "invalid_community_fact_time",
            "verificationTime",
            "timezone-aware datetime required",
        )
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail(
            "invalid_community_fact_time",
            "verificationTime",
            "second precision required",
        )
    return normalized


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail(
                "duplicate_community_fact_key",
                "communityFactEvidence",
                "duplicate JSON key",
            )
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    _fail(
        "invalid_community_fact_json",
        "communityFactEvidence",
        "non-finite JSON number",
    )


def _subject_document(subject: SubjectBinding) -> dict[str, str]:
    return {
        "phase": subject.phase,
        "workUnit": subject.work_unit,
        "sourceCommit": subject.source_commit,
        "controlPlaneDigest": subject.control_plane_digest,
        "contractDigest": subject.contract_digest,
    }


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


def _validate_subject(value: Any, path: str, *, criterion_id: str) -> Mapping[str, Any]:
    subject = _exact(
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
    spec = CRITERION_SPECS[criterion_id]
    if subject["phase"] != spec["phase"] or subject["workUnit"] != spec["workUnit"]:
        _fail(
            "community_fact_subject_mismatch",
            path,
            "criterion belongs to a different P00 work unit",
        )
    _commit(subject["sourceCommit"], f"{path}.sourceCommit")
    _digest(subject["controlPlaneDigest"], f"{path}.controlPlaneDigest")
    _digest(subject["contractDigest"], f"{path}.contractDigest")
    return subject


def _validate_criterion(
    value: Any, path: str, *, criterion_id: str
) -> Mapping[str, Any]:
    criterion = _exact(
        value,
        {
            "id",
            "kind",
            "evaluator",
            "evaluatorDigest",
            "evaluatorStatus",
            "evidenceSchema",
            "evidenceSchemaDigest",
            "datasetDigest",
            "thresholdDigest",
        },
        path,
    )
    spec = CRITERION_SPECS[criterion_id]
    exact = {
        "id": criterion_id,
        "kind": "EXTERNAL",
        "evaluator": spec["evaluator"],
        "evaluatorStatus": "external-only",
        "evidenceSchema": spec["evidenceSchema"],
    }
    if any(criterion.get(key) != expected for key, expected in exact.items()):
        _fail(
            "community_fact_criterion_mismatch",
            path,
            "criterion/evaluator/schema differs from the protected P00 definition",
        )
    for field in (
        "evaluatorDigest",
        "evidenceSchemaDigest",
        "datasetDigest",
        "thresholdDigest",
    ):
        _digest(criterion[field], f"{path}.{field}")
    return criterion


def _ordered_documents(
    value: Any,
    *,
    path: str,
    id_field: str,
    maximum: int,
    nonempty: bool,
) -> Sequence[Any]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or len(value) > maximum
        or (nonempty and not value)
    ):
        _fail(
            "invalid_community_fact_documents",
            path,
            "invalid bounded signed-document array",
        )
    identities: list[str] = []
    for index, document in enumerate(value):
        body = document.get("body") if isinstance(document, Mapping) else None
        identity = body.get(id_field) if isinstance(body, Mapping) else None
        identities.append(_identifier(identity, f"{path}[{index}].body.{id_field}"))
    if identities != sorted(set(identities)):
        _fail(
            "duplicate_or_unsorted_community_fact_document",
            path,
            "signed documents must be sorted and unique by ID",
        )
    return value


def _validate_evidence(value: Any) -> Mapping[str, Any]:
    evidence = _exact(
        value,
        {
            "schemaVersion",
            "kind",
            "criterionId",
            "policyDigest",
            "priorChainHeadDigest",
            "freezeDigest",
            "subject",
            "criterion",
            "statements",
            "factEvidenceDigest",
        },
        "communityFactEvidence",
    )
    if (
        evidence["schemaVersion"] != EVIDENCE_SCHEMA
        or evidence["kind"] != EVIDENCE_KIND
    ):
        _fail(
            "unsupported_community_fact_evidence",
            "communityFactEvidence",
            "unsupported schema or kind",
        )
    criterion_id = evidence["criterionId"]
    if criterion_id not in CRITERION_SPECS:
        _fail(
            "unsupported_community_fact_criterion",
            "communityFactEvidence.criterionId",
            "criterion has no approved community fact model",
        )
    _digest(evidence["policyDigest"], "communityFactEvidence.policyDigest")
    _digest(
        evidence["priorChainHeadDigest"],
        "communityFactEvidence.priorChainHeadDigest",
    )
    _digest(evidence["freezeDigest"], "communityFactEvidence.freezeDigest")
    _validate_subject(
        evidence["subject"], "communityFactEvidence.subject", criterion_id=criterion_id
    )
    _validate_criterion(
        evidence["criterion"],
        "communityFactEvidence.criterion",
        criterion_id=criterion_id,
    )
    _ordered_documents(
        evidence["statements"],
        path="communityFactEvidence.statements",
        id_field="statementId",
        maximum=MAX_STATEMENTS,
        nonempty=True,
    )
    _digest(
        evidence["factEvidenceDigest"],
        "communityFactEvidence.factEvidenceDigest",
    )
    return evidence


def community_fact_evidence_digest(document: Mapping[str, Any]) -> str:
    """Digest the exact raw evidence, excluding only its digest field."""

    evidence = _validate_evidence(document)
    return document_digest(evidence, omit_field="factEvidenceDigest")


def serialize_community_fact_evidence(document: Mapping[str, Any]) -> bytes:
    """Canonicalize a candidate and mechanically fill its evidence digest."""

    projected = deepcopy(document)
    _validate_evidence(projected)
    projected["factEvidenceDigest"] = document_digest(
        projected, omit_field="factEvidenceDigest"
    )
    return canonical_json_bytes(projected)


def _load(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EVIDENCE_BYTES:
        _fail(
            "invalid_community_fact_size",
            "communityFactEvidence",
            "canonical evidence bytes are empty or oversized",
        )
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except CommunityFactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail(
            "invalid_community_fact_json",
            "communityFactEvidence",
            "evidence is not strict UTF-8 JSON",
        )
    if not isinstance(value, Mapping):
        _fail(
            "invalid_community_fact_schema",
            "communityFactEvidence",
            "top level must be an object",
        )
    if raw != canonical_json_bytes(value):
        _fail(
            "noncanonical_community_fact",
            "communityFactEvidence",
            "evidence bytes must be exact canonical JSON",
        )
    evidence = _validate_evidence(value)
    if evidence["factEvidenceDigest"] != community_fact_evidence_digest(evidence):
        _fail(
            "community_fact_digest_mismatch",
            "communityFactEvidence.factEvidenceDigest",
            "declared digest differs from exact raw evidence",
        )
    return evidence


def _require_result(
    envelope: Mapping[str, Any],
    result: VerifiedCriterionResult,
    evidence: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_prior_chain_head_digest: str,
) -> None:
    if not isinstance(result, VerifiedCriterionResult) or not isinstance(
        envelope, Mapping
    ):
        _fail(
            "invalid_community_fact_result",
            "criterionResult",
            "fresh VerifiedCriterionResult and raw envelope required",
        )
    body = envelope.get("body")
    if not isinstance(body, Mapping):
        _fail(
            "invalid_community_fact_result",
            "criterionResult.body",
            "criterion body required",
        )
    if (
        envelope.get("attestationDigest") != result.attestation_digest
        or body.get("evidenceDigest") != result.evidence_digest
        or result.evidence_digest != evidence["factEvidenceDigest"]
    ):
        _fail(
            "community_fact_attestation_mismatch",
            "criterionResult",
            "criterion result and raw fact evidence differ",
        )
    if (
        result.outcome != "ATTESTED"
        or result.signature_verified is not True
        or result.criterion.kind != "EXTERNAL"
    ):
        _fail(
            "invalid_community_fact_result",
            "criterionResult",
            "signature-verified EXTERNAL ATTESTED result required",
        )
    if evidence["criterionId"] != result.criterion.criterion_id:
        _fail(
            "community_fact_criterion_mismatch",
            "communityFactEvidence.criterionId",
            "evidence belongs to another criterion",
        )
    if evidence["subject"] != _subject_document(result.subject):
        _fail(
            "community_fact_subject_mismatch",
            "communityFactEvidence.subject",
            "source/control/contract binding differs",
        )
    if evidence["criterion"] != _criterion_document(result.criterion):
        _fail(
            "community_fact_criterion_mismatch",
            "communityFactEvidence.criterion",
            "frozen criterion binding differs",
        )
    if evidence["freezeDigest"] != result.freeze_digest:
        _fail(
            "community_fact_freeze_mismatch",
            "communityFactEvidence.freezeDigest",
            "evidence belongs to another protected-input freeze",
        )
    if evidence["policyDigest"] != expected_policy_digest:
        _fail(
            "community_fact_policy_mismatch",
            "communityFactEvidence.policyDigest",
            "evidence belongs to another trust policy",
        )
    if evidence["priorChainHeadDigest"] != expected_prior_chain_head_digest:
        _fail(
            "community_fact_chain_mismatch",
            "communityFactEvidence.priorChainHeadDigest",
            "evidence belongs to another chain head",
        )
    if (
        result.signer.namespace != EXTERNAL_CRITERION_NAMESPACE
        or result.signer.source_commit != result.subject.source_commit
        or result.signer.control_plane_digest != result.subject.control_plane_digest
    ):
        _fail(
            "community_fact_signer_mismatch",
            "criterionResult.signer",
            "outer signer binding differs",
        )


def _require_roster(
    roster: EffectiveReviewerRoster,
    evidence: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_prior_chain_head_digest: str,
) -> EffectiveReviewerRoster:
    try:
        _require_verified(roster, EffectiveReviewerRoster, "reviewerRoster")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    expected = (
        expected_policy_digest,
        evidence["subject"]["controlPlaneDigest"],
        evidence["subject"]["sourceCommit"],
        expected_prior_chain_head_digest,
    )
    actual = (
        roster.policy_digest,
        roster.control_plane_digest,
        roster.source_commit,
        roster.prior_chain_head_digest,
    )
    if actual != expected:
        _fail(
            "community_fact_roster_mismatch",
            "reviewerRoster",
            "outer importer roster belongs to another policy/control/source/chain",
        )
    return roster


def _require_namespace_policy(
    policy_result: Mapping[str, Any], *, criterion_id: str, expected_policy_digest: str
) -> None:
    document = policy_result.get("document")
    if (
        not isinstance(document, Mapping)
        or policy_result.get("digest") != expected_policy_digest
        or document_digest(document) != expected_policy_digest
    ):
        _fail(
            "community_fact_policy_mismatch",
            "policyResult",
            "validated policy document/digest differs",
        )
    signature_schemes = document.get("signatureSchemes")
    human = (
        signature_schemes.get("human")
        if isinstance(signature_schemes, Mapping)
        else None
    )
    namespaces = human.get("namespaces") if isinstance(human, Mapping) else None
    expected_namespace = CRITERION_SPECS[criterion_id]["namespace"]
    if not isinstance(namespaces, Mapping) or expected_namespace not in set(
        namespaces.values()
    ):
        _fail(
            "community_fact_namespace_not_approved",
            "policyResult.document.signatureSchemes.human.namespaces",
            "dedicated nested statement namespace is not approved",
        )
    revoked = policy_result.get("revokedFingerprints")
    declared_revoked = document.get("revokedFingerprints")
    if (
        not isinstance(revoked, set)
        or not isinstance(declared_revoked, list)
        or revoked != set(declared_revoked)
    ):
        _fail(
            "invalid_policy_result",
            "policyResult.revokedFingerprints",
            "validated revocation projection differs from the policy document",
        )


def _principal(
    roster: EffectiveReviewerRoster, identity: str
) -> EffectiveReviewerPrincipal:
    selected = next(
        (
            principal
            for principal in roster.principals
            if principal.identity == identity
        ),
        None,
    )
    if selected is None:
        _fail("signer_not_allowed", "principal", "identity is not in fresh roster")
    return selected


def _statement(
    value: Any,
    *,
    kind: str,
    multiple_signatures: bool,
    path: str,
) -> tuple[Mapping[str, Any], bytes, Any]:
    signature_field = "signatures" if multiple_signatures else "signature"
    document = _exact(
        value,
        {"schemaVersion", "kind", "body", signature_field, "attestationDigest"},
        path,
    )
    if document["schemaVersion"] != STATEMENT_SCHEMA or document["kind"] != kind:
        _fail(
            "unsupported_community_statement",
            path,
            "statement schema or kind differs",
        )
    _digest(document["attestationDigest"], f"{path}.attestationDigest")
    if document["attestationDigest"] != document_digest(
        document, omit_field="attestationDigest"
    ):
        _fail(
            "community_statement_digest_mismatch",
            f"{path}.attestationDigest",
            "statement digest differs",
        )
    body = document["body"]
    if not isinstance(body, Mapping):
        _fail("invalid_community_fact_schema", f"{path}.body", "body must be object")
    payload = canonical_json_bytes(
        {
            "schemaVersion": document["schemaVersion"],
            "kind": document["kind"],
            "body": body,
        }
    )
    return body, payload, document[signature_field]


def _common_body(
    body: Mapping[str, Any],
    *,
    evidence: Mapping[str, Any],
    path: str,
) -> datetime:
    _identifier(body["statementId"], f"{path}.statementId")
    if body["freezeDigest"] != evidence["freezeDigest"]:
        _fail(
            "community_fact_freeze_mismatch",
            f"{path}.freezeDigest",
            "statement belongs to another freeze",
        )
    if body["subject"] != evidence["subject"]:
        _fail(
            "community_fact_subject_mismatch",
            f"{path}.subject",
            "statement belongs to another source/control/contract",
        )
    if body["criterionId"] != evidence["criterionId"]:
        _fail(
            "community_fact_criterion_mismatch",
            f"{path}.criterionId",
            "statement belongs to another criterion",
        )
    return _time(body["issuedAt"], f"{path}.issuedAt")


def _external_signature(
    *,
    roster: EffectiveReviewerRoster,
    evidence: Mapping[str, Any],
    payload: bytes,
    signature: Any,
    actor: Any,
    actor_role: str,
    issued_at: datetime,
    verification_time: datetime,
    path: str,
) -> EffectiveReviewerPrincipal:
    actor = _exact(
        actor,
        {"principal", "organization", "role"},
        f"{path}.body.actor",
    )
    if actor["role"] != actor_role:
        _fail(
            "community_statement_actor_mismatch",
            f"{path}.body.actor.role",
            "statement actor role differs",
        )
    descriptor = _exact(
        signature,
        {"scheme", "namespace", "principal", "value"},
        f"{path}.signature",
    )
    expected_namespace = CRITERION_SPECS[evidence["criterionId"]]["namespace"]
    if (
        descriptor["scheme"] != "openssh-sshsig-v1"
        or descriptor["namespace"] != expected_namespace
    ):
        _fail(
            "signature_namespace_mismatch",
            f"{path}.signature",
            "nested statement must use its dedicated SSHSIG namespace",
        )
    try:
        authorization = authorize_criterion_signer(
            roster,
            principal=descriptor["principal"],
            criterion_id=evidence["criterionId"],
            required_role=actor_role,
            required_capability="attest-external-result",
            at=verification_time,
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    selected = _principal(roster, authorization.principal)
    if (
        actor["principal"] != authorization.principal
        or actor["organization"] != authorization.organization
    ):
        _fail(
            "community_statement_actor_mismatch",
            f"{path}.body.actor",
            "actor differs from verified SSH principal",
        )
    if not (
        _time(selected.valid_from, f"{path}.signer.validFrom")
        <= issued_at
        < _time(selected.valid_until, f"{path}.signer.validUntil")
    ):
        _fail(
            "signer_outside_validity",
            f"{path}.signature",
            "signer was not valid when the statement was issued",
        )
    try:
        verify_sshsig(
            payload,
            armored_signature=descriptor["value"],
            public_key=selected.public_key,
            expected_namespace=expected_namespace,
        )
    except SshSigVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return selected


def _maintainer_signature(
    *,
    roster: EffectiveReviewerRoster,
    policy_result: Mapping[str, Any],
    payload: bytes,
    signature: Any,
    actor: Any,
    expected_namespace: str,
    issued_at: datetime,
    verification_time: datetime,
    path: str,
) -> EffectiveReviewerPrincipal:
    descriptor = _exact(
        signature,
        {"scheme", "namespace", "principal", "value"},
        f"{path}.signatures.maintainer",
    )
    if (
        descriptor["scheme"] != "openssh-sshsig-v1"
        or descriptor["namespace"] != expected_namespace
    ):
        _fail(
            "signature_namespace_mismatch",
            f"{path}.signatures.maintainer",
            "maintainer must sign in the dedicated outreach SSHSIG domain",
        )
    selected = _principal(roster, descriptor["principal"])
    if selected.origin != "policy" or "authorized-maintainer" not in selected.roles:
        _fail(
            "maintainer_not_authorized",
            f"{path}.signatures.maintainer.principal",
            "outreach requires a static authorized maintainer",
        )
    revoked = policy_result.get("revokedFingerprints")
    if not isinstance(revoked, set) or selected.fingerprint in revoked:
        _fail(
            "maintainer_revoked",
            f"{path}.signatures.maintainer.principal",
            "maintainer key is revoked or revocation policy unavailable",
        )
    actor = _exact(
        actor,
        {"principal", "organization", "role"},
        f"{path}.body.maintainer",
    )
    if actor != {
        "principal": selected.identity,
        "organization": selected.organization,
        "role": "authorized-maintainer",
    }:
        _fail(
            "community_statement_actor_mismatch",
            f"{path}.body.maintainer",
            "maintainer actor differs",
        )
    valid_from = _time(selected.valid_from, f"{path}.maintainer.validFrom")
    valid_until = _time(selected.valid_until, f"{path}.maintainer.validUntil")
    if not (
        valid_from <= issued_at < valid_until
        and valid_from <= verification_time < valid_until
    ):
        _fail(
            "maintainer_outside_validity",
            f"{path}.signatures.maintainer",
            "maintainer is outside validity",
        )
    try:
        verify_sshsig(
            payload,
            armored_signature=descriptor["value"],
            public_key=selected.public_key,
            expected_namespace=expected_namespace,
        )
    except SshSigVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return selected


def _coi(value: Any, path: str) -> None:
    conflict = _exact(value, {"independent", "statement"}, path)
    if conflict["independent"] is not True:
        _fail(
            "community_reviewer_not_independent",
            f"{path}.independent",
            "independence must be explicitly affirmed",
        )
    _text(conflict["statement"], f"{path}.statement", minimum=8, maximum=1024)


def _verify_outreach(
    evidence: Mapping[str, Any],
    *,
    roster: EffectiveReviewerRoster,
    policy_result: Mapping[str, Any],
    verification_time: datetime,
) -> set[str]:
    if len(evidence["statements"]) != 1:
        _fail(
            "outreach_receipt_count_mismatch",
            "communityFactEvidence.statements",
            "exactly one signed dispatch receipt required",
        )
    path = "communityFactEvidence.statements[0]"
    body, payload, signatures = _statement(
        evidence["statements"][0],
        kind=OUTREACH_KIND,
        multiple_signatures=True,
        path=path,
    )
    body = _exact(
        body,
        {
            "statementId",
            "freezeDigest",
            "subject",
            "criterionId",
            "contentDigest",
            "scope",
            "recipient",
            "channel",
            "dispatchStatus",
            "sentAt",
            "receipt",
            "issuedAt",
            "maintainer",
            "externalAttestor",
        },
        f"{path}.body",
    )
    issued_at = _common_body(body, evidence=evidence, path=f"{path}.body")
    if issued_at > verification_time:
        _fail("future_community_statement", f"{path}.body.issuedAt", "future statement")
    _digest(body["contentDigest"], f"{path}.body.contentDigest")
    _text(body["scope"], f"{path}.body.scope", minimum=8, maximum=1024)
    if body["channel"] not in CHANNELS:
        _fail("invalid_outreach_channel", f"{path}.body.channel", "invalid channel")
    if body["dispatchStatus"] != "SENT":
        _fail(
            "outreach_not_sent",
            f"{path}.body.dispatchStatus",
            "draft or queued outreach is not sent",
        )
    receipt = _exact(
        body["receipt"],
        {"receiptId", "status", "receivedAt"},
        f"{path}.body.receipt",
    )
    _identifier(receipt["receiptId"], f"{path}.body.receipt.receiptId")
    if receipt["status"] != "DELIVERED":
        _fail(
            "outreach_receipt_not_delivered",
            f"{path}.body.receipt.status",
            "receipt must affirm delivery",
        )
    sent_at = _time(body["sentAt"], f"{path}.body.sentAt")
    received_at = _time(receipt["receivedAt"], f"{path}.body.receipt.receivedAt")
    if not sent_at <= received_at <= issued_at <= verification_time:
        _fail(
            "invalid_outreach_timeline",
            f"{path}.body",
            "dispatch, receipt, issuance, and verification times are inconsistent",
        )
    signatures = _exact(
        signatures,
        {"maintainer", "externalAttestor"},
        f"{path}.signatures",
    )
    maintainer = _maintainer_signature(
        roster=roster,
        policy_result=policy_result,
        payload=payload,
        signature=signatures["maintainer"],
        actor=body["maintainer"],
        expected_namespace=OUTREACH_NAMESPACE,
        issued_at=issued_at,
        verification_time=verification_time,
        path=path,
    )
    external = _external_signature(
        roster=roster,
        evidence=evidence,
        payload=payload,
        signature=signatures["externalAttestor"],
        actor=body["externalAttestor"],
        actor_role="external-attestor",
        issued_at=issued_at,
        verification_time=verification_time,
        path=path,
    )
    recipient = _exact(
        body["recipient"],
        {"principal", "organization"},
        f"{path}.body.recipient",
    )
    if recipient != {
        "principal": external.identity,
        "organization": external.organization,
    }:
        _fail(
            "outreach_recipient_mismatch",
            f"{path}.body.recipient",
            "delivery receipt signer must be the scoped recipient",
        )
    if (
        maintainer.identity == external.identity
        or maintainer.organization == external.organization
    ):
        _fail(
            "outreach_signer_separation_failed",
            path,
            "maintainer and external receipt signer must be independent",
        )
    return {external.identity}


def _verify_design_partners(
    evidence: Mapping[str, Any],
    *,
    roster: EffectiveReviewerRoster,
    verification_time: datetime,
) -> set[str]:
    if not 3 <= len(evidence["statements"]) <= 16:
        _fail(
            "insufficient_design_partners",
            "communityFactEvidence.statements",
            "at least three willingness statements required",
        )
    principals: list[str] = []
    organizations: list[str] = []
    for index, raw_statement in enumerate(evidence["statements"]):
        path = f"communityFactEvidence.statements[{index}]"
        body, payload, signature = _statement(
            raw_statement,
            kind=DESIGN_PARTNER_KIND,
            multiple_signatures=False,
            path=path,
        )
        body = _exact(
            body,
            {
                "statementId",
                "freezeDigest",
                "subject",
                "criterionId",
                "commitment",
                "scope",
                "maintainerOf",
                "conflictOfInterest",
                "issuedAt",
                "actor",
            },
            f"{path}.body",
        )
        issued_at = _common_body(body, evidence=evidence, path=f"{path}.body")
        if issued_at > verification_time:
            _fail(
                "future_community_statement",
                f"{path}.body.issuedAt",
                "future statement",
            )
        if body["commitment"] not in COMMITMENTS:
            _fail(
                "design_partner_not_willing",
                f"{path}.body.commitment",
                "statement must explicitly agree to REVIEW or TRY",
            )
        _text(body["scope"], f"{path}.body.scope", minimum=8, maximum=1024)
        _text(body["maintainerOf"], f"{path}.body.maintainerOf", minimum=2, maximum=512)
        _coi(body["conflictOfInterest"], f"{path}.body.conflictOfInterest")
        signer = _external_signature(
            roster=roster,
            evidence=evidence,
            payload=payload,
            signature=signature,
            actor=body["actor"],
            actor_role="external-attestor",
            issued_at=issued_at,
            verification_time=verification_time,
            path=path,
        )
        if signer.origin != "delegation":
            _fail(
                "design_partner_not_external",
                f"{path}.body.actor",
                "design partner must be independently delegated",
            )
        principals.append(signer.identity)
        organizations.append(signer.organization)
    if len(principals) != len(set(principals)):
        _fail(
            "duplicate_design_partner_principal",
            "communityFactEvidence.statements",
            "design partners must have distinct principals",
        )
    if len(organizations) != len(set(organizations)):
        _fail(
            "duplicate_design_partner_organization",
            "communityFactEvidence.statements",
            "design partners must represent distinct organizations",
        )
    return set(principals)


def _feedback_manifest(value: Any, path: str) -> None:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or not value
        or len(value) > MAX_FEEDBACK_ITEMS
    ):
        _fail(
            "empty_external_feedback",
            path,
            "substantive feedback manifest must be nonempty and bounded",
        )
    identifiers: list[str] = []
    for index, raw_item in enumerate(value):
        item_path = f"{path}[{index}]"
        item = _exact(
            raw_item,
            {
                "itemId",
                "reviewedArtifactDigest",
                "feedbackDigest",
                "summary",
                "recommendation",
            },
            item_path,
        )
        identifiers.append(_identifier(item["itemId"], f"{item_path}.itemId"))
        reviewed = _digest(
            item["reviewedArtifactDigest"], f"{item_path}.reviewedArtifactDigest"
        )
        feedback = _digest(item["feedbackDigest"], f"{item_path}.feedbackDigest")
        if reviewed == feedback:
            _fail(
                "non_substantive_external_feedback",
                item_path,
                "feedback and reviewed artifact digests must differ",
            )
        summary = _text(item["summary"], f"{item_path}.summary", minimum=20)
        recommendation = _text(
            item["recommendation"], f"{item_path}.recommendation", minimum=20
        )
        placeholders = {"n/a", "none", "looks good", "no feedback"}
        if (
            summary.strip().lower() in placeholders
            or recommendation.strip().lower() in placeholders
        ):
            _fail(
                "non_substantive_external_feedback",
                item_path,
                "placeholder feedback is inadmissible",
            )
    if identifiers != sorted(set(identifiers)):
        _fail(
            "duplicate_or_unsorted_feedback",
            path,
            "feedback items must be sorted and unique",
        )


def _verify_review(
    evidence: Mapping[str, Any],
    *,
    roster: EffectiveReviewerRoster,
    verification_time: datetime,
) -> set[str]:
    principals: list[str] = []
    for index, raw_statement in enumerate(evidence["statements"]):
        path = f"communityFactEvidence.statements[{index}]"
        body, payload, signature = _statement(
            raw_statement,
            kind=REVIEW_KIND,
            multiple_signatures=False,
            path=path,
        )
        body = _exact(
            body,
            {
                "statementId",
                "freezeDigest",
                "subject",
                "criterionId",
                "feedbackManifest",
                "conflictOfInterest",
                "issuedAt",
                "actor",
            },
            f"{path}.body",
        )
        issued_at = _common_body(body, evidence=evidence, path=f"{path}.body")
        if issued_at > verification_time:
            _fail(
                "future_community_statement",
                f"{path}.body.issuedAt",
                "future statement",
            )
        _feedback_manifest(body["feedbackManifest"], f"{path}.body.feedbackManifest")
        _coi(body["conflictOfInterest"], f"{path}.body.conflictOfInterest")
        signer = _external_signature(
            roster=roster,
            evidence=evidence,
            payload=payload,
            signature=signature,
            actor=body["actor"],
            actor_role="independent-external-reviewer",
            issued_at=issued_at,
            verification_time=verification_time,
            path=path,
        )
        principals.append(signer.identity)
    if len(principals) != len(set(principals)):
        _fail(
            "duplicate_external_reviewer",
            "communityFactEvidence.statements",
            "reviewer principals must be unique",
        )
    return set(principals)


def _authorize_outer(
    result: VerifiedCriterionResult,
    roster: EffectiveReviewerRoster,
    *,
    verification_time: datetime,
    producers: set[str],
) -> None:
    try:
        authorization = authorize_criterion_signer(
            roster,
            principal=result.signer.principal,
            criterion_id=result.criterion.criterion_id,
            required_role="external-attestor",
            required_capability="attest-external-result",
            at=verification_time,
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if (
        result.signer.role != authorization.role
        or result.signer.organization != authorization.organization
        or result.signer.authority_digest != roster.authority_digest
    ):
        _fail(
            "community_fact_signer_mismatch",
            "criterionResult.signer",
            "outer signer differs from freshly verified fact producers",
        )
    if result.criterion.criterion_id == REVIEW:
        if result.signer.principal in producers:
            _fail(
                "community_review_separation_failed",
                "criterionResult.signer",
                "outer external attestor must differ from nested independent reviewer",
            )
    elif result.signer.principal not in producers:
        _fail(
            "community_fact_signer_mismatch",
            "criterionResult.signer",
            "outer attestor must be one of the verified fact producers",
        )


def _verify(
    *,
    evidence: Mapping[str, Any],
    envelope: Mapping[str, Any],
    result: VerifiedCriterionResult,
    roster: EffectiveReviewerRoster,
    policy_result: Mapping[str, Any],
    expected_policy_digest: str,
    expected_prior_chain_head_digest: str,
    verification_time: datetime,
) -> Mapping[str, Any]:
    _require_result(
        envelope,
        result,
        evidence,
        expected_policy_digest=expected_policy_digest,
        expected_prior_chain_head_digest=expected_prior_chain_head_digest,
    )
    _require_namespace_policy(
        policy_result,
        criterion_id=evidence["criterionId"],
        expected_policy_digest=expected_policy_digest,
    )
    roster = _require_roster(
        roster,
        evidence,
        expected_policy_digest=expected_policy_digest,
        expected_prior_chain_head_digest=expected_prior_chain_head_digest,
    )
    if evidence["criterionId"] == OUTREACH:
        producers = _verify_outreach(
            evidence,
            roster=roster,
            policy_result=policy_result,
            verification_time=verification_time,
        )
    elif evidence["criterionId"] == DESIGN_PARTNERS:
        producers = _verify_design_partners(
            evidence,
            roster=roster,
            verification_time=verification_time,
        )
    else:
        producers = _verify_review(
            evidence,
            roster=roster,
            verification_time=verification_time,
        )
    _authorize_outer(
        result,
        roster,
        verification_time=verification_time,
        producers=producers,
    )
    return {
        "status": "verified",
        "kind": "EXTERNAL",
        "criterionId": result.criterion.criterion_id,
        "attestationDigest": result.attestation_digest,
        "evaluator": result.criterion.evaluator,
        "evaluatorDigest": result.criterion.evaluator_digest,
        "datasetDigest": result.criterion.dataset_digest,
        "factEvidenceDigest": evidence["factEvidenceDigest"],
        "factVerifierDigest": FACT_VERIFIER_DIGEST,
        "sourceCommit": result.subject.source_commit,
        "controlPlaneDigest": result.subject.control_plane_digest,
        "contractDigest": result.subject.contract_digest,
        "satisfied": True,
    }


def build_p00_community_fact_verifier(
    expected_criterion_id: str,
    raw_evidence: bytes,
    *,
    reviewer_roster: EffectiveReviewerRoster,
    policy_result: Mapping[str, Any],
    expected_policy_digest: str,
    expected_prior_chain_head_digest: str,
    verification_time: datetime,
) -> FactVerifier:
    """Build a FactVerifier using the outer importer's freshly sealed roster.

    Community evidence deliberately contains no delegation/revocation arrays;
    this prevents it from omitting a revocation accepted by the outer bundle.
    ``reviewer_roster`` must be the exact identity-sealed roster reconstructed
    from that bundle's raw authorization documents.
    """

    if expected_criterion_id not in SUPPORTED_CRITERIA:
        _fail(
            "unsupported_community_fact_criterion",
            "expectedCriterionId",
            "criterion has no implemented P00 community fact model",
        )
    _digest(expected_policy_digest, "expectedPolicyDigest")
    _digest(expected_prior_chain_head_digest, "expectedPriorChainHeadDigest")
    fixed_time = _fixed_time(verification_time)
    evidence = _load(raw_evidence)
    if evidence["criterionId"] != expected_criterion_id:
        _fail(
            "community_fact_criterion_mismatch",
            "communityFactEvidence.criterionId",
            "artifact differs from the fixed verifier criterion",
        )

    def verify(
        envelope: Mapping[str, Any], result: VerifiedCriterionResult
    ) -> Mapping[str, Any]:
        return _verify(
            evidence=evidence,
            envelope=envelope,
            result=result,
            roster=reviewer_roster,
            policy_result=policy_result,
            expected_policy_digest=expected_policy_digest,
            expected_prior_chain_head_digest=expected_prior_chain_head_digest,
            verification_time=fixed_time,
        )

    return verify


def build_p00_outreach_fact_verifier(
    raw_evidence: bytes, **trusted: Any
) -> FactVerifier:
    return build_p00_community_fact_verifier(OUTREACH, raw_evidence, **trusted)


def build_p00_design_partner_fact_verifier(
    raw_evidence: bytes, **trusted: Any
) -> FactVerifier:
    return build_p00_community_fact_verifier(DESIGN_PARTNERS, raw_evidence, **trusted)


def build_p00_external_review_fact_verifier(
    raw_evidence: bytes, **trusted: Any
) -> FactVerifier:
    return build_p00_community_fact_verifier(REVIEW, raw_evidence, **trusted)


__all__ = [
    "CommunityFactError",
    "DESIGN_PARTNERS",
    "DESIGN_PARTNER_NAMESPACE",
    "EVIDENCE_KIND",
    "EVIDENCE_SCHEMA",
    "FACT_VERIFIER_DIGEST",
    "FACT_VERIFIER_SPEC",
    "OUTREACH",
    "OUTREACH_NAMESPACE",
    "REVIEW",
    "REVIEW_NAMESPACE",
    "STATEMENT_SCHEMA",
    "SUPPORTED_CRITERIA",
    "build_p00_community_fact_verifier",
    "build_p00_design_partner_fact_verifier",
    "build_p00_external_review_fact_verifier",
    "build_p00_outreach_fact_verifier",
    "community_fact_evidence_digest",
    "serialize_community_fact_evidence",
]
