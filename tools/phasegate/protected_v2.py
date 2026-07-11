"""R3 protected-control-plane and GitHub OIDC StateEvent verification.

R2 remains available in :mod:`tools.phasegate.protected` as an immutable
historical candidate.  This module defines the successor protocol: portable
SSHSIG verification for human decisions and digest-bound GitHub Actions OIDC
provenance for StateEvents.  Repository protection and exact source bindings
remain explicit inputs; OIDC provenance from an unprotected ref is rejected.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from .digest import canonical_json_bytes, sha256_bytes
from .oidc import (
    OidcVerificationError,
    validate_jwks_snapshot,
    verify_github_actions_oidc_token,
)
from .protected import (
    ALLOWED_TRANSITIONS,
    ProtectedVerificationError,
    _exact_keys,
    _parse_utc,
    _require_commit,
    _require_nonempty,
    _require_sha256,
    _ssh_public_key_fingerprint,
    _state_core_digest,
    _validate_state_invariants,
    document_digest,
)
from .sshsig import SshSigVerificationError, verify_sshsig


POLICY_SCHEMA = "urn:agentapi-doctor:protected-verifier-policy:v1alpha2"
POLICY_KIND = "ProtectedVerifierTrustPolicyCandidate"
APPROVAL_SCHEMA = "urn:agentapi-doctor:control-plane-approval:v1alpha2"
APPROVAL_KIND = "ControlPlaneApprovalAttestation"
STATE_EVENT_SCHEMA = "urn:agentapi-doctor:state-event:v1alpha2"
STATE_EVENT_KIND = "SignedStateEvent"
STATE_VIEW_SCHEMA = "urn:agentapi-doctor:execution:v1alpha2"

APPROVAL_NAMESPACE = "agentapi-doctor/control-plane-approval/v2"
STATE_EVENT_NAMESPACE = "agentapi-doctor/state-event/v1"
OIDC_SIGNATURE_SCHEME = "github-actions-oidc-jwt-rs256-v1"
OIDC_AUDIENCE_PREFIX = "urn:agentapi-doctor:state-event:v1:"
OIDC_PROVENANCE_AUDIENCE_PREFIX = "urn:agentapi-doctor:provenance:v1:"
REPOSITORY_PROTECTION_SCHEMA = (
    "urn:agentapi-doctor:repository-protection-observation:v1alpha1"
)
EXPECTED_RULESET_NAME = "P00 protected main"
EXPECTED_RULE_TYPES = (
    "deletion",
    "linear_history",
    "non_fast_forward",
    "pull_request",
    "required_signatures",
    "required_status_checks",
)
API_LIMITATIONS = ["ruleset bypass actors not observable with read-only token"]

R2_REQUEST_DIGEST = (
    "sha256:3fc6b9adfc077a2b3f78c2a811a8d61f9fb72c0e7a6c03ff269ff0ee4cc35ca0"
)
R2_CONTROL_PLANE_DIGEST = (
    "sha256:8423ed10cd3af376e58382226ba1550f3831d93542ffb580bc1c755e1dee44c6"
)
R2_CANDIDATE_SOURCE_COMMIT = "5babc022f1a714024c903122eb150ed49c515e6d"
R2_REQUEST_COMMIT = "8faf45512ec5384e816390ad1a46a403c103c5dc"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:+-]{0,127}$")
EVENT_ID_RE = re.compile(r"^evt-([0-9]{8})$")

EXPECTED_EXTERNAL_PINS = [
    "trustPolicyDigest",
    "jwksSnapshotDigest",
    "controlPlaneDigest",
    "candidateSourceCommit",
    "requestDigest",
    "workflowExecutionCommit",
    "priorChainHeadDigest",
    "resultingChainHeadDigest",
]

REVIEWER_DELEGATION_NAMESPACE = "agentapi-doctor/reviewer-delegation/v1"
EXPECTED_REVIEWER_DELEGATION_POLICY = {
    "namespace": REVIEWER_DELEGATION_NAMESPACE,
    "rootCapability": "delegate-reviewer",
    "allowedRoles": [
        "external-attestor",
        "independent-dataset-reviewer",
        "independent-external-reviewer",
        "independent-rights-reviewer",
        "independent-technical-reviewer",
    ],
    "allowedCapabilities": [
        "attest-external-result",
        "attest-human-result",
        "freeze-protected-input",
    ],
    "roleGrants": {
        "external-attestor": {
            "capabilities": ["attest-external-result"],
            "criteria": [
                "P00-X-CROSSPLATFORM",
                "P00-X-DESIGN-PARTNERS",
                "P00-X-OUTREACH",
                "P00-X-REVIEW",
            ],
        },
        "independent-dataset-reviewer": {
            "capabilities": ["freeze-protected-input"],
            "criteria": [
                "P00-M-AGGREGATE",
                "P00-M-COMPETITIVE",
                "P00-M-DOCS",
                "P00-M-DUAL-VIEW",
                "P00-M-PROVENANCE",
                "P00-M-REDUCTION",
                "P00-M-REPLAY",
                "P00-M-REPRO",
                "P00-M-SECRET",
                "P00-M-TAXONOMY",
                "P00-M-UNKNOWN",
            ],
        },
        "independent-external-reviewer": {
            "capabilities": ["attest-external-result", "attest-human-result"],
            "criteria": ["P00-H-GO-NOGO", "P00-X-REVIEW"],
        },
        "independent-rights-reviewer": {
            "capabilities": ["attest-human-result"],
            "criteria": ["P00-H-CORPUS-RIGHTS"],
        },
        "independent-technical-reviewer": {
            "capabilities": ["attest-human-result"],
            "criteria": ["P00-H-SPIKE-ADR"],
        },
    },
    "maxValiditySeconds": 7_776_000,
    "priorChainHeadRequired": True,
    "delegatedMayApproveControlPlane": False,
    "delegatedMaySignStateEvent": False,
    "delegatedMayDelegate": False,
}

EXPECTED_HUMAN_CRITERION_ROLE_GRANTS = {
    "P00-H-CONTROL": {
        "roles": ["independent-reviewer"],
        "threshold": 1,
        "derivedFromBootstrapApprovalAndGenesis": True,
    },
    "P00-H-NO-PUBLIC-CLAIM": {
        "roles": ["authorized-maintainer"],
        "threshold": 1,
        "derivedFromBootstrapApprovalAndGenesis": False,
    },
    "P00-H-CORPUS-RIGHTS": {
        "roles": ["independent-rights-reviewer"],
        "threshold": 1,
        "derivedFromBootstrapApprovalAndGenesis": False,
    },
    "P00-H-SPIKE-ADR": {
        "roles": ["independent-technical-reviewer"],
        "threshold": 1,
        "derivedFromBootstrapApprovalAndGenesis": False,
    },
    "P00-H-GO-NOGO": {
        "roles": ["authorized-maintainer", "independent-external-reviewer"],
        "threshold": 2,
        "distinctPrincipals": True,
        "distinctOrganizations": True,
        "derivedFromBootstrapApprovalAndGenesis": False,
    },
}

EXPECTED_MACHINE_PROVENANCE_POLICY = {
    "type": "github-actions-oidc-rs256-v1",
    "audiencePrefix": OIDC_PROVENANCE_AUDIENCE_PREFIX,
    "signerPolicyRef": "githubActionsStateSigner",
    "allowedNamespaces": [
        "agentapi-doctor/activation-proof/v1",
        "agentapi-doctor/criterion-result/machine/v1",
        "agentapi-doctor/lifecycle-evidence/invalidation/v1",
        "agentapi-doctor/lifecycle-proof/v1",
        "agentapi-doctor/phase-criterion-result/machine/v1",
        "agentapi-doctor/phase-transition-proof/v1",
        "agentapi-doctor/transition-proof/v1",
    ],
    "requiredComponentPaths": [
        ".github/workflows/p00-protected-state-writer.yml",
        "tools/phasegate/__init__.py",
        "tools/phasegate/chain_artifact.py",
        "tools/phasegate/chain_witness.py",
        "tools/phasegate/community_facts.py",
        "tools/phasegate/control_context.py",
        "tools/phasegate/delegation.py",
        "tools/phasegate/digest.py",
        "tools/phasegate/evidence_index.py",
        "tools/phasegate/execution_artifact.py",
        "tools/phasegate/external_facts.py",
        "tools/phasegate/gate_runner.py",
        "tools/phasegate/lifecycle_bundle.py",
        "tools/phasegate/lifecycle_evidence.py",
        "tools/phasegate/main.py",
        "tools/phasegate/oidc.py",
        "tools/phasegate/oidc_provenance.py",
        "tools/phasegate/p00_evaluators.py",
        "tools/phasegate/phase_bundle.py",
        "tools/phasegate/phase_evidence.py",
        "tools/phasegate/post_event_writer.py",
        "tools/phasegate/protected.py",
        "tools/phasegate/protected_v2.py",
        "tools/phasegate/provenance.py",
        "tools/phasegate/provenance_writer.py",
        "tools/phasegate/run_executor.py",
        "tools/phasegate/serialized_bundle.py",
        "tools/phasegate/sshsig.py",
        "tools/phasegate/state_chain_v2.py",
        "tools/phasegate/state_writer.py",
        "tools/phasegate/validation.py",
        "tools/phasegate/workflow_orchestrator.py",
    ],
    "componentApprovalBinding": (
        "authorityDigest binds the exact approved component digest map"
    ),
    "runAttempt": "1",
    "shaMustEqualWorkflowSha": True,
    "headAndBaseRefMustBeAbsent": True,
}


def _fail(code: str, path: str, message: str) -> None:
    raise ProtectedVerificationError(code, path, message)


def _now_utc(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        _fail("invalid_timestamp", "now", "verification time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _signed_payload(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": envelope["schemaVersion"],
            "kind": envelope["kind"],
            "body": envelope["body"],
        }
    )


def _validate_signature_descriptor(
    signature: Any, *, expected_namespace: str, path: str
) -> tuple[str, str]:
    descriptor = _exact_keys(
        signature, {"scheme", "namespace", "principal", "value"}, path
    )
    if descriptor["scheme"] != "openssh-sshsig-v1":
        _fail("unsupported_signature_scheme", f"{path}.scheme", "expected SSHSIG v1")
    if descriptor["namespace"] != expected_namespace:
        _fail(
            "signature_namespace_mismatch",
            f"{path}.namespace",
            "signature namespace mismatch",
        )
    principal = descriptor["principal"]
    if not isinstance(principal, str) or not PRINCIPAL_RE.fullmatch(principal):
        _fail("invalid_principal", f"{path}.principal", "invalid exact principal")
    value = descriptor["value"]
    if not isinstance(value, str) or len(value) > 16384:
        _fail("malformed_signature", f"{path}.value", "invalid bounded signature")
    return principal, value


def _principal_for(
    policy_result: Mapping[str, Any],
    *,
    identity: str,
    capability: str,
    role: str,
    at: datetime,
) -> dict[str, Any]:
    principal = policy_result["principals"].get(identity)
    if principal is None:
        _fail("signer_not_allowed", "signature.principal", "principal is not approved")
    if principal["fingerprint"] in policy_result["revokedFingerprints"]:
        _fail("signer_revoked", "signature.principal", "principal key is revoked")
    if capability not in principal["capabilities"]:
        _fail("role_not_authorized", "signature.principal", f"missing {capability}")
    if role not in principal["roles"]:
        _fail("role_not_authorized", "actor.role", "role is not granted to principal")
    valid_from = _parse_utc(principal["validFrom"], "policy.principal.validFrom")
    valid_until = _parse_utc(principal["validUntil"], "policy.principal.validUntil")
    if not valid_from <= at < valid_until:
        _fail(
            "signer_outside_validity",
            "signature.principal",
            "signer was outside policy validity at consumption time",
        )
    return principal


def _verify_human_sshsig(
    *, payload: bytes, signature: Mapping[str, Any], principal: Mapping[str, Any], namespace: str
) -> None:
    _, armored = _validate_signature_descriptor(
        signature, expected_namespace=namespace, path="signature"
    )
    try:
        verify_sshsig(
            payload,
            armored_signature=armored,
            public_key=principal["publicKey"],
            expected_namespace=namespace,
        )
    except SshSigVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)


def _validate_policy_principal(entry: Any, index: int) -> dict[str, Any]:
    path = f"policy.sshPrincipals[{index}]"
    principal = _exact_keys(
        entry,
        {
            "identity",
            "organization",
            "roles",
            "publicKey",
            "fingerprint",
            "capabilities",
            "validFrom",
            "validUntil",
        },
        path,
    )
    if not isinstance(principal["identity"], str) or not PRINCIPAL_RE.fullmatch(
        principal["identity"]
    ):
        _fail("invalid_principal", f"{path}.identity", "invalid exact identity")
    _require_nonempty(principal["organization"], f"{path}.organization", maximum=256)
    roles = principal["roles"]
    capabilities = principal["capabilities"]
    if (
        not isinstance(roles, list)
        or not roles
        or roles != sorted(set(roles))
        or any(not isinstance(item, str) or not item.isascii() for item in roles)
    ):
        _fail("invalid_roles", f"{path}.roles", "roles must be sorted unique ASCII")
    allowed_capabilities = {
        "approve-control-plane",
        "approve-transition",
        "attest-human-result",
        "delegate-reviewer",
        "freeze-protected-input",
        "witness-chain-head",
    }
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or capabilities != sorted(set(capabilities))
        or not set(capabilities).issubset(allowed_capabilities)
    ):
        _fail(
            "invalid_capabilities",
            f"{path}.capabilities",
            "capabilities must be a sorted supported set",
        )
    fingerprint = _ssh_public_key_fingerprint(principal["publicKey"], f"{path}.publicKey")
    if principal["fingerprint"] != fingerprint:
        _fail(
            "public_key_fingerprint_mismatch",
            f"{path}.fingerprint",
            "fingerprint does not match key",
        )
    if _parse_utc(principal["validFrom"], f"{path}.validFrom") >= _parse_utc(
        principal["validUntil"], f"{path}.validUntil"
    ):
        _fail("invalid_principal_validity", path, "validFrom must precede validUntil")
    return principal


def validate_trust_policy_v2(
    policy: Any,
    *,
    jwks_snapshot: Any,
    expected_policy_digest: str,
    expected_jwks_snapshot_digest: str,
    expected_control_plane_digest: str,
) -> dict[str, Any]:
    """Validate the exact hybrid SSHSIG/OIDC R3 trust policy."""

    for value, path in (
        (expected_policy_digest, "external.expectedPolicyDigest"),
        (expected_jwks_snapshot_digest, "external.expectedJwksSnapshotDigest"),
        (expected_control_plane_digest, "external.expectedControlPlaneDigest"),
    ):
        _require_sha256(value, path)
    actual_policy_digest = document_digest(policy)
    if actual_policy_digest != expected_policy_digest:
        _fail("trust_policy_digest_mismatch", "policy", "policy differs from external pin")
    document = _exact_keys(
        policy,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "revision",
            "policyStatus",
            "controlPlaneDigest",
            "signatureSchemes",
            "thresholds",
            "separationOfDuties",
            "sshPrincipals",
            "reviewerDelegation",
            "githubActionsStateSigner",
            "repositoryProtection",
            "protectedFacts",
            "humanCriterionRoleGrants",
            "revokedFingerprints",
            "revokedOidcKids",
            "requiredExternalPins",
            "allowedTransitions",
            "controlPlaneRevisionPolicy",
        },
        "policy",
    )
    if (
        document["schemaVersion"] != POLICY_SCHEMA
        or document["kind"] != POLICY_KIND
        or document["policyId"] != "P00-protected-verifier"
        or document["revision"] != 2
        or document["policyStatus"]
        != "configured-candidate-awaiting-independent-approval"
    ):
        _fail("invalid_policy_identity", "policy", "unsupported R3 policy identity")
    if document["controlPlaneDigest"] != expected_control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "policy.controlPlaneDigest",
            "policy subject differs from external pin",
        )
    schemes = _exact_keys(
        document["signatureSchemes"],
        {"human", "machineProvenance", "stateEvent"},
        "policy.signatureSchemes",
    )
    human = _exact_keys(
        schemes["human"],
        {"type", "allowedKeyTypes", "allowedMessageHashes", "verifier", "namespaces"},
        "policy.signatureSchemes.human",
    )
    expected_namespaces = {
        "activationApproval": "agentapi-doctor/activation-approval/v1",
        "blockerResolution": "agentapi-doctor/lifecycle-evidence/blocker-resolution/v1",
        "chainHeadWitness": "agentapi-doctor/chain-head-witness/v1",
        "communityDesignPartner": "agentapi-doctor/community-fact/design-partner/v1",
        "communityExternalReview": "agentapi-doctor/community-fact/external-review/v1",
        "communityOutreach": "agentapi-doctor/community-fact/outreach/v1",
        "controlPlaneApproval": APPROVAL_NAMESPACE,
        "criterionResult": "agentapi-doctor/criterion-result/human/v1",
        "datasetFreezeSelection": "agentapi-doctor/p00-dataset-freeze-selection/v1",
        "externalCriterionResult": "agentapi-doctor/criterion-result/external/v1",
        "lifecycleApproval": "agentapi-doctor/lifecycle-approval/v1",
        "phaseGoNoGo": "agentapi-doctor/phase-go-no-go-authorization/v1",
        "phaseProtectedInputFreeze": "agentapi-doctor/phase-protected-input-freeze/v1",
        "phaseTransitionApproval": "agentapi-doctor/phase-transition-approval/v1",
        "protectedInputFreeze": "agentapi-doctor/protected-input-freeze/v1",
        "reviewerDelegation": REVIEWER_DELEGATION_NAMESPACE,
        "supersessionApproval": "agentapi-doctor/lifecycle-evidence/supersession-approval/v1",
        "transitionApproval": "agentapi-doctor/transition-approval/v1",
    }
    if human != {
        "type": "openssh-sshsig-v1",
        "allowedKeyTypes": ["ssh-ed25519"],
        "allowedMessageHashes": ["sha256", "sha512"],
        "verifier": "dependency-free-rfc8032-and-openssh-sshsig-profile",
        "namespaces": expected_namespaces,
    }:
        _fail("invalid_signature_policy", "policy.signatureSchemes.human", "policy drift")
    machine_provenance = _exact_keys(
        schemes["machineProvenance"],
        set(EXPECTED_MACHINE_PROVENANCE_POLICY),
        "policy.signatureSchemes.machineProvenance",
    )
    if machine_provenance != EXPECTED_MACHINE_PROVENANCE_POLICY:
        _fail(
            "invalid_machine_provenance_policy",
            "policy.signatureSchemes.machineProvenance",
            "protected workflow OIDC provenance policy drift",
        )
    state_scheme = _exact_keys(
        schemes["stateEvent"],
        {
            "type",
            "namespace",
            "audiencePrefix",
            "jwksSnapshotPath",
            "jwksSnapshotDigest",
            "onlineKeyDiscoveryDuringReplay",
        },
        "policy.signatureSchemes.stateEvent",
    )
    if state_scheme != {
        "type": "github-actions-oidc-rs256-v1",
        "namespace": STATE_EVENT_NAMESPACE,
        "audiencePrefix": OIDC_AUDIENCE_PREFIX,
        "jwksSnapshotPath": "execution/protected-verifier/github-actions-oidc-jwks.json",
        "jwksSnapshotDigest": expected_jwks_snapshot_digest,
        "onlineKeyDiscoveryDuringReplay": False,
    }:
        _fail("invalid_signature_policy", "policy.signatureSchemes.stateEvent", "policy drift")
    try:
        jwks_result = validate_jwks_snapshot(
            jwks_snapshot, expected_snapshot_digest=expected_jwks_snapshot_digest
        )
    except OidcVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    thresholds = document["thresholds"]
    if thresholds != {
        "controlPlaneApproval": 1,
        "stateEvent": 1,
        "transitionApproval": 1,
        "chainHeadWitness": 1,
        "p00GoNoGo": 2,
    }:
        _fail("unsupported_signature_threshold", "policy.thresholds", "threshold drift")
    separation = document["separationOfDuties"]
    if separation != {
        "stateEventSignerMustDifferFromEveryFactSigner": True,
        "stateEventSignerOrganization": "github-actions",
        "controlPlaneApprovalRole": "independent-reviewer",
        "stateEventRole": "protected-workflow",
        "oneSshKeyMayNotRepresentMultiplePrincipals": True,
        "codingAgentMayProduceHumanExternalOrTimeFact": False,
    }:
        _fail("separation_of_duties_drift", "policy.separationOfDuties", "policy drift")
    principals_raw = document["sshPrincipals"]
    if not isinstance(principals_raw, list) or not principals_raw:
        _fail("incomplete_trust_roster", "policy.sshPrincipals", "reviewer is required")
    principals = [
        _validate_policy_principal(entry, index)
        for index, entry in enumerate(principals_raw)
    ]
    identities = [item["identity"] for item in principals]
    fingerprints = [item["fingerprint"] for item in principals]
    if len(set(identities)) != len(identities) or len(set(fingerprints)) != len(fingerprints):
        _fail("ambiguous_signer", "policy.sshPrincipals", "identities/keys must be unique")
    if not any("approve-control-plane" in item["capabilities"] for item in principals):
        _fail("incomplete_trust_roster", "policy.sshPrincipals", "approval signer missing")
    delegation_policy = _exact_keys(
        document["reviewerDelegation"],
        set(EXPECTED_REVIEWER_DELEGATION_POLICY),
        "policy.reviewerDelegation",
    )
    if delegation_policy != EXPECTED_REVIEWER_DELEGATION_POLICY:
        _fail(
            "reviewer_delegation_policy_drift",
            "policy.reviewerDelegation",
            "P00 reviewer delegation scope or safety boundary drifted",
        )
    delegation_roots = [
        item
        for item in principals
        if delegation_policy["rootCapability"] in item["capabilities"]
    ]
    if len(delegation_roots) != 1:
        _fail(
            "invalid_delegation_root",
            "policy.sshPrincipals",
            "exactly one SSH principal must hold delegate-reviewer",
        )
    revoked_fingerprints = document["revokedFingerprints"]
    revoked_oidc = document["revokedOidcKids"]
    for values, path in (
        (revoked_fingerprints, "policy.revokedFingerprints"),
        (revoked_oidc, "policy.revokedOidcKids"),
    ):
        if not isinstance(values, list) or values != sorted(set(values)):
            _fail("invalid_revocation_list", path, "must be sorted unique")
    if set(fingerprints) & set(revoked_fingerprints):
        _fail("revoked_active_principal", "policy", "active reviewer key is revoked")
    if set(jwks_result["keys"]) & set(revoked_oidc):
        _fail("revoked_active_principal", "policy", "approved OIDC key is revoked")
    if document["requiredExternalPins"] != EXPECTED_EXTERNAL_PINS:
        _fail("external_pin_policy_drift", "policy.requiredExternalPins", "pin set drift")
    if document["allowedTransitions"] != {
        key: list(value) for key, value in ALLOWED_TRANSITIONS.items()
    }:
        _fail("transition_policy_drift", "policy.allowedTransitions", "transition drift")
    state_signer = _exact_keys(
        document["githubActionsStateSigner"],
        {
            "identity",
            "organization",
            "role",
            "repository",
            "repositoryId",
            "repositoryOwner",
            "repositoryOwnerId",
            "repositoryVisibility",
            "workflowPath",
            "workflowRef",
            "eventName",
            "ref",
            "refType",
            "refProtected",
            "runnerEnvironment",
            "allowedActorIds",
            "runAttempt",
            "workflowShaSource",
            "shaMustEqualWorkflowSha",
            "headAndBaseRefMustBeEmpty",
        },
        "policy.githubActionsStateSigner",
    )
    expected_signer = {
        "identity": "github-actions:whyiug/agentapi-doctor:p00-state-writer",
        "organization": "github-actions",
        "role": "protected-workflow",
        "repository": "whyiug/agentapi-doctor",
        "repositoryId": "1296831403",
        "repositoryOwner": "whyiug",
        "repositoryOwnerId": "6668626",
        "repositoryVisibility": "public",
        "workflowPath": ".github/workflows/p00-protected-state-writer.yml",
        "workflowRef": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
        "eventName": "workflow_dispatch",
        "ref": "refs/heads/main",
        "refType": "branch",
        "refProtected": "true",
        "runnerEnvironment": "github-hosted",
        "allowedActorIds": ["6668626"],
        "runAttempt": "1",
        "workflowShaSource": "approval.body.workflowExecutionCommit",
        "shaMustEqualWorkflowSha": True,
        "headAndBaseRefMustBeEmpty": True,
    }
    if state_signer != expected_signer:
        _fail("invalid_oidc_signer_policy", "policy.githubActionsStateSigner", "claim policy drift")
    protection = document["repositoryProtection"]
    required_protection = {
        "required": True,
        "visibility": "public",
        "branch": "main",
        "observationApi": [
            "GET /repos/whyiug/agentapi-doctor",
            "GET /repos/whyiug/agentapi-doctor/branches/main",
            "GET /repos/whyiug/agentapi-doctor/rules/branches/main",
            "GET /repos/whyiug/agentapi-doctor/rulesets",
            "GET /repos/whyiug/agentapi-doctor/rulesets/{id}",
        ],
        "ruleset": {
            "name": EXPECTED_RULESET_NAME,
            "target": "branch",
            "sourceType": "Repository",
            "source": "whyiug/agentapi-doctor",
            "enforcement": "active",
            "conditions": {
                "refName": {"include": ["refs/heads/main"], "exclude": []}
            },
        },
        "requiredRuleTypes": list(EXPECTED_RULE_TYPES),
        "pullRequest": {
            "requiredApprovingReviewCount": 1,
            "dismissStaleReviewsOnPush": True,
            "requireCodeOwnerReview": True,
            "requireLastPushApproval": True,
            "requiredReviewThreadResolution": True,
        },
        "requiredStatusChecks": {
            "strict": True,
            "contexts": [
                "P00 bootstrap cross-platform / aggregate",
                "P00 protected control-plane / verify",
            ],
            "integrationId": "positive integer when observable; null is retained when the read-only API omits it",
        },
        "apiLimitations": API_LIMITATIONS,
        "administratorAndBypassVisibility": (
            "unproved; no enforce-admins or no-bypass claim is made"
        ),
        "compensatingControl": (
            "independent SSHSIG approval binds the exact workflow execution commit, "
            "candidate source, policy, and verifier implementation"
        ),
        "proofSource": (
            "public GitHub Rulesets REST responses captured, normalized, and "
            "digest-bound by the OIDC StateEvent writer"
        ),
        "missingOrWeakerProof": "non-authoritative-provenance-only",
    }
    if protection != required_protection:
        _fail("repository_protection_policy_drift", "policy.repositoryProtection", "policy drift")
    # The remaining declarative grants are themselves approval inputs.  Keep
    # their shape strict; criterion-specific semantic validation lives in the
    # provenance verifier and refuses missing roles/verifiers.
    if not isinstance(document["protectedFacts"], dict) or set(document["protectedFacts"]) != {
        "machine", "external", "time", "human", "missingVerifier"
    }:
        _fail("invalid_fact_policy", "policy.protectedFacts", "fact policy drift")
    grants = document["humanCriterionRoleGrants"]
    if grants != EXPECTED_HUMAN_CRITERION_ROLE_GRANTS:
        _fail("invalid_fact_policy", "policy.humanCriterionRoleGrants", "grant set drift")
    revision_policy = document["controlPlaneRevisionPolicy"]
    if revision_policy != {
        "p00": "all P00 evaluators and protected result semantics must be implemented and approved before Genesis",
        "postP00": "a separately approved ControlPlaneRevision event and historical revision map are required before P01 activation",
        "silentDigestSwap": "forbidden",
    }:
        _fail("control_plane_revision_policy_drift", "policy.controlPlaneRevisionPolicy", "policy drift")
    return {
        "document": document,
        "digest": actual_policy_digest,
        "principals": {item["identity"]: item for item in principals},
        "revokedFingerprints": set(revoked_fingerprints),
        "revokedOidcKids": set(revoked_oidc),
        "jwks": jwks_result,
        "stateSigner": state_signer,
        "repositoryProtection": protection,
        "machineProvenance": deepcopy(machine_provenance),
        "reviewerDelegation": deepcopy(delegation_policy),
        "delegationRoots": {
            item["identity"]: deepcopy(item) for item in delegation_roots
        },
    }


def verify_control_plane_approval_v2(
    *,
    request: Any,
    approval: Any,
    policy: Any,
    jwks_snapshot: Any,
    expected_policy_digest: str,
    expected_jwks_snapshot_digest: str,
    expected_control_plane_digest: str,
    expected_candidate_source_commit: str,
    expected_request_digest: str,
    expected_workflow_execution_commit: str,
    consumption_time: datetime | None = None,
) -> dict[str, Any]:
    """Verify an exact R3 decision using portable SSHSIG verification."""

    _require_sha256(expected_request_digest, "external.expectedRequestDigest")
    _require_commit(expected_candidate_source_commit, "external.expectedCandidateSourceCommit")
    _require_commit(expected_workflow_execution_commit, "external.expectedWorkflowExecutionCommit")
    actual_request_digest = document_digest(request)
    if actual_request_digest != expected_request_digest:
        _fail("request_digest_mismatch", "request", "request differs from external pin")
    request_document = _exact_keys(
        request,
        {
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
        },
        "request",
    )
    if (
        request_document["schemaVersion"]
        != "urn:agentapi-doctor:bootstrap-request:v1alpha3"
        or request_document["kind"] != "BootstrapControlPlaneReviewRequest"
        or request_document["requestId"] != "P00.B00-R3"
        or request_document["revision"] != 3
        or request_document["requestStatus"] != "pending_review"
    ):
        _fail("invalid_request", "request", "unsupported R3 request")
    if request_document["previousRequest"] != {
        "requestId": "P00.B00-R2",
        "revision": 2,
        "requestDigest": R2_REQUEST_DIGEST,
        "controlPlaneDigest": R2_CONTROL_PLANE_DIGEST,
        "candidateSourceCommit": R2_CANDIDATE_SOURCE_COMMIT,
        "requestCommit": R2_REQUEST_COMMIT,
    }:
        _fail("request_revision_chain_mismatch", "request.previousRequest", "R2 chain drift")
    candidate = _exact_keys(
        request_document["candidate"],
        {
            "baseCommit",
            "candidateSourceCommit",
            "gitObjectFormat",
            "canonicalPlanPath",
            "controlPlaneDigest",
        },
        "request.candidate",
    )
    if (
        candidate["baseCommit"] != R2_REQUEST_COMMIT
        or candidate["gitObjectFormat"] != "sha1"
        or candidate["canonicalPlanPath"] != "agentapi-doctor-Plan.md"
        or candidate["candidateSourceCommit"] != expected_candidate_source_commit
        or candidate["controlPlaneDigest"] != expected_control_plane_digest
    ):
        _fail("request_candidate_binding_drift", "request.candidate", "candidate binding drift")
    if not isinstance(request_document["componentDigests"], dict):
        _fail("invalid_request", "request.componentDigests", "component map required")
    policy_result = validate_trust_policy_v2(
        policy,
        jwks_snapshot=jwks_snapshot,
        expected_policy_digest=expected_policy_digest,
        expected_jwks_snapshot_digest=expected_jwks_snapshot_digest,
        expected_control_plane_digest=expected_control_plane_digest,
    )
    envelope = _exact_keys(
        approval,
        {"schemaVersion", "kind", "body", "signature", "attestationDigest"},
        "approval",
    )
    if envelope["schemaVersion"] != APPROVAL_SCHEMA or envelope["kind"] != APPROVAL_KIND:
        _fail("invalid_approval_schema", "approval", "unsupported approval envelope")
    actual_approval_digest = document_digest(envelope, omit_field="attestationDigest")
    if envelope["attestationDigest"] != actual_approval_digest:
        _fail("approval_digest_mismatch", "approval.attestationDigest", "digest mismatch")
    body = _exact_keys(
        envelope["body"],
        {
            "attestationId",
            "requestId",
            "requestRevision",
            "requestDigest",
            "decision",
            "candidateSourceCommit",
            "workflowExecutionCommit",
            "controlPlaneDigest",
            "digestGroups",
            "reviewedDecisionIds",
            "reviewedAmbiguityIds",
            "scope",
            "reason",
            "validFrom",
            "validUntil",
            "constraints",
            "conflictOfInterest",
            "reviewer",
            "trustPolicyDigest",
            "jwksSnapshotDigest",
        },
        "approval.body",
    )
    _require_nonempty(body["attestationId"], "approval.body.attestationId", maximum=256)
    if (
        body["requestId"] != request_document["requestId"]
        or body["requestRevision"] != request_document["revision"]
        or body["requestDigest"] != actual_request_digest
    ):
        _fail("request_identity_mismatch", "approval.body", "approval request binding mismatch")
    if body["decision"] not in {"APPROVE", "REJECT"}:
        _fail("invalid_approval_decision", "approval.body.decision", "invalid decision")
    if body["candidateSourceCommit"] != expected_candidate_source_commit:
        _fail("source_commit_mismatch", "approval.body.candidateSourceCommit", "source mismatch")
    if body["workflowExecutionCommit"] != expected_workflow_execution_commit:
        _fail(
            "workflow_execution_commit_mismatch",
            "approval.body.workflowExecutionCommit",
            "workflow commit differs from external pin",
        )
    if body["controlPlaneDigest"] != expected_control_plane_digest:
        _fail("control_plane_digest_mismatch", "approval.body.controlPlaneDigest", "digest mismatch")
    if body["digestGroups"] != request_document["digestGroups"]:
        _fail("approval_digest_group_mismatch", "approval.body.digestGroups", "group mismatch")
    decision_ids = [item.get("id") for item in request_document["decisionsRequested"]]
    ambiguity_ids = [item.get("id") for item in request_document["ambiguities"]]
    if (
        body["reviewedDecisionIds"] != decision_ids
        or len(set(decision_ids)) != len(decision_ids)
        or body["reviewedAmbiguityIds"] != ambiguity_ids
        or len(set(ambiguity_ids)) != len(ambiguity_ids)
    ):
        _fail("incomplete_review_decisions", "approval.body", "review coverage mismatch")
    if body["scope"] != {"phase": "P00", "bootstrapId": "P00.B00"}:
        _fail("invalid_approval_scope", "approval.body.scope", "scope mismatch")
    _require_nonempty(body["reason"], "approval.body.reason")
    if body["constraints"] != []:
        _fail("unsupported_approval_constraints", "approval.body.constraints", "constraints unsupported")
    conflict = _exact_keys(
        body["conflictOfInterest"], {"independent", "statement"}, "approval.body.conflictOfInterest"
    )
    if conflict["independent"] is not True:
        _fail("reviewer_not_independent", "approval.body.conflictOfInterest", "independence required")
    _require_nonempty(conflict["statement"], "approval.body.conflictOfInterest.statement")
    reviewer = _exact_keys(
        body["reviewer"], {"principal", "role", "organization"}, "approval.body.reviewer"
    )
    if body["trustPolicyDigest"] != policy_result["digest"]:
        _fail("trust_policy_digest_mismatch", "approval.body.trustPolicyDigest", "policy mismatch")
    if body["jwksSnapshotDigest"] != expected_jwks_snapshot_digest:
        _fail("oidc_jwks_snapshot_digest_mismatch", "approval.body.jwksSnapshotDigest", "snapshot mismatch")
    valid_from = _parse_utc(body["validFrom"], "approval.body.validFrom")
    valid_until = _parse_utc(body["validUntil"], "approval.body.validUntil")
    consumed_at = _now_utc(consumption_time)
    if valid_from >= valid_until or not valid_from <= consumed_at < valid_until:
        _fail("approval_outside_validity", "approval.body", "approval invalid at consumption")
    signature_principal, _ = _validate_signature_descriptor(
        envelope["signature"], expected_namespace=APPROVAL_NAMESPACE, path="approval.signature"
    )
    if signature_principal != reviewer["principal"]:
        _fail("actor_principal_mismatch", "approval", "reviewer/signature mismatch")
    trusted = _principal_for(
        policy_result,
        identity=signature_principal,
        capability="approve-control-plane",
        role=reviewer["role"],
        at=consumed_at,
    )
    if reviewer["organization"] != trusted["organization"]:
        _fail("role_not_authorized", "approval.body.reviewer", "organization mismatch")
    _verify_human_sshsig(
        payload=_signed_payload(envelope),
        signature=envelope["signature"],
        principal=trusted,
        namespace=APPROVAL_NAMESPACE,
    )
    return {
        "status": "verified",
        "decision": body["decision"],
        "approvalDigest": actual_approval_digest,
        "requestId": request_document["requestId"],
        "requestDigest": actual_request_digest,
        "controlPlaneDigest": expected_control_plane_digest,
        "candidateSourceCommit": expected_candidate_source_commit,
        "workflowExecutionCommit": expected_workflow_execution_commit,
        "reviewer": deepcopy(reviewer),
        "trustPolicyDigest": policy_result["digest"],
        "jwksSnapshotDigest": expected_jwks_snapshot_digest,
        "componentDigests": deepcopy(request_document["componentDigests"]),
        "digestGroups": deepcopy(request_document["digestGroups"]),
        "validFrom": body["validFrom"],
        "validUntil": body["validUntil"],
    }


def _expected_oidc_claims(
    policy_result: Mapping[str, Any], *, workflow_execution_commit: str
) -> dict[str, str]:
    signer = policy_result["stateSigner"]
    actor_ids = signer["allowedActorIds"]
    if actor_ids != ["6668626"]:
        _fail("invalid_oidc_signer_policy", "policy", "exact actor ID required")
    return {
        "repository": signer["repository"],
        "repository_id": signer["repositoryId"],
        "repository_owner": signer["repositoryOwner"],
        "repository_owner_id": signer["repositoryOwnerId"],
        "repository_visibility": signer["repositoryVisibility"],
        "event_name": signer["eventName"],
        "ref": signer["ref"],
        "ref_type": signer["refType"],
        "ref_protected": signer["refProtected"],
        "runner_environment": signer["runnerEnvironment"],
        "actor_id": actor_ids[0],
        "workflow_ref": signer["workflowRef"],
        "workflow_sha": workflow_execution_commit,
        "sha": workflow_execution_commit,
    }


def _verify_repository_protection_observation(
    observation: Any,
    *,
    policy_result: Mapping[str, Any],
    workflow_execution_commit: str,
    event_timestamp: datetime,
) -> dict[str, Any]:
    """Verify normalized public Rulesets facts and explicit API limitations."""

    value = _exact_keys(
        observation,
        {
            "schemaVersion",
            "source",
            "observedAt",
            "repository",
            "branch",
            "ruleset",
            "effectiveRules",
            "apiLimitations",
            "apiEvidenceDigest",
        },
        "event.body.repositoryProtection",
    )
    if (
        value["schemaVersion"] != REPOSITORY_PROTECTION_SCHEMA
        or value["source"] != "github-rulesets-rest-api-2022-11-28"
    ):
        _fail(
            "invalid_repository_protection_observation",
            "event.body.repositoryProtection",
            "unsupported repository protection evidence source",
        )
    observed_at = _parse_utc(
        value["observedAt"], "event.body.repositoryProtection.observedAt"
    )
    if observed_at != event_timestamp:
        _fail(
            "repository_protection_time_mismatch",
            "event.body.repositoryProtection.observedAt",
            "protection observation must be atomic with the Genesis statement",
        )

    signer = policy_result["stateSigner"]
    policy = policy_result["repositoryProtection"]
    repository = _exact_keys(
        value["repository"],
        {
            "id",
            "owner",
            "ownerId",
            "name",
            "fullName",
            "visibility",
            "defaultBranch",
        },
        "event.body.repositoryProtection.repository",
    )
    expected_repository = {
        "id": signer["repositoryId"],
        "owner": signer["repositoryOwner"],
        "ownerId": signer["repositoryOwnerId"],
        "name": signer["repository"].split("/", 1)[1],
        "fullName": signer["repository"],
        "visibility": policy["visibility"],
        "defaultBranch": policy["branch"],
    }
    if repository != expected_repository or repository["visibility"] != "public":
        _fail(
            "repository_identity_mismatch",
            "event.body.repositoryProtection.repository",
            "repository identity or public visibility differs from approved policy",
        )

    branch = _exact_keys(
        value["branch"],
        {"name", "protected", "commitSha"},
        "event.body.repositoryProtection.branch",
    )
    if branch != {
        "name": policy["branch"],
        "protected": True,
        "commitSha": workflow_execution_commit,
    }:
        _fail(
            "branch_not_protected",
            "event.body.repositoryProtection.branch",
            "protected main observation does not bind the approved workflow commit",
        )
    ruleset = _exact_keys(
        value["ruleset"],
        {
            "id",
            "name",
            "target",
            "sourceType",
            "source",
            "enforcement",
            "conditions",
            "rules",
            "detailDigest",
        },
        "event.body.repositoryProtection.ruleset",
    )
    ruleset_id = ruleset["id"]
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        _fail(
            "repository_ruleset_mismatch",
            "event.body.repositoryProtection.ruleset.id",
            "ruleset ID must be a positive integer",
        )
    expected_ruleset = policy["ruleset"]
    for field in ("name", "target", "sourceType", "source", "enforcement", "conditions"):
        if ruleset[field] != expected_ruleset[field]:
            _fail(
                "repository_ruleset_mismatch",
                f"event.body.repositoryProtection.ruleset.{field}",
                "ruleset identity, source, enforcement, or conditions differ from policy",
            )

    rules = ruleset["rules"]
    if not isinstance(rules, list) or [
        item.get("type") if isinstance(item, dict) else None for item in rules
    ] != policy["requiredRuleTypes"]:
        _fail(
            "repository_ruleset_mismatch",
            "event.body.repositoryProtection.ruleset.rules",
            "ruleset rule types differ from the exact approved set",
        )
    for index, rule in enumerate(rules):
        rule_path = f"event.body.repositoryProtection.ruleset.rules[{index}]"
        rule_type = rule["type"]
        if rule_type in {
            "deletion",
            "linear_history",
            "non_fast_forward",
            "required_signatures",
        }:
            _exact_keys(rule, {"type"}, rule_path)
            continue
        descriptor = _exact_keys(rule, {"type", "parameters"}, rule_path)
        if rule_type == "pull_request":
            parameters = _exact_keys(
                descriptor["parameters"],
                {
                    "dismissStaleReviewsOnPush",
                    "requireCodeOwnerReview",
                    "requireLastPushApproval",
                    "requiredApprovingReviewCount",
                    "requiredReviewThreadResolution",
                },
                f"{rule_path}.parameters",
            )
            if parameters != {
                "dismissStaleReviewsOnPush": policy["pullRequest"][
                    "dismissStaleReviewsOnPush"
                ],
                "requireCodeOwnerReview": policy["pullRequest"][
                    "requireCodeOwnerReview"
                ],
                "requireLastPushApproval": policy["pullRequest"][
                    "requireLastPushApproval"
                ],
                "requiredApprovingReviewCount": policy["pullRequest"][
                    "requiredApprovingReviewCount"
                ],
                "requiredReviewThreadResolution": policy["pullRequest"][
                    "requiredReviewThreadResolution"
                ],
            }:
                _fail(
                    "repository_ruleset_weakened",
                    f"{rule_path}.parameters",
                    "pull-request controls differ from policy",
                )
            continue
        if rule_type != "required_status_checks":
            _fail("unexpected_active_rule", rule_path, "unapproved rule type")
        parameters = _exact_keys(
            descriptor["parameters"],
            {"strictRequiredStatusChecksPolicy", "requiredStatusChecks"},
            f"{rule_path}.parameters",
        )
        if parameters["strictRequiredStatusChecksPolicy"] is not True:
            _fail(
                "required_status_checks_mismatch",
                f"{rule_path}.parameters.strictRequiredStatusChecksPolicy",
                "status check policy must be strict",
            )
        checks = parameters["requiredStatusChecks"]
        expected_contexts = policy["requiredStatusChecks"]["contexts"]
        if not isinstance(checks, list) or len(checks) != len(expected_contexts):
            _fail(
                "required_status_checks_mismatch",
                f"{rule_path}.parameters.requiredStatusChecks",
                "required status check set is incomplete",
            )
        for check_index, check in enumerate(checks):
            check_path = f"{rule_path}.parameters.requiredStatusChecks[{check_index}]"
            checked = _exact_keys(check, {"context", "integrationId"}, check_path)
            integration_id = checked["integrationId"]
            if integration_id is not None and (
                isinstance(integration_id, bool)
                or not isinstance(integration_id, int)
                or integration_id <= 0
            ):
                _fail(
                    "invalid_repository_protection_observation",
                    f"{check_path}.integrationId",
                    "integration ID must be positive when observable",
                )
        if [check["context"] for check in checks] != expected_contexts:
            _fail(
                "required_status_checks_mismatch",
                f"{rule_path}.parameters.requiredStatusChecks",
                "required status check contexts differ from policy",
            )
    if value["effectiveRules"] != rules:
        _fail(
            "effective_ruleset_mismatch",
            "event.body.repositoryProtection.effectiveRules",
            "effective main rules differ from the single active ruleset detail",
        )
    if value["apiLimitations"] != policy["apiLimitations"]:
        _fail(
            "repository_protection_limitation_mismatch",
            "event.body.repositoryProtection.apiLimitations",
            "read-only API limitation must remain explicit",
        )
    detail_projection = {
        key: ruleset[key]
        for key in (
            "id",
            "name",
            "target",
            "sourceType",
            "source",
            "enforcement",
            "conditions",
            "rules",
        )
    }
    _require_sha256(
        ruleset["detailDigest"],
        "event.body.repositoryProtection.ruleset.detailDigest",
    )
    actual_detail_digest = sha256_bytes(canonical_json_bytes(detail_projection))
    if ruleset["detailDigest"] != actual_detail_digest:
        _fail(
            "repository_ruleset_detail_digest_mismatch",
            "event.body.repositoryProtection.ruleset.detailDigest",
            "normalized active ruleset detail digest mismatch",
        )
    _require_sha256(
        value["apiEvidenceDigest"],
        "event.body.repositoryProtection.apiEvidenceDigest",
    )
    evidence_projection = {
        "repository": repository,
        "branch": branch,
        "ruleset": ruleset,
        "effectiveRules": value["effectiveRules"],
        "apiLimitations": value["apiLimitations"],
    }
    actual_evidence_digest = sha256_bytes(canonical_json_bytes(evidence_projection))
    if value["apiEvidenceDigest"] != actual_evidence_digest:
        _fail(
            "repository_protection_evidence_digest_mismatch",
            "event.body.repositoryProtection.apiEvidenceDigest",
            "normalized GitHub API evidence digest mismatch",
        )
    return {
        "apiEvidenceDigest": actual_evidence_digest,
        "repositoryId": repository["id"],
        "visibility": repository["visibility"],
        "branch": branch["name"],
        "rulesetId": ruleset_id,
        "rulesetDetailDigest": actual_detail_digest,
        "apiLimitations": deepcopy(value["apiLimitations"]),
    }


def _verify_workflow_blob(
    *, repo_root: Path, workflow_commit: str, workflow_path: str, expected_digest: str
) -> None:
    _require_commit(workflow_commit, "workflowCommit")
    _require_sha256(expected_digest, "workflowDigest")
    git = Path("/usr/bin/git")
    if not git.is_file() or git.is_symlink() or not os.access(git, os.X_OK):
        _fail("git_verifier_unavailable", str(git), "fixed Git executable unavailable")
    try:
        completed = subprocess.run(
            [str(git), "-c", "core.pager=cat", "-C", str(repo_root), "show", f"{workflow_commit}:{workflow_path}"],
            check=False,
            capture_output=True,
            timeout=20,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail("git_verifier_unavailable", "workflowCommit", str(exc))
    if completed.returncode != 0:
        _fail("workflow_source_unavailable", "workflowCommit", "cannot read workflow at signed commit")
    raw = completed.stdout
    if b"\x00" in raw:
        _fail("workflow_source_digest_mismatch", workflow_path, "workflow must be text")
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if sha256_bytes(normalized) != expected_digest:
        _fail("workflow_source_digest_mismatch", workflow_path, "workflow changed after approval")


def _initial_state_from_genesis_v2(
    body: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    approval_result: Mapping[str, Any],
    contract_digests: Mapping[str, str],
) -> dict[str, Any]:
    units = [f"P00.W0{index}" for index in range(1, 6)]
    if (
        payload["requestId"] != approval_result["requestId"]
        or payload["requestDigest"] != approval_result["requestDigest"]
        or payload["approvalDigest"] != approval_result["approvalDigest"]
        or payload["planVersion"] != "1.0"
        or payload["activePhase"] != "P00"
        or payload["activeWorkUnit"] != "P00.W01"
        or payload["pendingWorkUnit"] is not None
    ):
        _fail("invalid_genesis", "event.body.payload", "Genesis approval/state binding mismatch")
    aggregate = contract_digests.get("execution/phases/P00.yaml")
    expected_units = {
        unit: contract_digests.get(f"execution/work-units/{unit}.yaml") for unit in units
    }
    if payload["aggregateContractDigest"] != aggregate or payload["workUnitContractDigests"] != expected_units:
        _fail("contract_digest_mismatch", "event.body.payload", "contract set mismatch")
    work_units = {
        unit: {
            "status": "ACTIVE" if unit == "P00.W01" else "NOT_STARTED",
            "contractDigest": expected_units[unit],
            "approvalDigest": approval_result["approvalDigest"] if unit == "P00.W01" else None,
            "sourceCommit": body["sourceCommit"] if unit == "P00.W01" else None,
        }
        for unit in units
    }
    core = {
        "planVersion": "1.0",
        "controlPlaneDigest": body["controlPlaneDigest"],
        "activePhase": "P00",
        "activeWorkUnit": "P00.W01",
        "pendingWorkUnit": None,
        "phases": {
            "P00": {
                "status": "ACTIVE",
                "aggregateContractDigest": aggregate,
                "controlPlaneDigest": body["controlPlaneDigest"],
                "baseCommit": body["sourceCommit"],
                "startedAt": body["timestamp"],
                "workUnits": work_units,
            }
        },
    }
    _validate_state_invariants(core)
    if payload["resultingStateDigest"] != _state_core_digest(core):
        _fail("state_digest_mismatch", "event.body.payload.resultingStateDigest", "state mismatch")
    return core


def verify_genesis_event_v2(
    *,
    event: Any,
    policy_result: Mapping[str, Any],
    approval_result: Mapping[str, Any],
    jwks_snapshot: Any,
    expected_control_plane_digest: str,
    expected_chain_head_digest: str,
    contract_digests: Mapping[str, str],
    repo_root: Path,
) -> dict[str, Any]:
    """Verify the R3 Genesis event and derive its unique state view."""

    _require_sha256(expected_chain_head_digest, "external.expectedChainHeadDigest")
    envelope = _exact_keys(
        event, {"schemaVersion", "kind", "body", "signature", "eventDigest"}, "event"
    )
    if envelope["schemaVersion"] != STATE_EVENT_SCHEMA or envelope["kind"] != STATE_EVENT_KIND:
        _fail("invalid_event_schema", "event", "unsupported StateEvent")
    actual_event_digest = document_digest(envelope, omit_field="eventDigest")
    if envelope["eventDigest"] != actual_event_digest or actual_event_digest != expected_chain_head_digest:
        _fail("chain_head_digest_mismatch", "event", "event/head digest mismatch")
    body = _exact_keys(
        envelope["body"],
        {
            "eventType",
            "eventId",
            "sequence",
            "previousDigest",
            "timestamp",
            "actor",
            "sourceCommit",
            "controlPlaneDigest",
            "trustPolicyDigest",
            "reasonCode",
            "reason",
            "repositoryProtection",
            "writer",
            "payload",
        },
        "event.body",
    )
    if (
        body["eventType"] != "Genesis"
        or body["eventId"] != "evt-00000000"
        or body["sequence"] != 0
        or body["previousDigest"] is not None
    ):
        _fail("invalid_genesis", "event.body", "first event must be sequence-zero Genesis")
    if body["sourceCommit"] != approval_result["candidateSourceCommit"]:
        _fail("source_commit_mismatch", "event.body.sourceCommit", "source mismatch")
    if body["controlPlaneDigest"] != expected_control_plane_digest:
        _fail("control_plane_digest_mismatch", "event.body.controlPlaneDigest", "digest mismatch")
    if body["trustPolicyDigest"] != policy_result["digest"]:
        _fail("trust_policy_digest_mismatch", "event.body.trustPolicyDigest", "policy mismatch")
    timestamp = _parse_utc(body["timestamp"], "event.body.timestamp")
    actor = _exact_keys(body["actor"], {"principal", "role", "organization"}, "event.body.actor")
    signer = policy_result["stateSigner"]
    if actor != {
        "principal": signer["identity"],
        "role": signer["role"],
        "organization": signer["organization"],
    }:
        _fail("actor_principal_mismatch", "event.body.actor", "OIDC actor mismatch")
    protection_result = _verify_repository_protection_observation(
        body["repositoryProtection"],
        policy_result=policy_result,
        workflow_execution_commit=approval_result["workflowExecutionCommit"],
        event_timestamp=timestamp,
    )
    signature = _exact_keys(
        envelope["signature"], {"scheme", "namespace", "statementDigest", "jwt"}, "event.signature"
    )
    statement_digest = sha256_bytes(_signed_payload(envelope))
    if (
        signature["scheme"] != OIDC_SIGNATURE_SCHEME
        or signature["namespace"] != STATE_EVENT_NAMESPACE
        or signature["statementDigest"] != statement_digest
    ):
        _fail("signature_binding_mismatch", "event.signature", "OIDC statement binding mismatch")
    writer = _exact_keys(
        body["writer"],
        {"jwksSnapshotDigest", "claimsPolicyDigest", "workflowPath", "workflowExecutionCommit"},
        "event.body.writer",
    )
    if (
        writer["jwksSnapshotDigest"] != approval_result["jwksSnapshotDigest"]
        or writer["workflowPath"] != signer["workflowPath"]
        or writer["workflowExecutionCommit"] != approval_result["workflowExecutionCommit"]
    ):
        _fail("writer_binding_mismatch", "event.body.writer", "writer trust binding mismatch")
    claims = _expected_oidc_claims(
        policy_result, workflow_execution_commit=approval_result["workflowExecutionCommit"]
    )
    if writer["claimsPolicyDigest"] != sha256_bytes(canonical_json_bytes(claims)):
        _fail("writer_binding_mismatch", "event.body.writer.claimsPolicyDigest", "claims policy mismatch")
    try:
        snapshot_result = validate_jwks_snapshot(
            jwks_snapshot,
            expected_snapshot_digest=approval_result["jwksSnapshotDigest"],
        )
        verified_claims = verify_github_actions_oidc_token(
            signature["jwt"],
            approved_jwks=jwks_snapshot["keys"],
            expected_audience=OIDC_AUDIENCE_PREFIX + statement_digest,
            expected_claims=claims,
            statement_timestamp=timestamp,
        )
    except OidcVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if verified_claims["run_attempt"] != "1":
        _fail("oidc_rerun_forbidden", "event.signature", "rerun forbidden")
    for claim in ("head_ref", "base_ref"):
        if verified_claims.get(claim) not in {None, ""}:
            _fail(
                "oidc_pull_request_claim_forbidden",
                f"jwt.claims.{claim}",
                "workflow_dispatch StateEvent must not carry a pull-request ref",
            )
    executed_paths = [
        signer["workflowPath"],
        "tools/phasegate/__init__.py",
        "tools/phasegate/digest.py",
        "tools/phasegate/oidc.py",
        "tools/phasegate/protected.py",
        "tools/phasegate/protected_v2.py",
        "tools/phasegate/sshsig.py",
        "tools/phasegate/state_writer.py",
        "tools/phasegate/validation.py",
    ]
    for executed_path in executed_paths:
        expected_digest = approval_result["componentDigests"].get(executed_path)
        if expected_digest is None:
            _fail(
                "workflow_source_digest_mismatch",
                executed_path,
                "approved executed-component digest is missing",
            )
        _verify_workflow_blob(
            repo_root=repo_root,
            workflow_commit=approval_result["workflowExecutionCommit"],
            workflow_path=executed_path,
            expected_digest=expected_digest,
        )
    payload = _exact_keys(
        body["payload"],
        {
            "requestId",
            "requestDigest",
            "approvalDigest",
            "planVersion",
            "activePhase",
            "activeWorkUnit",
            "pendingWorkUnit",
            "aggregateContractDigest",
            "workUnitContractDigests",
            "resultingStateDigest",
        },
        "event.body.payload",
    )
    core = _initial_state_from_genesis_v2(
        body, payload, approval_result=approval_result, contract_digests=contract_digests
    )
    return {
        "schemaVersion": STATE_VIEW_SCHEMA,
        **deepcopy(core),
        "stateDigest": _state_core_digest(core),
        "attachments": [],
        "chain": {"eventCount": 1, "headSequence": 0, "headDigest": actual_event_digest},
        "provenance": {
            "oidcJwksSnapshotDigest": snapshot_result["digest"],
            "workflowExecutionCommit": approval_result["workflowExecutionCommit"],
            "workflowRunId": verified_claims["run_id"],
            "workflowCheckRunId": verified_claims["check_run_id"],
            "repositoryProtection": protection_result,
        },
    }
