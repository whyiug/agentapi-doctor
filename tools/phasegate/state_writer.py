"""Protected, OIDC-backed construction of the P00 Genesis candidate.

The writer has deliberately narrow authority: it constructs one deterministic
Genesis statement in memory, obtains a digest-bound GitHub Actions OIDC token,
and verifies that token against caller-supplied trust material before returning
the envelope.  It does not write repository state or discover trust roots.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
from typing import Any, Callable, Mapping
from urllib import parse, request

from .digest import DigestError, canonical_json_bytes, sha256_bytes
from .oidc import validate_jwks_snapshot, verify_github_actions_oidc_token


STATE_EVENT_SCHEMA = "urn:agentapi-doctor:state-event:v1alpha2"
STATE_EVENT_KIND = "SignedStateEvent"
STATE_EVENT_NAMESPACE = "agentapi-doctor/state-event/v1"
OIDC_SIGNATURE_SCHEME = "github-actions-oidc-jwt-rs256-v1"
OIDC_AUDIENCE_PREFIX = "urn:agentapi-doctor:state-event:v1:"
REPOSITORY_PROTECTION_SCHEMA = (
    "urn:agentapi-doctor:repository-protection-observation:v1alpha1"
)
GITHUB_API_VERSION = "2022-11-28"
GITHUB_API_ROOT = "https://api.github.com"

REPOSITORY = "whyiug/agentapi-doctor"
REPOSITORY_ID = "1296831403"
REPOSITORY_OWNER = "whyiug"
REPOSITORY_OWNER_ID = "6668626"
REPOSITORY_NAME = "agentapi-doctor"
PROTECTED_BRANCH = "main"
EXPECTED_RULESET_NAME = "P00 protected main"
API_LIMITATIONS = ("ruleset bypass actors not observable with read-only token",)
REQUIRED_STATUS_CHECKS = tuple(
    sorted(
        (
            "P00 protected control-plane / verify",
            "P00 bootstrap cross-platform / aggregate",
        )
    )
)
EXPECTED_RULE_TYPES = (
    "deletion",
    "non_fast_forward",
    "pull_request",
    "required_linear_history",
    "required_signatures",
    "required_status_checks",
)
ACTOR = {
    "principal": "github-actions:whyiug/agentapi-doctor:p00-state-writer",
    "role": "protected-workflow",
    "organization": "github-actions",
}
REQUEST_ID = "P00.B00-R3"
PLAN_VERSION = "1.0"
WORK_UNITS = tuple(f"P00.W0{index}" for index in range(1, 6))

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_PATH_RE = re.compile(
    r"^\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$"
)
REQUIRED_CLAIM_PINS = frozenset(
    {
        "repository",
        "repository_id",
        "repository_owner",
        "repository_owner_id",
        "repository_visibility",
        "event_name",
        "ref",
        "ref_type",
        "ref_protected",
        "runner_environment",
        "actor_id",
        "workflow_ref",
        "workflow_sha",
        "sha",
    }
)
RESERVED_DYNAMIC_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "jti",
        "run_id",
        "run_number",
        "run_attempt",
        "check_run_id",
        "nbf",
        "iat",
        "exp",
    }
)
MAX_OIDC_RESPONSE_BYTES = 65536
MAX_GITHUB_API_RESPONSE_BYTES = 1048576

TokenProvider = Callable[[str], str]
RepositoryProtectionProvider = Callable[[], Mapping[str, Any]]


@dataclass
class StateWriterError(ValueError):
    """Stable, secret-free failure from the protected writer."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> None:
    raise StateWriterError(code, path, message)


def _digest(value: Any, path: str) -> str:
    try:
        return sha256_bytes(canonical_json_bytes(value))
    except DigestError as exc:
        _fail("invalid_canonical_input", path, str(exc))


def _require_digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _require_commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        _fail("invalid_source_commit", path, "expected a lowercase 40-hex Git SHA-1")
    return value


def _timestamp(value: datetime | str) -> tuple[datetime, str]:
    if isinstance(value, str):
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            _fail(
                "invalid_timestamp",
                "statementTimestamp",
                "expected second-precision RFC3339 UTC timestamp",
            )
        return parsed, value
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(
            "invalid_timestamp",
            "statementTimestamp",
            "timestamp must be a timezone-aware datetime or RFC3339 UTC string",
        )
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail(
            "invalid_timestamp",
            "statementTimestamp",
            "timestamp must have second precision",
        )
    return normalized, normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_approval(
    approval_result: Mapping[str, Any],
    *,
    source_commit: str,
    control_plane_digest: str,
    trust_policy_digest: str,
    workflow_execution_commit: str,
) -> None:
    if not isinstance(approval_result, Mapping):
        _fail("invalid_approval_result", "approvalResult", "must be an object")
    if approval_result.get("status") != "verified":
        _fail(
            "approval_not_verified",
            "approvalResult.status",
            "Genesis requires the result of successful approval verification",
        )
    if approval_result.get("decision") != "APPROVE":
        _fail(
            "approval_not_valid_for_genesis",
            "approvalResult.decision",
            "Genesis requires an independently verified APPROVE decision",
        )
    _require_digest(approval_result.get("approvalDigest"), "approvalResult.approvalDigest")
    _require_digest(approval_result.get("requestDigest"), "approvalResult.requestDigest")
    if approval_result.get("candidateSourceCommit") != source_commit:
        _fail(
            "source_commit_mismatch",
            "approvalResult.candidateSourceCommit",
            "writer source differs from the approved candidate",
        )
    if approval_result.get("controlPlaneDigest") != control_plane_digest:
        _fail(
            "control_plane_digest_mismatch",
            "approvalResult.controlPlaneDigest",
            "writer control plane differs from the approved candidate",
        )
    if approval_result.get("trustPolicyDigest") != trust_policy_digest:
        _fail(
            "trust_policy_digest_mismatch",
            "approvalResult.trustPolicyDigest",
            "writer policy differs from the verified approval policy",
        )
    if approval_result.get("workflowExecutionCommit") != workflow_execution_commit:
        _fail(
            "workflow_execution_commit_mismatch",
            "approvalResult.workflowExecutionCommit",
            "workflow execution commit differs from the independently approved commit",
        )


def _contract_digest_set(contract_digests: Mapping[str, str]) -> tuple[str, dict[str, str]]:
    if not isinstance(contract_digests, Mapping):
        _fail("invalid_contract_digests", "contractDigests", "must be an object")
    aggregate_path = "execution/phases/P00.yaml"
    aggregate = _require_digest(
        contract_digests.get(aggregate_path), f"contractDigests.{aggregate_path}"
    )
    units: dict[str, str] = {}
    for unit in WORK_UNITS:
        path = f"execution/work-units/{unit}.yaml"
        units[unit] = _require_digest(
            contract_digests.get(path), f"contractDigests.{path}"
        )
    return aggregate, units


def _jwks_keys_and_digest(
    approved_jwks: Any, *, expected_jwks_snapshot_digest: str
) -> tuple[Any, str]:
    snapshot = deepcopy(approved_jwks)
    # Validate the complete independently pinned snapshot before token
    # acquisition so malformed repository input cannot trigger a request.
    result = validate_jwks_snapshot(
        snapshot, expected_snapshot_digest=expected_jwks_snapshot_digest
    )
    return snapshot["keys"], result["digest"]


def _claims_policy(
    expected_claims: Mapping[str, str],
    *,
    workflow_execution_commit: str,
    workflow_path: str,
) -> tuple[dict[str, str], str]:
    if not isinstance(expected_claims, Mapping):
        _fail("invalid_claims_policy", "expectedClaims", "must be an object")
    claims = dict(expected_claims)
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in claims.items()
    ):
        _fail(
            "invalid_claims_policy",
            "expectedClaims",
            "claim names and exact policy values must be strings",
        )
    missing = REQUIRED_CLAIM_PINS - set(claims)
    if missing:
        _fail(
            "incomplete_claims_policy",
            "expectedClaims",
            f"missing protected claim pins: {sorted(missing)}",
        )
    reserved = RESERVED_DYNAMIC_CLAIMS & set(claims)
    if reserved:
        _fail(
            "invalid_claims_policy",
            "expectedClaims",
            f"dynamic/signature claims are verifier-owned: {sorted(reserved)}",
        )
    if claims["repository"] != REPOSITORY:
        _fail(
            "repository_claim_mismatch",
            "expectedClaims.repository",
            "writer is restricted to whyiug/agentapi-doctor",
        )
    if (
        claims["sha"] != workflow_execution_commit
        or claims["workflow_sha"] != workflow_execution_commit
    ):
        _fail(
            "source_claim_mismatch",
            "expectedClaims",
            "sha and workflow_sha must bind the independently approved workflow execution commit",
        )
    workflow_prefix = f"{REPOSITORY}/{workflow_path}@"
    workflow_ref = claims["workflow_ref"]
    if not workflow_ref.startswith(workflow_prefix) or not workflow_ref.removeprefix(
        workflow_prefix
    ):
        _fail(
            "workflow_claim_mismatch",
            "expectedClaims.workflow_ref",
            "workflow_ref must bind the declared repository workflow path and ref",
        )
    return claims, _digest(claims, "expectedClaims")


def _api_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_repository_protection_evidence", path, "must be an object")
    return value


def _api_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(
            "invalid_repository_protection_evidence",
            path,
            "must be a non-empty string",
        )
    return value


def _api_id(value: Any, path: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(
            "invalid_repository_protection_evidence",
            path,
            "must be a positive GitHub numeric ID",
        )
    return str(value)


def _api_array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail("invalid_repository_protection_evidence", path, "must be an array")
    return value


def _normalize_rules(
    raw_rules: Any,
    *,
    path: str,
    expected_ruleset_id: int | None = None,
) -> list[dict[str, Any]]:
    rules = _api_array(raw_rules, path)
    normalized: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(rules):
        rule_path = f"{path}[{index}]"
        rule = _api_object(raw_rule, rule_path)
        rule_type = _api_string(rule.get("type"), f"{rule_path}.type")
        if expected_ruleset_id is not None:
            if (
                rule.get("ruleset_id") != expected_ruleset_id
                or rule.get("ruleset_source_type") != "Repository"
                or rule.get("ruleset_source") != REPOSITORY
            ):
                _fail(
                    "effective_ruleset_mismatch",
                    rule_path,
                    "effective rule is not sourced by the single expected ruleset",
                )
        if rule_type in {
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "required_signatures",
        }:
            normalized.append({"type": rule_type})
            continue
        parameters = _api_object(rule.get("parameters"), f"{rule_path}.parameters")
        if rule_type == "pull_request":
            projected = {
                "dismissStaleReviewsOnPush": parameters.get(
                    "dismiss_stale_reviews_on_push"
                ),
                "requireCodeOwnerReview": parameters.get(
                    "require_code_owner_review"
                ),
                "requireLastPushApproval": parameters.get(
                    "require_last_push_approval"
                ),
                "requiredApprovingReviewCount": parameters.get(
                    "required_approving_review_count"
                ),
                "requiredReviewThreadResolution": parameters.get(
                    "required_review_thread_resolution"
                ),
            }
            if projected != {
                "dismissStaleReviewsOnPush": True,
                "requireCodeOwnerReview": True,
                "requireLastPushApproval": True,
                "requiredApprovingReviewCount": 1,
                "requiredReviewThreadResolution": True,
            }:
                _fail(
                    "repository_ruleset_weakened",
                    f"{rule_path}.parameters",
                    "pull-request protections differ from approved controls",
                )
            normalized.append({"type": rule_type, "parameters": projected})
            continue
        if rule_type == "required_status_checks":
            if parameters.get("strict_required_status_checks_policy") is not True:
                _fail(
                    "required_status_checks_mismatch",
                    f"{rule_path}.parameters.strict_required_status_checks_policy",
                    "required status checks must use the strict policy",
                )
            raw_checks = _api_array(
                parameters.get("required_status_checks"),
                f"{rule_path}.parameters.required_status_checks",
            )
            checks: list[dict[str, Any]] = []
            for check_index, raw_check in enumerate(raw_checks):
                check_path = (
                    f"{rule_path}.parameters.required_status_checks[{check_index}]"
                )
                check = _api_object(raw_check, check_path)
                context = _api_string(check.get("context"), f"{check_path}.context")
                integration_id = check.get("integration_id")
                if integration_id is not None and (
                    isinstance(integration_id, bool)
                    or not isinstance(integration_id, int)
                    or integration_id <= 0
                ):
                    _fail(
                        "invalid_repository_protection_evidence",
                        f"{check_path}.integration_id",
                        "integration ID must be a positive integer when observable",
                    )
                checks.append(
                    {"context": context, "integrationId": integration_id}
                )
            checks.sort(key=lambda item: item["context"].encode("utf-8"))
            if (
                [item["context"] for item in checks]
                != list(REQUIRED_STATUS_CHECKS)
                or len(checks) != len({item["context"] for item in checks})
            ):
                _fail(
                    "required_status_checks_mismatch",
                    f"{rule_path}.parameters.required_status_checks",
                    "required checks must exactly equal the approved check set",
                )
            normalized.append(
                {
                    "type": rule_type,
                    "parameters": {
                        "strictRequiredStatusChecksPolicy": True,
                        "requiredStatusChecks": checks,
                    },
                }
            )
            continue
        _fail(
            "unexpected_active_rule",
            rule_path,
            "effective rules contain an unapproved rule type",
        )
    normalized.sort(key=lambda item: item["type"].encode("utf-8"))
    if [item["type"] for item in normalized] != list(EXPECTED_RULE_TYPES):
        _fail(
            "repository_ruleset_mismatch",
            path,
            "active rules must exactly equal the approved rule type set",
        )
    return normalized


def _repository_protection_observation(
    api_evidence: Any,
    *,
    expected_claims: Mapping[str, str],
    workflow_execution_commit: str,
    observed_at: str,
) -> dict[str, Any]:
    """Normalize public Rulesets evidence and its explicit API limitation."""

    evidence = _api_object(api_evidence, "githubApi")
    if set(evidence) != {
        "repository",
        "branch",
        "effectiveRules",
        "rulesets",
        "rulesetDetail",
    }:
        _fail(
            "invalid_repository_protection_evidence",
            "githubApi",
            "expected exact repository, branch, rules, rulesets, and detail responses",
        )
    repository = _api_object(evidence["repository"], "githubApi.repository")
    owner = _api_object(repository.get("owner"), "githubApi.repository.owner")
    repository_facts = {
        "id": _api_id(repository.get("id"), "githubApi.repository.id"),
        "owner": _api_string(owner.get("login"), "githubApi.repository.owner.login"),
        "ownerId": _api_id(owner.get("id"), "githubApi.repository.owner.id"),
        "name": _api_string(repository.get("name"), "githubApi.repository.name"),
        "fullName": _api_string(
            repository.get("full_name"), "githubApi.repository.full_name"
        ),
        "visibility": _api_string(
            repository.get("visibility"), "githubApi.repository.visibility"
        ),
        "defaultBranch": _api_string(
            repository.get("default_branch"), "githubApi.repository.default_branch"
        ),
    }
    if repository.get("private") is not False:
        _fail("repository_not_public", "githubApi.repository.private", "must be public")
    expected_repository = {
        "id": REPOSITORY_ID,
        "owner": REPOSITORY_OWNER,
        "ownerId": REPOSITORY_OWNER_ID,
        "name": REPOSITORY_NAME,
        "fullName": REPOSITORY,
        "visibility": "public",
        "defaultBranch": PROTECTED_BRANCH,
    }
    if repository_facts != expected_repository or any(
        (
            expected_claims["repository_id"] != REPOSITORY_ID,
            expected_claims["repository_owner"] != REPOSITORY_OWNER,
            expected_claims["repository_owner_id"] != REPOSITORY_OWNER_ID,
            expected_claims["repository"] != REPOSITORY,
            expected_claims["repository_visibility"] != "public",
        )
    ):
        _fail(
            "repository_identity_mismatch",
            "githubApi.repository",
            "repository identity/public visibility differs from approved claims",
        )

    branch = _api_object(evidence["branch"], "githubApi.branch")
    commit = _api_object(branch.get("commit"), "githubApi.branch.commit")
    branch_facts = {
        "name": _api_string(branch.get("name"), "githubApi.branch.name"),
        "protected": branch.get("protected"),
        "commitSha": _api_string(commit.get("sha"), "githubApi.branch.commit.sha"),
    }
    if branch_facts != {
        "name": PROTECTED_BRANCH,
        "protected": True,
        "commitSha": workflow_execution_commit,
    }:
        _fail(
            "branch_not_protected",
            "githubApi.branch",
            "main must be protected at the approved workflow commit",
        )
    if (
        expected_claims["ref"] != f"refs/heads/{PROTECTED_BRANCH}"
        or expected_claims["ref_type"] != "branch"
        or expected_claims["ref_protected"] != "true"
    ):
        _fail(
            "repository_protection_claim_mismatch",
            "expectedClaims",
            "OIDC claims must independently bind protected main",
        )

    active_summaries = []
    for index, raw_summary in enumerate(
        _api_array(evidence["rulesets"], "githubApi.rulesets")
    ):
        summary = _api_object(raw_summary, f"githubApi.rulesets[{index}]")
        if summary.get("enforcement") == "active" and summary.get("target") == "branch":
            active_summaries.append(summary)
    if len(active_summaries) != 1:
        _fail(
            "repository_ruleset_mismatch",
            "githubApi.rulesets",
            "exactly one active branch ruleset must be observable",
        )
    summary = active_summaries[0]
    ruleset_id = summary.get("id")
    if (
        isinstance(ruleset_id, bool)
        or not isinstance(ruleset_id, int)
        or ruleset_id <= 0
        or summary.get("name") != EXPECTED_RULESET_NAME
        or summary.get("source_type") != "Repository"
        or summary.get("source") != REPOSITORY
    ):
        _fail(
            "repository_ruleset_mismatch",
            "githubApi.rulesets",
            "active ruleset identity/source differs from policy",
        )

    detail = _api_object(evidence["rulesetDetail"], "githubApi.rulesetDetail")
    if (
        detail.get("id") != ruleset_id
        or detail.get("name") != EXPECTED_RULESET_NAME
        or detail.get("target") != "branch"
        or detail.get("source_type") != "Repository"
        or detail.get("source") != REPOSITORY
        or detail.get("enforcement") != "active"
    ):
        _fail(
            "repository_ruleset_mismatch",
            "githubApi.rulesetDetail",
            "ruleset detail identity/source/enforcement mismatch",
        )
    conditions = _api_object(
        detail.get("conditions"), "githubApi.rulesetDetail.conditions"
    )
    if set(conditions) != {"ref_name"}:
        _fail(
            "repository_ruleset_conditions_mismatch",
            "githubApi.rulesetDetail.conditions",
            "repository ruleset must have only an exact ref-name condition",
        )
    ref_name = _api_object(
        conditions["ref_name"], "githubApi.rulesetDetail.conditions.ref_name"
    )
    normalized_conditions = {
        "refName": {
            "include": ref_name.get("include"),
            "exclude": ref_name.get("exclude"),
        }
    }
    if normalized_conditions != {
        "refName": {"include": ["refs/heads/main"], "exclude": []}
    }:
        _fail(
            "repository_ruleset_conditions_mismatch",
            "githubApi.rulesetDetail.conditions.ref_name",
            "ruleset must target only refs/heads/main",
        )
    detail_rules = _normalize_rules(
        detail.get("rules"), path="githubApi.rulesetDetail.rules"
    )
    effective_rules = _normalize_rules(
        evidence["effectiveRules"],
        path="githubApi.effectiveRules",
        expected_ruleset_id=ruleset_id,
    )
    if effective_rules != detail_rules:
        _fail(
            "effective_ruleset_mismatch",
            "githubApi.effectiveRules",
            "effective branch rules differ from the active ruleset detail",
        )
    detail_projection = {
        "id": ruleset_id,
        "name": EXPECTED_RULESET_NAME,
        "target": "branch",
        "sourceType": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
        "conditions": normalized_conditions,
        "rules": detail_rules,
    }
    ruleset = {
        **detail_projection,
        "detailDigest": _digest(
            detail_projection, "repositoryProtection.rulesetDetail"
        ),
    }
    observation: dict[str, Any] = {
        "schemaVersion": REPOSITORY_PROTECTION_SCHEMA,
        "source": "github-rulesets-rest-api-2022-11-28",
        "observedAt": observed_at,
        "repository": repository_facts,
        "branch": branch_facts,
        "ruleset": ruleset,
        "effectiveRules": effective_rules,
        "apiLimitations": list(API_LIMITATIONS),
    }
    observation["apiEvidenceDigest"] = _digest(
        {
            key: observation[key]
            for key in (
                "repository",
                "branch",
                "ruleset",
                "effectiveRules",
                "apiLimitations",
            )
        },
        "repositoryProtection.apiEvidence",
    )
    return observation


def _initial_state(
    *,
    timestamp: str,
    source_commit: str,
    control_plane_digest: str,
    aggregate_contract_digest: str,
    work_unit_contract_digests: Mapping[str, str],
    approval_digest: str,
) -> dict[str, Any]:
    units: dict[str, Any] = {}
    for unit in WORK_UNITS:
        active = unit == "P00.W01"
        units[unit] = {
            "status": "ACTIVE" if active else "NOT_STARTED",
            "contractDigest": work_unit_contract_digests[unit],
            "approvalDigest": approval_digest if active else None,
            "sourceCommit": source_commit if active else None,
        }
    return {
        "planVersion": PLAN_VERSION,
        "controlPlaneDigest": control_plane_digest,
        "activePhase": "P00",
        "activeWorkUnit": "P00.W01",
        "pendingWorkUnit": None,
        "phases": {
            "P00": {
                "status": "ACTIVE",
                "aggregateContractDigest": aggregate_contract_digest,
                "controlPlaneDigest": control_plane_digest,
                "baseCommit": source_commit,
                "startedAt": timestamp,
                "workUnits": units,
            }
        },
    }


def github_repository_protection_provider(
    *,
    environ: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> Mapping[str, Any]:
    """Read public repository Rulesets evidence through GitHub's REST API.

    This provider has no mutation path.  It uses the ephemeral workflow token
    only for fixed GET requests and returns strict JSON documents for
    normalization by :func:`create_genesis_event`.
    """

    environment = os.environ if environ is None else environ
    if environment.get("GITHUB_ACTIONS") != "true":
        _fail(
            "not_github_actions",
            "environment.GITHUB_ACTIONS",
            "repository protection may be observed only in GitHub Actions",
        )
    expected_environment = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
        "GITHUB_REPOSITORY_OWNER": REPOSITORY_OWNER,
        "GITHUB_REPOSITORY_OWNER_ID": REPOSITORY_OWNER_ID,
        "GITHUB_REF": f"refs/heads/{PROTECTED_BRANCH}",
        "GITHUB_REF_PROTECTED": "true",
    }
    for name, expected in expected_environment.items():
        if environment.get(name) != expected:
            _fail(
                "unsafe_github_environment",
                f"environment.{name}",
                "GitHub workflow repository/ref identity mismatch",
            )
    _require_commit(environment.get("GITHUB_SHA"), "environment.GITHUB_SHA")
    token = environment.get("GITHUB_TOKEN")
    if not token:
        _fail(
            "missing_github_token",
            "environment.GITHUB_TOKEN",
            "ephemeral read-only GitHub workflow token is unavailable",
        )
    opener = request.urlopen if urlopen is None else urlopen

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(
                    "invalid_github_api_response",
                    "githubApi",
                    "GitHub API response contains a duplicate key",
                )
            result[key] = value
        return result

    def fetch(label: str, endpoint: str, *, array: bool) -> Any:
        api_request = request.Request(
            endpoint,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
            method="GET",
        )
        try:
            with opener(api_request, timeout=10) as response:
                status = response.getcode()
                payload = response.read(MAX_GITHUB_API_RESPONSE_BYTES + 1)
                headers = getattr(response, "headers", {})
                link = headers.get("Link", "") if hasattr(headers, "get") else ""
        except Exception:
            _fail(
                "github_api_request_failed",
                f"githubApi.{label}",
                "read-only GitHub API request failed",
            )
        if status != 200:
            _fail(
                "github_api_request_failed",
                f"githubApi.{label}",
                "GitHub API did not return HTTP 200",
            )
        if 'rel="next"' in link:
            _fail(
                "github_api_pagination_unresolved",
                f"githubApi.{label}",
                "Rulesets evidence exceeds the single bounded API page",
            )
        if len(payload) > MAX_GITHUB_API_RESPONSE_BYTES:
            _fail(
                "github_api_response_too_large",
                f"githubApi.{label}",
                "GitHub API response is too large",
            )
        try:
            document = json.loads(
                payload.decode("utf-8"), object_pairs_hook=unique_pairs
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail(
                "invalid_github_api_response",
                f"githubApi.{label}",
                "GitHub API response is not strict UTF-8 JSON",
            )
        expected_type = list if array else dict
        if not isinstance(document, expected_type):
            _fail(
                "invalid_github_api_response",
                f"githubApi.{label}",
                "GitHub API response has the wrong top-level type",
            )
        return document

    endpoints = {
        "repository": f"{GITHUB_API_ROOT}/repos/{REPOSITORY}",
        "branch": f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/branches/{PROTECTED_BRANCH}",
        "effectiveRules": (
            f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/rules/branches/"
            f"{PROTECTED_BRANCH}?per_page=100&page=1"
        ),
        "rulesets": (
            f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/rulesets?"
            "includes_parents=true&targets=branch&per_page=100&page=1"
        ),
    }
    documents = {
        label: fetch(
            label,
            endpoint,
            array=label in {"effectiveRules", "rulesets"},
        )
        for label, endpoint in endpoints.items()
    }
    expected_summaries = [
        item
        for item in documents["rulesets"]
        if isinstance(item, dict)
        and item.get("name") == EXPECTED_RULESET_NAME
        and item.get("target") == "branch"
        and item.get("source_type") == "Repository"
        and item.get("source") == REPOSITORY
        and item.get("enforcement") == "active"
    ]
    if len(expected_summaries) != 1:
        _fail(
            "repository_ruleset_mismatch",
            "githubApi.rulesets",
            "cannot select one exact active repository ruleset",
        )
    ruleset_id = expected_summaries[0].get("id")
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        _fail(
            "repository_ruleset_mismatch",
            "githubApi.rulesets.id",
            "selected ruleset has no stable numeric ID",
        )
    documents["rulesetDetail"] = fetch(
        "rulesetDetail",
        (
            f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/rulesets/{ruleset_id}"
            "?includes_parents=true"
        ),
        array=False,
    )
    return documents


def github_actions_token_provider(
    audience: str,
    *,
    environ: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> str:
    """Request one OIDC token, but only inside a genuine Actions environment.

    The bearer credential and returned JWT are never placed in an exception or
    log message.  ``urlopen`` exists solely to make the boundary locally
    testable without network access.
    """

    environment = os.environ if environ is None else environ
    if environment.get("GITHUB_ACTIONS") != "true":
        _fail(
            "not_github_actions",
            "environment.GITHUB_ACTIONS",
            "default token acquisition is restricted to GitHub Actions",
        )
    endpoint = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not endpoint or not bearer:
        _fail(
            "missing_oidc_environment",
            "environment",
            "GitHub Actions OIDC request variables are unavailable",
        )
    if not isinstance(audience, str) or not audience.startswith(OIDC_AUDIENCE_PREFIX):
        _fail("invalid_audience", "audience", "writer audience prefix mismatch")
    parsed = parse.urlsplit(endpoint)
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not hostname.endswith(".actions.githubusercontent.com")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        _fail(
            "unsafe_oidc_endpoint",
            "environment.ACTIONS_ID_TOKEN_REQUEST_URL",
            "OIDC endpoint must be an HTTPS GitHub Actions host",
        )
    query = parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(name == "audience" for name, _ in query):
        _fail(
            "unsafe_oidc_endpoint",
            "environment.ACTIONS_ID_TOKEN_REQUEST_URL",
            "OIDC request URL must not preselect an audience",
        )
    query.append(("audience", audience))
    target = parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parse.urlencode(query), "")
    )
    oidc_request = request.Request(
        target,
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        method="GET",
    )
    opener = request.urlopen if urlopen is None else urlopen
    try:
        with opener(oidc_request, timeout=10) as response:
            payload = response.read(MAX_OIDC_RESPONSE_BYTES + 1)
    except Exception:
        _fail(
            "oidc_request_failed",
            "tokenProvider",
            "GitHub Actions OIDC token request failed",
        )
    if len(payload) > MAX_OIDC_RESPONSE_BYTES:
        _fail("oidc_response_too_large", "tokenProvider", "OIDC response is too large")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(
                    "invalid_oidc_response",
                    "tokenProvider",
                    "OIDC response contains a duplicate key",
                )
            result[key] = value
        return result

    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(
            "invalid_oidc_response",
            "tokenProvider",
            "OIDC response is not strict UTF-8 JSON",
        )
    if not isinstance(document, dict) or set(document) != {"value"}:
        _fail(
            "invalid_oidc_response",
            "tokenProvider",
            "OIDC response field set is invalid",
        )
    token = document["value"]
    if not isinstance(token, str) or not token or not token.isascii():
        _fail("invalid_oidc_response", "tokenProvider", "OIDC JWT is invalid")
    return token


def create_genesis_event(
    *,
    approval_result: Mapping[str, Any],
    contract_digests: Mapping[str, str],
    source_commit: str,
    control_plane_digest: str,
    trust_policy_digest: str,
    approved_jwks: Any,
    expected_jwks_snapshot_digest: str,
    expected_claims: Mapping[str, str],
    workflow_path: str,
    workflow_execution_commit: str,
    statement_timestamp: datetime | str,
    repository_protection_provider: RepositoryProtectionProvider | None = None,
    token_provider: TokenProvider | None = None,
) -> dict[str, Any]:
    """Construct and self-verify the sole P00 Genesis event in memory."""

    source_commit = _require_commit(source_commit, "sourceCommit")
    control_plane_digest = _require_digest(control_plane_digest, "controlPlaneDigest")
    trust_policy_digest = _require_digest(trust_policy_digest, "trustPolicyDigest")
    workflow_execution_commit = _require_commit(
        workflow_execution_commit, "workflowExecutionCommit"
    )
    expected_jwks_snapshot_digest = _require_digest(
        expected_jwks_snapshot_digest, "expectedJwksSnapshotDigest"
    )
    if not isinstance(workflow_path, str) or not WORKFLOW_PATH_RE.fullmatch(workflow_path):
        _fail(
            "invalid_workflow_path",
            "workflowPath",
            "expected one top-level .github/workflows/*.yml path",
        )
    timestamp_value, timestamp_text = _timestamp(statement_timestamp)
    _validate_approval(
        approval_result,
        source_commit=source_commit,
        control_plane_digest=control_plane_digest,
        trust_policy_digest=trust_policy_digest,
        workflow_execution_commit=workflow_execution_commit,
    )
    aggregate_digest, unit_digests = _contract_digest_set(contract_digests)
    jwks_keys, jwks_digest = _jwks_keys_and_digest(
        approved_jwks,
        expected_jwks_snapshot_digest=expected_jwks_snapshot_digest,
    )
    claims, claims_digest = _claims_policy(
        expected_claims,
        workflow_execution_commit=workflow_execution_commit,
        workflow_path=workflow_path,
    )
    protection_provider = (
        github_repository_protection_provider
        if repository_protection_provider is None
        else repository_protection_provider
    )
    try:
        api_evidence = protection_provider()
    except StateWriterError:
        raise
    except Exception:
        _fail(
            "repository_protection_provider_failed",
            "repositoryProtectionProvider",
            "injected repository protection provider failed",
        )
    repository_protection = _repository_protection_observation(
        api_evidence,
        expected_claims=claims,
        workflow_execution_commit=workflow_execution_commit,
        observed_at=timestamp_text,
    )
    approval_digest = approval_result["approvalDigest"]
    state = _initial_state(
        timestamp=timestamp_text,
        source_commit=source_commit,
        control_plane_digest=control_plane_digest,
        aggregate_contract_digest=aggregate_digest,
        work_unit_contract_digests=unit_digests,
        approval_digest=approval_digest,
    )
    body = {
        "eventType": "Genesis",
        "eventId": "evt-00000000",
        "sequence": 0,
        "previousDigest": None,
        "timestamp": timestamp_text,
        "actor": deepcopy(ACTOR),
        "sourceCommit": source_commit,
        "controlPlaneDigest": control_plane_digest,
        "trustPolicyDigest": trust_policy_digest,
        "reasonCode": "approved-bootstrap-genesis",
        "reason": "Protected GitHub Actions writer activated approved P00/P00.W01.",
        "repositoryProtection": repository_protection,
        "writer": {
            "jwksSnapshotDigest": jwks_digest,
            "claimsPolicyDigest": claims_digest,
            "workflowPath": workflow_path,
            "workflowExecutionCommit": workflow_execution_commit,
        },
        "payload": {
            "requestId": REQUEST_ID,
            "requestDigest": approval_result["requestDigest"],
            "approvalDigest": approval_digest,
            "planVersion": PLAN_VERSION,
            "activePhase": "P00",
            "activeWorkUnit": "P00.W01",
            "pendingWorkUnit": None,
            "aggregateContractDigest": aggregate_digest,
            "workUnitContractDigests": unit_digests,
            "resultingStateDigest": _digest(state, "resultingState"),
        },
    }
    statement = {
        "schemaVersion": STATE_EVENT_SCHEMA,
        "kind": STATE_EVENT_KIND,
        "body": body,
    }
    statement_digest = _digest(statement, "statement")
    audience = OIDC_AUDIENCE_PREFIX + statement_digest
    provider = github_actions_token_provider if token_provider is None else token_provider
    try:
        token = provider(audience)
    except StateWriterError:
        raise
    except Exception:
        _fail(
            "token_provider_failed",
            "tokenProvider",
            "injected OIDC token provider failed",
        )
    if not isinstance(token, str):
        _fail("invalid_oidc_token", "tokenProvider", "token provider returned no JWT")
    verified_claims = verify_github_actions_oidc_token(
        token,
        approved_jwks=jwks_keys,
        expected_audience=audience,
        expected_claims=claims,
        statement_timestamp=timestamp_value,
    )
    for claim in ("head_ref", "base_ref"):
        if verified_claims.get(claim) not in {None, ""}:
            _fail(
                "oidc_pull_request_claim_forbidden",
                f"jwt.claims.{claim}",
                "workflow_dispatch StateEvent must not carry a pull-request ref",
            )
    envelope = {
        **statement,
        "signature": {
            "scheme": OIDC_SIGNATURE_SCHEME,
            "namespace": STATE_EVENT_NAMESPACE,
            "statementDigest": statement_digest,
            "jwt": token,
        },
    }
    envelope["eventDigest"] = _digest(envelope, "event")
    return envelope


# A descriptive alias for workflow callers; both names retain the same narrow
# in-memory behavior.
build_genesis_event = create_genesis_event
