"""Independent P00 EXTERNAL fact verification from GitHub Actions REST data.

This module implements only ``P00-X-CROSSPLATFORM``.  A signed EXTERNAL
criterion result is still only a producer claim; the callback returned by
``build_p00_crossplatform_fact_verifier`` re-observes one immutable, first
attempt GitHub Actions run and derives ``satisfied`` from the run, workflow,
and jobs responses.  It never accepts a caller-supplied boolean.

Normative sources: Plan section 29.4 (external facts cannot be self-reported),
Plan section 34's P00 convergence list, and
``execution/gates/p00/P00.W01.yaml#P00-X-CROSSPLATFORM``.

GitHub REST shapes are pinned to the official current-version endpoints:
https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run-attempt
and
https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#list-jobs-for-a-workflow-run-attempt.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
import re
import ssl
from typing import Any, NoReturn
from urllib import request

from .digest import canonical_json_bytes, sha256_bytes
from .protected import ProtectedVerificationError
from .provenance import (
    CriterionBinding,
    SubjectBinding,
    VerifiedCriterionResult,
)


EVIDENCE_SCHEMA = "urn:agentapi-doctor:github-actions-cross-platform-evidence:v1alpha1"
EVIDENCE_KIND = "GitHubActionsCrossPlatformEvidence"
FACT_SCHEMA = "urn:agentapi-doctor:github-actions-cross-platform-fact:v1alpha1"
FACT_KIND = "VerifiedGitHubActionsCrossPlatformFact"

CRITERION_ID = "P00-X-CROSSPLATFORM"
EVALUATOR = "attestation://ci/cross-platform/v1"
EVIDENCE_SCHEMA_ID = "evidence-schema://attestation/cross-platform/v1"

REPOSITORY = "whyiug/agentapi-doctor"
REPOSITORY_ID = 1_296_831_403
REPOSITORY_OWNER = "whyiug"
REPOSITORY_OWNER_ID = 6_668_626
REPOSITORY_NAME = "agentapi-doctor"
WORKFLOW_PATH = ".github/workflows/p00-bootstrap-cross-platform.yml"
WORKFLOW_REF = "refs/heads/main"
WORKFLOW_RUN_PATH = f"{WORKFLOW_PATH}@main"
WORKFLOW_NAME = "P00 bootstrap cross-platform"
WORKFLOW_EVENT = "push"
BRANCH = "main"
RUN_ATTEMPT = 1

GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024
API_TIMEOUT_SECONDS = 10

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ENDPOINT_RE = re.compile(
    r"^/repos/whyiug/agentapi-doctor/actions/(?:"
    r"runs/[1-9][0-9]*/attempts/1|"
    r"workflows/[1-9][0-9]*|"
    r"runs/[1-9][0-9]*/attempts/1/jobs\?per_page=100&page=1"
    r")$"
)

PLATFORM_SPECS: tuple[dict[str, Any], ...] = (
    {
        "platform": "Linux",
        "jobName": "ubuntu-24.04",
        "runnerLabel": "ubuntu-24.04",
        "requiredSteps": (
            "Checkout exact revision without credentials",
            "Run dependency-free bootstrap validation",
            "Upload exact platform result",
        ),
    },
    {
        "platform": "macOS",
        "jobName": "macos-14",
        "runnerLabel": "macos-14",
        "requiredSteps": (
            "Checkout exact revision without credentials",
            "Run dependency-free bootstrap validation",
            "Upload exact platform result",
        ),
    },
    {
        "platform": "Windows",
        "jobName": "windows-2022",
        "runnerLabel": "windows-2022",
        "requiredSteps": (
            "Checkout exact revision without credentials",
            "Run dependency-free bootstrap validation",
            "Upload exact platform result",
        ),
    },
    {
        "platform": "aggregate",
        "jobName": "P00 bootstrap cross-platform / aggregate",
        "runnerLabel": "ubuntu-24.04",
        "requiredSteps": (
            "Download all exact platform results",
            "Require three PASS results with one control-plane digest",
            "Upload aggregate candidate evidence",
        ),
    },
)

UNSUPPORTED_P00_EXTERNAL_CRITERIA = frozenset(
    {
        "P00-X-OUTREACH",
        "P00-X-DESIGN-PARTNERS",
        "P00-X-REVIEW",
    }
)

FACT_VERIFIER_SPEC = {
    "schemaVersion": "urn:agentapi-doctor:external-fact-verifier-spec:v1alpha1",
    "kind": "GitHubActionsCrossPlatformFactVerifier",
    "criterionId": CRITERION_ID,
    "evaluator": EVALUATOR,
    "evidenceSchema": EVIDENCE_SCHEMA_ID,
    "repository": {"fullName": REPOSITORY, "id": str(REPOSITORY_ID)},
    "workflow": {
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "ref": WORKFLOW_REF,
        "event": WORKFLOW_EVENT,
    },
    "runAttempt": RUN_ATTEMPT,
    "jobs": [
        {
            "platform": item["platform"],
            "jobName": item["jobName"],
            "runnerLabel": item["runnerLabel"],
            "requiredSteps": list(item["requiredSteps"]),
        }
        for item in PLATFORM_SPECS
    ],
    "requirements": [
        "agentapi-doctor-Plan.md section 29.4",
        "agentapi-doctor-Plan.md section 34 P00-X-CROSSPLATFORM",
        "execution/gates/p00/P00.W01.yaml P00-X-CROSSPLATFORM",
    ],
    "apiReferences": [
        "https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run-attempt",
        "https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#list-jobs-for-a-workflow-run-attempt",
        "https://docs.github.com/en/rest/actions/workflows",
    ],
}
FACT_VERIFIER_DIGEST = sha256_bytes(canonical_json_bytes(FACT_VERIFIER_SPEC))

JsonFetcher = Callable[[str], Mapping[str, Any]]
FactVerifier = Callable[[Mapping[str, Any], VerifiedCriterionResult], Mapping[str, Any]]


class ExternalFactError(ProtectedVerificationError):
    """Stable, secret-free EXTERNAL fact verification failure."""


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise ExternalFactError(code, path, message)


def _exact(value: Any, fields: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(
            "invalid_external_evidence_schema",
            path,
            "field set differs from the versioned schema",
        )
    return value


def _string(value: Any, path: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        _fail("invalid_external_evidence", path, "invalid bounded string")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail("invalid_external_evidence", path, "expected a positive integer")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_external_evidence_digest", path, "invalid SHA-256 digest")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _fail("invalid_external_source_commit", path, "invalid Git commit")
    return value


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail(
                "duplicate_external_evidence_key",
                "externalEvidence",
                "external evidence contains a duplicate key",
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(
        "invalid_external_evidence_json",
        "externalEvidence",
        "non-finite JSON numbers are forbidden",
    )


def _load_evidence(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EVIDENCE_BYTES:
        _fail(
            "invalid_external_evidence_size",
            "externalEvidence",
            "evidence must be non-empty bounded bytes",
        )
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except ExternalFactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail(
            "invalid_external_evidence_json",
            "externalEvidence",
            "evidence is not strict UTF-8 JSON",
        )
    if not isinstance(value, Mapping):
        _fail(
            "invalid_external_evidence_schema",
            "externalEvidence",
            "top level must be an object",
        )
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError):
        _fail(
            "invalid_external_evidence_json",
            "externalEvidence",
            "evidence cannot be canonicalized",
        )
    if canonical != raw:
        _fail(
            "noncanonical_external_evidence",
            "externalEvidence",
            "evidence bytes must be exact canonical JSON",
        )
    return _validate_evidence_document(value)


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


def _validate_subject(value: Any, path: str) -> Mapping[str, Any]:
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
    if subject["phase"] != "P00" or subject["workUnit"] != "P00.W01":
        _fail(
            "unsupported_external_fact_subject",
            path,
            "cross-platform fact verification is scoped to P00.W01",
        )
    _commit(subject["sourceCommit"], f"{path}.sourceCommit")
    _digest(subject["controlPlaneDigest"], f"{path}.controlPlaneDigest")
    _digest(subject["contractDigest"], f"{path}.contractDigest")
    return subject


def _validate_criterion(value: Any, path: str) -> Mapping[str, Any]:
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
    exact = {
        "id": CRITERION_ID,
        "kind": "EXTERNAL",
        "evaluator": EVALUATOR,
        "evaluatorStatus": "external-only",
        "evidenceSchema": EVIDENCE_SCHEMA_ID,
    }
    if any(criterion.get(key) != expected for key, expected in exact.items()):
        _fail(
            "unsupported_external_fact_criterion",
            path,
            "only the exact P00 cross-platform criterion is implemented",
        )
    for field in (
        "evaluatorDigest",
        "evidenceSchemaDigest",
        "datasetDigest",
        "thresholdDigest",
    ):
        _digest(criterion[field], f"{path}.{field}")
    return criterion


def _validate_evidence_document(value: Any) -> Mapping[str, Any]:
    evidence = _exact(
        value,
        {
            "schemaVersion",
            "kind",
            "provider",
            "freezeDigest",
            "subject",
            "criterion",
            "repository",
            "workflow",
            "runId",
            "runAttempt",
            "factEvidenceDigest",
        },
        "externalEvidence",
    )
    if (
        evidence["schemaVersion"] != EVIDENCE_SCHEMA
        or evidence["kind"] != EVIDENCE_KIND
        or evidence["provider"] != "github-actions-rest"
    ):
        _fail(
            "unsupported_external_evidence",
            "externalEvidence",
            "unsupported evidence schema, kind, or provider",
        )
    _digest(evidence["freezeDigest"], "externalEvidence.freezeDigest")
    _validate_subject(evidence["subject"], "externalEvidence.subject")
    _validate_criterion(evidence["criterion"], "externalEvidence.criterion")
    repository = _exact(
        evidence["repository"], {"fullName", "id"}, "externalEvidence.repository"
    )
    if repository != {"fullName": REPOSITORY, "id": str(REPOSITORY_ID)}:
        _fail(
            "external_repository_binding_mismatch",
            "externalEvidence.repository",
            "repository differs from the approved P00 repository",
        )
    workflow = _exact(
        evidence["workflow"],
        {"name", "path", "ref"},
        "externalEvidence.workflow",
    )
    if workflow != {
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "ref": WORKFLOW_REF,
    }:
        _fail(
            "external_workflow_binding_mismatch",
            "externalEvidence.workflow",
            "workflow identity differs from the approved P00 workflow",
        )
    _integer(evidence["runId"], "externalEvidence.runId")
    attempt = _integer(evidence["runAttempt"], "externalEvidence.runAttempt")
    if attempt != RUN_ATTEMPT:
        _fail(
            "external_rerun_forbidden",
            "externalEvidence.runAttempt",
            "only the first workflow attempt is admissible",
        )
    _digest(evidence["factEvidenceDigest"], "externalEvidence.factEvidenceDigest")
    return evidence


def _require_result_binding(
    envelope: Mapping[str, Any],
    result: VerifiedCriterionResult,
    evidence: Mapping[str, Any],
) -> None:
    if not isinstance(result, VerifiedCriterionResult):
        _fail(
            "invalid_external_fact_result",
            "criterionResult",
            "VerifiedCriterionResult is required",
        )
    if not isinstance(envelope, Mapping):
        _fail(
            "invalid_external_fact_result",
            "criterionResult",
            "criterion envelope is required",
        )
    body = envelope.get("body")
    if not isinstance(body, Mapping):
        _fail(
            "invalid_external_fact_result",
            "criterionResult.body",
            "criterion body is required",
        )
    if (
        envelope.get("attestationDigest") != result.attestation_digest
        or body.get("evidenceDigest") != result.evidence_digest
    ):
        _fail(
            "external_attestation_binding_mismatch",
            "criterionResult",
            "fact verifier received a copied or different attestation",
        )
    if result.outcome != "ATTESTED" or not result.signature_verified:
        _fail(
            "invalid_external_fact_result",
            "criterionResult",
            "a signature-verified EXTERNAL ATTESTED result is required",
        )
    expected_subject = _subject_document(result.subject)
    expected_criterion = _criterion_document(result.criterion)
    if evidence["subject"] != expected_subject:
        _fail(
            "external_subject_binding_mismatch",
            "externalEvidence.subject",
            "evidence belongs to a different source or contract",
        )
    if evidence["criterion"] != expected_criterion:
        _fail(
            "external_criterion_binding_mismatch",
            "externalEvidence.criterion",
            "evidence belongs to a different criterion binding",
        )
    if evidence["freezeDigest"] != result.freeze_digest:
        _fail(
            "external_freeze_binding_mismatch",
            "externalEvidence.freezeDigest",
            "evidence belongs to a different protected-input freeze",
        )


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _default_urlopen(api_request: request.Request, timeout: int):
    context = ssl.create_default_context()
    opener = request.build_opener(
        request.ProxyHandler({}),
        request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )
    return opener.open(api_request, timeout=timeout)


def _strict_api_json(raw: bytes, path: str) -> Mapping[str, Any]:
    def api_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail(
                    "invalid_github_api_response",
                    path,
                    "GitHub API response contains a duplicate key",
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=api_pairs,
            parse_constant=lambda _value: _fail(
                "invalid_github_api_response",
                path,
                "GitHub API response contains a non-finite number",
            ),
        )
    except ExternalFactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail(
            "invalid_github_api_response",
            path,
            "GitHub API response is not strict UTF-8 JSON",
        )
    if not isinstance(value, Mapping):
        _fail(
            "invalid_github_api_response",
            path,
            "GitHub API response must be an object",
        )
    return value


def github_actions_rest_fetch(
    endpoint: str,
    *,
    environ: Mapping[str, str] | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> Mapping[str, Any]:
    """Fetch one fixed read-only GitHub Actions REST resource.

    Only three endpoint shapes under the exact approved repository are
    accepted.  The production opener uses normal certificate and hostname
    validation, disables environment proxies, and refuses redirects.
    """

    if not isinstance(endpoint, str) or ENDPOINT_RE.fullmatch(endpoint) is None:
        _fail(
            "unsafe_github_api_endpoint",
            "githubApi.endpoint",
            "endpoint is outside the fixed read-only GitHub Actions API scope",
        )
    environment = os.environ if environ is None else environ
    token = environment.get(GITHUB_TOKEN_ENV)
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 4096
        or not token.isascii()
        or any(character.isspace() for character in token)
    ):
        _fail(
            "missing_github_token",
            f"environment.{GITHUB_TOKEN_ENV}",
            "a bounded GitHub token must be supplied through the environment",
        )
    url = GITHUB_API_ROOT + endpoint
    api_request = request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "agentapi-doctor-p00-external-fact-verifier",
        },
        method="GET",
    )
    opener = _default_urlopen if urlopen is None else urlopen
    try:
        with opener(api_request, timeout=API_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            final_url = response.geturl() if hasattr(response, "geturl") else url
            headers = getattr(response, "headers", {})
            content_length = (
                headers.get("Content-Length") if hasattr(headers, "get") else None
            )
            content_encoding = (
                headers.get("Content-Encoding", "") if hasattr(headers, "get") else ""
            )
            content_type = (
                headers.get("Content-Type", "application/json")
                if hasattr(headers, "get")
                else "application/json"
            )
            link = headers.get("Link", "") if hasattr(headers, "get") else ""
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except (TypeError, ValueError):
                    _fail(
                        "invalid_github_api_response",
                        "githubApi.headers.Content-Length",
                        "invalid response length",
                    )
                if declared_length < 0 or declared_length > MAX_API_RESPONSE_BYTES:
                    _fail(
                        "github_api_response_too_large",
                        "githubApi",
                        "GitHub API response exceeds the bounded size",
                    )
            payload = response.read(MAX_API_RESPONSE_BYTES + 1)
    except ExternalFactError:
        raise
    except Exception:
        _fail(
            "github_api_request_failed",
            "githubApi",
            "read-only GitHub API request failed",
        )
    if status != 200 or final_url != url:
        _fail(
            "github_api_request_failed",
            "githubApi",
            "GitHub API response was not an exact non-redirected HTTP 200",
        )
    if content_encoding not in {"", "identity"}:
        _fail(
            "unsupported_github_api_encoding",
            "githubApi.headers.Content-Encoding",
            "compressed API responses are not accepted",
        )
    if not isinstance(content_type, str) or not content_type.lower().startswith(
        "application/json"
    ):
        _fail(
            "invalid_github_api_response",
            "githubApi.headers.Content-Type",
            "GitHub API response is not JSON",
        )
    if 'rel="next"' in link:
        _fail(
            "github_api_pagination_unresolved",
            "githubApi.headers.Link",
            "GitHub API response requires another page",
        )
    if len(payload) > MAX_API_RESPONSE_BYTES:
        _fail(
            "github_api_response_too_large",
            "githubApi",
            "GitHub API response exceeds the bounded size",
        )
    return _strict_api_json(payload, "githubApi")


def _fetch(fetcher: JsonFetcher, endpoint: str, path: str) -> Mapping[str, Any]:
    try:
        value = fetcher(endpoint)
    except ExternalFactError:
        raise
    except Exception:
        _fail(
            "github_api_request_failed",
            path,
            "trusted GitHub Actions observation failed",
        )
    if not isinstance(value, Mapping):
        _fail("invalid_github_api_response", path, "response must be an object")
    return value


def _api_string(document: Mapping[str, Any], field: str, path: str) -> str:
    return _string(document.get(field), f"{path}.{field}", maximum=8192)


def _api_integer(document: Mapping[str, Any], field: str, path: str) -> int:
    return _integer(document.get(field), f"{path}.{field}")


def _utc(value: Any, path: str) -> tuple[datetime, str]:
    raw = _string(value, path, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        _fail("invalid_github_api_response", path, "invalid timestamp")
    if parsed.tzinfo is None:
        _fail("invalid_github_api_response", path, "timestamp lacks timezone")
    normalized = parsed.astimezone(timezone.utc)
    rendered = normalized.isoformat(
        timespec="microseconds" if normalized.microsecond else "seconds"
    ).replace("+00:00", "Z")
    return normalized, rendered


def _validate_repository(value: Any, path: str, *, expected_url: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_github_api_response", path, "repository must be an object")
    owner = value.get("owner")
    if not isinstance(owner, Mapping):
        _fail("invalid_github_api_response", f"{path}.owner", "owner must be an object")
    exact = {
        "id": REPOSITORY_ID,
        "name": REPOSITORY_NAME,
        "full_name": REPOSITORY,
        "fork": False,
        "private": False,
        "visibility": "public",
        "url": expected_url,
    }
    if any(value.get(key) != expected for key, expected in exact.items()):
        _fail(
            "external_repository_observation_mismatch",
            path,
            "run repository is not the exact public, non-fork P00 repository",
        )
    if owner.get("login") != REPOSITORY_OWNER or owner.get("id") != REPOSITORY_OWNER_ID:
        _fail(
            "external_repository_observation_mismatch",
            f"{path}.owner",
            "repository owner identity differs",
        )
    return {
        "id": str(REPOSITORY_ID),
        "fullName": REPOSITORY,
        "owner": REPOSITORY_OWNER,
        "ownerId": str(REPOSITORY_OWNER_ID),
        "visibility": "public",
        "fork": False,
    }


def _validate_run(
    value: Mapping[str, Any], evidence: Mapping[str, Any]
) -> tuple[dict[str, Any], int]:
    path = "githubApi.run"
    run_id = _api_integer(value, "id", path)
    if run_id != evidence["runId"]:
        _fail("external_run_binding_mismatch", f"{path}.id", "run ID differs")
    run_number = _api_integer(value, "run_number", path)
    attempt = _api_integer(value, "run_attempt", path)
    if attempt != RUN_ATTEMPT or attempt != evidence["runAttempt"]:
        _fail(
            "external_rerun_forbidden",
            f"{path}.run_attempt",
            "rerun attempts are not admissible",
        )
    source_commit = evidence["subject"]["sourceCommit"]
    exact = {
        "name": WORKFLOW_NAME,
        "event": WORKFLOW_EVENT,
        "status": "completed",
        "conclusion": "success",
        "head_branch": BRANCH,
        "head_sha": source_commit,
        "path": WORKFLOW_RUN_PATH,
    }
    if any(value.get(key) != expected for key, expected in exact.items()):
        _fail(
            "external_run_observation_mismatch",
            path,
            "run source, ref, workflow, status, or conclusion differs",
        )
    pull_requests = value.get("pull_requests")
    if pull_requests != []:
        _fail(
            "external_pull_request_run_forbidden",
            f"{path}.pull_requests",
            "pull-request and fork runs are not admissible",
        )
    base_url = f"{GITHUB_API_ROOT}/repos/{REPOSITORY}"
    run_url = f"{base_url}/actions/runs/{run_id}"
    if value.get("url") != run_url or value.get("jobs_url") != f"{run_url}/jobs":
        _fail(
            "external_run_url_mismatch",
            path,
            "run REST identity differs from the approved repository",
        )
    workflow_id = _api_integer(value, "workflow_id", path)
    if value.get("workflow_url") != f"{base_url}/actions/workflows/{workflow_id}":
        _fail(
            "external_workflow_binding_mismatch",
            f"{path}.workflow_url",
            "workflow REST identity differs",
        )
    repository_projection = _validate_repository(
        value.get("repository"), f"{path}.repository", expected_url=base_url
    )
    head_projection = _validate_repository(
        value.get("head_repository"),
        f"{path}.head_repository",
        expected_url=base_url,
    )
    if head_projection != repository_projection:
        _fail(
            "external_fork_run_forbidden",
            f"{path}.head_repository",
            "head repository differs from the protected repository",
        )
    head_commit = value.get("head_commit")
    if not isinstance(head_commit, Mapping) or head_commit.get("id") != source_commit:
        _fail(
            "external_source_commit_mismatch",
            f"{path}.head_commit",
            "head commit differs from the criterion subject",
        )
    check_suite_id = _api_integer(value, "check_suite_id", path)
    created, created_text = _utc(value.get("created_at"), f"{path}.created_at")
    started, started_text = _utc(value.get("run_started_at"), f"{path}.run_started_at")
    updated, updated_text = _utc(value.get("updated_at"), f"{path}.updated_at")
    if not (created <= started <= updated):
        _fail(
            "invalid_github_api_response",
            path,
            "run timestamps are not monotonic",
        )
    return (
        {
            "id": str(run_id),
            "number": run_number,
            "attempt": attempt,
            "event": WORKFLOW_EVENT,
            "headBranch": BRANCH,
            "headSha": source_commit,
            "status": "completed",
            "conclusion": "success",
            "checkSuiteId": str(check_suite_id),
            "createdAt": created_text,
            "startedAt": started_text,
            "updatedAt": updated_text,
        },
        workflow_id,
    )


def _validate_workflow(value: Mapping[str, Any], workflow_id: int) -> dict[str, Any]:
    path = "githubApi.workflow"
    exact = {
        "id": workflow_id,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "state": "active",
        "url": f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/actions/workflows/{workflow_id}",
    }
    if any(value.get(key) != expected for key, expected in exact.items()):
        _fail(
            "external_workflow_observation_mismatch",
            path,
            "workflow ID, name, path, state, or repository differs",
        )
    return {
        "id": str(workflow_id),
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "ref": WORKFLOW_REF,
        "state": "active",
    }


def _validate_steps(value: Any, *, required: Sequence[str], path: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        _fail("invalid_github_api_response", path, "job steps must be an array")
    names: list[str] = []
    numbers: list[int] = []
    for index, raw_step in enumerate(value):
        step_path = f"{path}[{index}]"
        if not isinstance(raw_step, Mapping):
            _fail("invalid_github_api_response", step_path, "step must be an object")
        name = _api_string(raw_step, "name", step_path)
        number = _api_integer(raw_step, "number", step_path)
        if (
            raw_step.get("status") != "completed"
            or raw_step.get("conclusion") != "success"
        ):
            _fail(
                "external_job_step_not_successful",
                step_path,
                "cancelled, skipped, incomplete, or failed steps are inadmissible",
            )
        names.append(name)
        numbers.append(number)
    if len(names) != len(set(names)) or len(numbers) != len(set(numbers)):
        _fail(
            "duplicate_external_job_step",
            path,
            "job step names and numbers must be unique",
        )
    if any(names.count(name) != 1 for name in required):
        _fail(
            "external_required_job_step_missing",
            path,
            "the exact semantic workflow steps did not all complete",
        )
    return list(required)


def _validate_jobs(
    value: Mapping[str, Any], evidence: Mapping[str, Any]
) -> list[dict[str, Any]]:
    path = "githubApi.jobs"
    total = value.get("total_count")
    jobs = value.get("jobs")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or isinstance(jobs, (str, bytes))
        or not isinstance(jobs, Sequence)
        or total != len(PLATFORM_SPECS)
        or len(jobs) != total
    ):
        _fail(
            "external_job_set_mismatch",
            path,
            "exactly the three platform jobs and aggregate job are required",
        )
    by_name: dict[str, Mapping[str, Any]] = {}
    job_ids: set[int] = set()
    for index, raw_job in enumerate(jobs):
        job_path = f"{path}.jobs[{index}]"
        if not isinstance(raw_job, Mapping):
            _fail("invalid_github_api_response", job_path, "job must be an object")
        name = _api_string(raw_job, "name", job_path)
        job_id = _api_integer(raw_job, "id", job_path)
        if name in by_name or job_id in job_ids:
            _fail(
                "duplicate_external_job",
                job_path,
                "job names and IDs must be unique",
            )
        by_name[name] = raw_job
        job_ids.add(job_id)
    expected_names = {item["jobName"] for item in PLATFORM_SPECS}
    if set(by_name) != expected_names:
        _fail(
            "external_job_set_mismatch",
            path,
            "platform/aggregate job identities differ",
        )
    source_commit = evidence["subject"]["sourceCommit"]
    run_id = evidence["runId"]
    run_url = f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/actions/runs/{run_id}"
    projections: list[dict[str, Any]] = []
    for spec in PLATFORM_SPECS:
        raw_job = by_name[spec["jobName"]]
        job_path = f"{path}.{spec['jobName']}"
        job_id = _api_integer(raw_job, "id", job_path)
        exact = {
            "run_id": run_id,
            "run_url": run_url,
            "head_sha": source_commit,
            "status": "completed",
            "conclusion": "success",
            "workflow_name": WORKFLOW_NAME,
            "head_branch": BRANCH,
            "url": f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/actions/jobs/{job_id}",
            "check_run_url": f"{GITHUB_API_ROOT}/repos/{REPOSITORY}/check-runs/{job_id}",
        }
        if any(raw_job.get(key) != expected for key, expected in exact.items()):
            _fail(
                "external_job_observation_mismatch",
                job_path,
                "job source, run, workflow, status, or conclusion differs",
            )
        labels = raw_job.get("labels")
        if (
            isinstance(labels, (str, bytes))
            or not isinstance(labels, Sequence)
            or any(not isinstance(label, str) or not label for label in labels)
            or len(labels) != len(set(labels))
            or spec["runnerLabel"] not in labels
            or "self-hosted" in labels
        ):
            _fail(
                "external_runner_identity_mismatch",
                f"{job_path}.labels",
                "job did not run on the expected GitHub-hosted platform label",
            )
        started, started_text = _utc(
            raw_job.get("started_at"), f"{job_path}.started_at"
        )
        completed, completed_text = _utc(
            raw_job.get("completed_at"), f"{job_path}.completed_at"
        )
        if completed < started:
            _fail(
                "invalid_github_api_response",
                job_path,
                "job timestamps are not monotonic",
            )
        required_steps = _validate_steps(
            raw_job.get("steps"),
            required=spec["requiredSteps"],
            path=f"{job_path}.steps",
        )
        projections.append(
            {
                "platform": spec["platform"],
                "id": str(job_id),
                "name": spec["jobName"],
                "runnerLabels": sorted(labels),
                "status": "completed",
                "conclusion": "success",
                "headSha": source_commit,
                "startedAt": started_text,
                "completedAt": completed_text,
                "requiredSteps": required_steps,
            }
        )
    return projections


def _observe(evidence: Mapping[str, Any], fetcher: JsonFetcher) -> Mapping[str, Any]:
    run_id = evidence["runId"]
    attempt = evidence["runAttempt"]
    prefix = f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    run = _fetch(fetcher, prefix, "githubApi.run")
    run_projection, workflow_id = _validate_run(run, evidence)
    workflow = _fetch(
        fetcher,
        f"/repos/{REPOSITORY}/actions/workflows/{workflow_id}",
        "githubApi.workflow",
    )
    workflow_projection = _validate_workflow(workflow, workflow_id)
    jobs = _fetch(
        fetcher,
        f"{prefix}/jobs?per_page=100&page=1",
        "githubApi.jobs",
    )
    jobs_projection = _validate_jobs(jobs, evidence)
    return {
        "schemaVersion": FACT_SCHEMA,
        "kind": FACT_KIND,
        "provider": "github-actions-rest",
        "freezeDigest": evidence["freezeDigest"],
        "subject": deepcopy(evidence["subject"]),
        "criterion": deepcopy(evidence["criterion"]),
        "repository": {
            "id": str(REPOSITORY_ID),
            "fullName": REPOSITORY,
            "owner": REPOSITORY_OWNER,
            "ownerId": str(REPOSITORY_OWNER_ID),
            "visibility": "public",
            "fork": False,
        },
        "workflow": workflow_projection,
        "run": run_projection,
        "jobs": jobs_projection,
    }


def _default_fetcher(endpoint: str) -> Mapping[str, Any]:
    return github_actions_rest_fetch(endpoint)


def create_p00_crossplatform_evidence(
    *,
    freeze_digest: str,
    subject: SubjectBinding,
    criterion: CriterionBinding,
    run_id: int,
    fetcher: JsonFetcher | None = None,
) -> bytes:
    """Create a canonical candidate evidence locator plus recomputed fact digest.

    This helper does not grant authority.  The protected importer must call the
    independent verifier below, which fetches and validates the REST data again.
    """

    _digest(freeze_digest, "freezeDigest")
    if not isinstance(subject, SubjectBinding):
        _fail("invalid_external_fact_subject", "subject", "SubjectBinding required")
    if not isinstance(criterion, CriterionBinding):
        _fail(
            "invalid_external_fact_criterion",
            "criterion",
            "CriterionBinding required",
        )
    evidence: dict[str, Any] = {
        "schemaVersion": EVIDENCE_SCHEMA,
        "kind": EVIDENCE_KIND,
        "provider": "github-actions-rest",
        "freezeDigest": freeze_digest,
        "subject": _subject_document(subject),
        "criterion": _criterion_document(criterion),
        "repository": {"fullName": REPOSITORY, "id": str(REPOSITORY_ID)},
        "workflow": {
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "ref": WORKFLOW_REF,
        },
        "runId": _integer(run_id, "runId"),
        "runAttempt": RUN_ATTEMPT,
        "factEvidenceDigest": "sha256:" + "0" * 64,
    }
    _validate_evidence_document(evidence)
    provider = _default_fetcher if fetcher is None else fetcher
    fact = _observe(evidence, provider)
    evidence["factEvidenceDigest"] = sha256_bytes(canonical_json_bytes(fact))
    return canonical_json_bytes(evidence)


def build_p00_crossplatform_fact_verifier(
    raw_evidence: bytes, *, fetcher: JsonFetcher | None = None
) -> FactVerifier:
    """Return the exact ``provenance.FactVerifier`` callback for P00.W01."""

    evidence = _load_evidence(raw_evidence)
    provider = _default_fetcher if fetcher is None else fetcher

    def verify(
        envelope: Mapping[str, Any], result: VerifiedCriterionResult
    ) -> Mapping[str, Any]:
        _require_result_binding(envelope, result, evidence)
        fact = _observe(evidence, provider)
        fact_digest = sha256_bytes(canonical_json_bytes(fact))
        if (
            evidence["factEvidenceDigest"] != fact_digest
            or result.evidence_digest != fact_digest
        ):
            _fail(
                "external_fact_evidence_digest_mismatch",
                "externalEvidence.factEvidenceDigest",
                "signed evidence digest differs from the fresh REST observation",
            )
        return {
            "status": "verified",
            "kind": "EXTERNAL",
            "criterionId": result.criterion.criterion_id,
            "attestationDigest": result.attestation_digest,
            "evaluator": result.criterion.evaluator,
            "evaluatorDigest": result.criterion.evaluator_digest,
            "datasetDigest": result.criterion.dataset_digest,
            "factEvidenceDigest": fact_digest,
            "factVerifierDigest": FACT_VERIFIER_DIGEST,
            "sourceCommit": result.subject.source_commit,
            "controlPlaneDigest": result.subject.control_plane_digest,
            "contractDigest": result.subject.contract_digest,
            "satisfied": True,
        }

    return verify


def build_p00_external_fact_verifier(
    criterion_id: str,
    raw_evidence: bytes,
    *,
    fetcher: JsonFetcher | None = None,
) -> FactVerifier:
    """Dispatch only implemented P00 EXTERNAL fact models, fail closed otherwise."""

    if criterion_id != CRITERION_ID:
        detail = (
            "outreach/design-partner/review facts require separately approved "
            "evidence models"
            if criterion_id in UNSUPPORTED_P00_EXTERNAL_CRITERIA
            else "criterion has no approved P00 external fact verifier"
        )
        _fail(
            "unsupported_external_fact_model",
            "criterionId",
            detail,
        )
    return build_p00_crossplatform_fact_verifier(raw_evidence, fetcher=fetcher)


__all__ = [
    "CRITERION_ID",
    "EVIDENCE_KIND",
    "EVIDENCE_SCHEMA",
    "ExternalFactError",
    "FACT_VERIFIER_DIGEST",
    "FACT_VERIFIER_SPEC",
    "GITHUB_API_ROOT",
    "GITHUB_API_VERSION",
    "MAX_API_RESPONSE_BYTES",
    "REPOSITORY",
    "RUN_ATTEMPT",
    "UNSUPPORTED_P00_EXTERNAL_CRITERIA",
    "WORKFLOW_PATH",
    "WORKFLOW_REF",
    "build_p00_crossplatform_fact_verifier",
    "build_p00_external_fact_verifier",
    "create_p00_crossplatform_evidence",
    "github_actions_rest_fetch",
]
