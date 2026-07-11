from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from typing import Any
import unittest
from urllib import error as urlerror

from tools.phasegate.digest import canonical_json_bytes
from tools.phasegate.external_facts import (
    CRITERION_ID,
    FACT_VERIFIER_DIGEST,
    FACT_VERIFIER_SPEC,
    GITHUB_API_ROOT,
    GITHUB_API_VERSION,
    MAX_API_RESPONSE_BYTES,
    REPOSITORY,
    RUN_ATTEMPT,
    UNSUPPORTED_P00_EXTERNAL_CRITERIA,
    ExternalFactError,
    build_p00_crossplatform_fact_verifier,
    build_p00_external_fact_verifier,
    create_p00_crossplatform_evidence,
    github_actions_rest_fetch,
)
from tools.phasegate.provenance import (
    EXTERNAL_CRITERION_NAMESPACE,
    CriterionBinding,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedSignerResult,
)


def D(character: str) -> str:
    return "sha256:" + character * 64


class P00CrossPlatformExternalFactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_commit = "a" * 40
        self.subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=self.source_commit,
            control_plane_digest=D("1"),
            contract_digest=D("2"),
        )
        self.criterion = CriterionBinding(
            criterion_id=CRITERION_ID,
            kind="EXTERNAL",
            evaluator="attestation://ci/cross-platform/v1",
            evaluator_digest=D("3"),
            evaluator_status="external-only",
            evidence_schema="evidence-schema://attestation/cross-platform/v1",
            evidence_schema_digest=D("4"),
            dataset_digest=D("5"),
            threshold_digest=D("6"),
        )
        self.freeze_digest = D("7")
        self.run_id = 7001
        self.workflow_id = 8001
        self.run_endpoint = f"/repos/{REPOSITORY}/actions/runs/{self.run_id}/attempts/1"
        self.workflow_endpoint = (
            f"/repos/{REPOSITORY}/actions/workflows/{self.workflow_id}"
        )
        self.jobs_endpoint = self.run_endpoint + "/jobs?per_page=100&page=1"
        self.documents = self._documents()
        self.requested: list[str] = []
        self.raw_evidence = create_p00_crossplatform_evidence(
            freeze_digest=self.freeze_digest,
            subject=self.subject,
            criterion=self.criterion,
            run_id=self.run_id,
            fetcher=self._fetch,
        )
        self.evidence = json.loads(self.raw_evidence)
        self.fact_digest = self.evidence["factEvidenceDigest"]
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=EXTERNAL_CRITERION_NAMESPACE,
            principal="external@test.invalid",
            role="external-attestor",
            organization="external-test",
            statement_digest=D("8"),
            authority_digest=D("9"),
            source_commit=self.source_commit,
            control_plane_digest=self.subject.control_plane_digest,
        )
        self.result = VerifiedCriterionResult(
            attestation_digest=D("a"),
            statement_digest=D("b"),
            result_id="result-P00-X-CROSSPLATFORM",
            freeze_digest=self.freeze_digest,
            subject=self.subject,
            criterion=self.criterion,
            outcome="ATTESTED",
            evidence_digest=self.fact_digest,
            run_pair_digest=None,
            signature_verified=True,
            fact_status="signature_verified_fact_unverified",
            criterion_satisfied=False,
            signer=signer,
        )
        self.envelope = {
            "attestationDigest": self.result.attestation_digest,
            "body": {"evidenceDigest": self.fact_digest},
        }
        self.requested.clear()

    def _repository(self) -> dict[str, Any]:
        base = f"{GITHUB_API_ROOT}/repos/{REPOSITORY}"
        return {
            "id": 1_296_831_403,
            "name": "agentapi-doctor",
            "full_name": REPOSITORY,
            "fork": False,
            "private": False,
            "visibility": "public",
            "url": base,
            "owner": {"login": "whyiug", "id": 6_668_626},
        }

    @staticmethod
    def _steps(required: tuple[str, ...]) -> list[dict[str, Any]]:
        names = ("Set up job", *required, "Complete job")
        return [
            {
                "name": name,
                "number": index,
                "status": "completed",
                "conclusion": "success",
            }
            for index, name in enumerate(names, start=1)
        ]

    def _job(
        self,
        job_id: int,
        name: str,
        label: str,
        required_steps: tuple[str, ...],
    ) -> dict[str, Any]:
        base = f"{GITHUB_API_ROOT}/repos/{REPOSITORY}"
        return {
            "id": job_id,
            "run_id": self.run_id,
            "run_url": f"{base}/actions/runs/{self.run_id}",
            "head_sha": self.source_commit,
            "url": f"{base}/actions/jobs/{job_id}",
            "check_run_url": f"{base}/check-runs/{job_id}",
            "status": "completed",
            "conclusion": "success",
            "name": name,
            "labels": [label],
            "workflow_name": "P00 bootstrap cross-platform",
            "head_branch": "main",
            "started_at": "2026-07-11T01:01:00Z",
            "completed_at": "2026-07-11T01:02:00Z",
            "steps": self._steps(required_steps),
        }

    def _documents(self) -> dict[str, dict[str, Any]]:
        base = f"{GITHUB_API_ROOT}/repos/{REPOSITORY}"
        platform_steps = (
            "Checkout exact revision without credentials",
            "Run dependency-free bootstrap validation",
            "Upload exact platform result",
        )
        aggregate_steps = (
            "Download all exact platform results",
            "Require three PASS results with one control-plane digest",
            "Upload aggregate candidate evidence",
        )
        run = {
            "id": self.run_id,
            "run_number": 19,
            "run_attempt": RUN_ATTEMPT,
            "name": "P00 bootstrap cross-platform",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": self.source_commit,
            "path": ".github/workflows/p00-bootstrap-cross-platform.yml@main",
            "pull_requests": [],
            "url": f"{base}/actions/runs/{self.run_id}",
            "jobs_url": f"{base}/actions/runs/{self.run_id}/jobs",
            "workflow_id": self.workflow_id,
            "workflow_url": f"{base}/actions/workflows/{self.workflow_id}",
            "repository": self._repository(),
            "head_repository": self._repository(),
            "head_commit": {"id": self.source_commit},
            "check_suite_id": 9001,
            "created_at": "2026-07-11T01:00:00Z",
            "run_started_at": "2026-07-11T01:00:30Z",
            "updated_at": "2026-07-11T01:03:00Z",
        }
        workflow = {
            "id": self.workflow_id,
            "name": "P00 bootstrap cross-platform",
            "path": ".github/workflows/p00-bootstrap-cross-platform.yml",
            "state": "active",
            "url": f"{base}/actions/workflows/{self.workflow_id}",
        }
        jobs = [
            self._job(101, "ubuntu-24.04", "ubuntu-24.04", platform_steps),
            self._job(102, "macos-14", "macos-14", platform_steps),
            self._job(103, "windows-2022", "windows-2022", platform_steps),
            self._job(
                104,
                "P00 bootstrap cross-platform / aggregate",
                "ubuntu-24.04",
                aggregate_steps,
            ),
        ]
        return {
            self.run_endpoint: run,
            self.workflow_endpoint: workflow,
            self.jobs_endpoint: {"total_count": 4, "jobs": jobs},
        }

    def _fetch(self, endpoint: str) -> dict[str, Any]:
        self.requested.append(endpoint)
        return deepcopy(self.documents[endpoint])

    @staticmethod
    def _mapping_fetcher(documents: dict[str, Any]):
        def fetch(endpoint: str) -> dict[str, Any]:
            return deepcopy(documents[endpoint])

        return fetch

    def _assert_observation_rejected(
        self, documents: dict[str, Any], expected_code: str
    ) -> None:
        verifier = build_p00_crossplatform_fact_verifier(
            self.raw_evidence,
            fetcher=self._mapping_fetcher(documents),
        )
        with self.assertRaises(ExternalFactError) as caught:
            verifier(self.envelope, self.result)
        self.assertEqual(caught.exception.code, expected_code)

    def test_reference_observation_recomputes_exact_fact_mapping(self) -> None:
        verifier = build_p00_crossplatform_fact_verifier(
            self.raw_evidence, fetcher=self._fetch
        )
        fact = verifier(self.envelope, self.result)
        self.assertEqual(
            self.requested,
            [self.run_endpoint, self.workflow_endpoint, self.jobs_endpoint],
        )
        self.assertEqual(
            set(fact),
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
        )
        self.assertEqual(fact["factEvidenceDigest"], self.fact_digest)
        self.assertEqual(fact["factVerifierDigest"], FACT_VERIFIER_DIGEST)
        self.assertIs(fact["satisfied"], True)
        self.assertNotIn("satisfied", self.evidence)

    def test_repo_source_workflow_attempt_fork_and_pr_mutants_fail(self) -> None:
        cases: list[tuple[str, str, Any]] = []

        wrong_repo = deepcopy(self.documents)
        wrong_repo[self.run_endpoint]["repository"]["full_name"] = "other/repo"
        cases.append(
            (
                "wrong repository",
                "external_repository_observation_mismatch",
                wrong_repo,
            )
        )

        wrong_sha = deepcopy(self.documents)
        wrong_sha[self.run_endpoint]["head_sha"] = "b" * 40
        cases.append(("wrong sha", "external_run_observation_mismatch", wrong_sha))

        wrong_ref = deepcopy(self.documents)
        wrong_ref[self.run_endpoint]["path"] = (
            ".github/workflows/p00-bootstrap-cross-platform.yml@feature"
        )
        cases.append(("wrong ref", "external_run_observation_mismatch", wrong_ref))

        rerun = deepcopy(self.documents)
        rerun[self.run_endpoint]["run_attempt"] = 2
        cases.append(("rerun", "external_rerun_forbidden", rerun))

        fork = deepcopy(self.documents)
        fork[self.run_endpoint]["head_repository"]["fork"] = True
        cases.append(
            (
                "fork",
                "external_repository_observation_mismatch",
                fork,
            )
        )

        pull_request = deepcopy(self.documents)
        pull_request[self.run_endpoint]["pull_requests"] = [{"id": 1}]
        cases.append(
            (
                "pull request",
                "external_pull_request_run_forbidden",
                pull_request,
            )
        )

        wrong_workflow = deepcopy(self.documents)
        wrong_workflow[self.workflow_endpoint]["path"] = ".github/workflows/other.yml"
        cases.append(
            (
                "wrong workflow",
                "external_workflow_observation_mismatch",
                wrong_workflow,
            )
        )

        for label, code, documents in cases:
            with self.subTest(label=label):
                self._assert_observation_rejected(documents, code)

    def test_duplicate_missing_cancelled_skipped_and_wrong_jobs_fail(self) -> None:
        cases: list[tuple[str, str, Any]] = []

        duplicate = deepcopy(self.documents)
        duplicate[self.jobs_endpoint]["jobs"][3]["name"] = "ubuntu-24.04"
        cases.append(("duplicate", "duplicate_external_job", duplicate))

        missing = deepcopy(self.documents)
        missing[self.jobs_endpoint]["jobs"].pop()
        missing[self.jobs_endpoint]["total_count"] = 3
        cases.append(("missing", "external_job_set_mismatch", missing))

        cancelled = deepcopy(self.documents)
        cancelled[self.jobs_endpoint]["jobs"][0]["conclusion"] = "cancelled"
        cases.append(("cancelled", "external_job_observation_mismatch", cancelled))

        skipped = deepcopy(self.documents)
        skipped[self.jobs_endpoint]["jobs"][1]["steps"][1]["conclusion"] = "skipped"
        cases.append(("skipped", "external_job_step_not_successful", skipped))

        wrong_runner = deepcopy(self.documents)
        wrong_runner[self.jobs_endpoint]["jobs"][2]["labels"] = ["self-hosted"]
        cases.append(
            ("wrong runner", "external_runner_identity_mismatch", wrong_runner)
        )

        wrong_job_sha = deepcopy(self.documents)
        wrong_job_sha[self.jobs_endpoint]["jobs"][0]["head_sha"] = "b" * 40
        cases.append(
            ("wrong job sha", "external_job_observation_mismatch", wrong_job_sha)
        )

        duplicate_id = deepcopy(self.documents)
        duplicate_id[self.jobs_endpoint]["jobs"][3]["id"] = 101
        cases.append(("duplicate id", "duplicate_external_job", duplicate_id))

        for label, code, documents in cases:
            with self.subTest(label=label):
                self._assert_observation_rejected(documents, code)

    def test_canonical_copied_digest_subject_and_attestation_mutants_fail(self) -> None:
        with self.assertRaises(ExternalFactError) as noncanonical:
            build_p00_crossplatform_fact_verifier(self.raw_evidence + b"\n")
        self.assertEqual(noncanonical.exception.code, "noncanonical_external_evidence")

        duplicate = b'{"schemaVersion":"copied",' + self.raw_evidence[1:]
        with self.assertRaises(ExternalFactError) as duplicated:
            build_p00_crossplatform_fact_verifier(duplicate)
        self.assertEqual(duplicated.exception.code, "duplicate_external_evidence_key")

        boolean_attempt = deepcopy(self.evidence)
        boolean_attempt["runAttempt"] = True
        with self.assertRaises(ExternalFactError) as attempt_error:
            build_p00_crossplatform_fact_verifier(canonical_json_bytes(boolean_attempt))
        self.assertEqual(attempt_error.exception.code, "invalid_external_evidence")

        copied = deepcopy(self.evidence)
        copied["factEvidenceDigest"] = D("c")
        copied_raw = canonical_json_bytes(copied)
        copied_result = replace(self.result, evidence_digest=D("c"))
        copied_envelope = {
            "attestationDigest": copied_result.attestation_digest,
            "body": {"evidenceDigest": D("c")},
        }
        verifier = build_p00_crossplatform_fact_verifier(
            copied_raw, fetcher=self._fetch
        )
        with self.assertRaises(ExternalFactError) as digest_error:
            verifier(copied_envelope, copied_result)
        self.assertEqual(
            digest_error.exception.code, "external_fact_evidence_digest_mismatch"
        )

        other_subject = replace(self.subject, source_commit="b" * 40)
        other_result = replace(self.result, subject=other_subject)
        verifier = build_p00_crossplatform_fact_verifier(
            self.raw_evidence, fetcher=self._fetch
        )
        with self.assertRaises(ExternalFactError) as subject_error:
            verifier(self.envelope, other_result)
        self.assertEqual(
            subject_error.exception.code, "external_subject_binding_mismatch"
        )

        copied_envelope = deepcopy(self.envelope)
        copied_envelope["attestationDigest"] = D("d")
        with self.assertRaises(ExternalFactError) as attestation_error:
            verifier(copied_envelope, self.result)
        self.assertEqual(
            attestation_error.exception.code,
            "external_attestation_binding_mismatch",
        )

    def test_other_p00_external_fact_models_are_explicitly_unsupported(self) -> None:
        self.assertEqual(
            UNSUPPORTED_P00_EXTERNAL_CRITERIA,
            {
                "P00-X-OUTREACH",
                "P00-X-DESIGN-PARTNERS",
                "P00-X-REVIEW",
            },
        )
        for criterion_id in sorted(UNSUPPORTED_P00_EXTERNAL_CRITERIA):
            with self.subTest(criterion_id=criterion_id):
                with self.assertRaises(ExternalFactError) as caught:
                    build_p00_external_fact_verifier(
                        criterion_id, self.raw_evidence, fetcher=self._fetch
                    )
                self.assertEqual(
                    caught.exception.code, "unsupported_external_fact_model"
                )


class GitHubActionsRestFetcherTests(unittest.TestCase):
    ENDPOINT = "/repos/whyiug/agentapi-doctor/actions/runs/7001/attempts/1"

    class Response:
        def __init__(
            self,
            payload: bytes,
            *,
            status: int = 200,
            final_url: str | None = None,
            headers: dict[str, str] | None = None,
        ) -> None:
            self.payload = payload
            self.status = status
            self.final_url = final_url
            self.headers = headers or {
                "Content-Type": "application/json; charset=utf-8"
            }
            self.read_limit: int | None = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return self.final_url or (
                GITHUB_API_ROOT + GitHubActionsRestFetcherTests.ENDPOINT
            )

        def read(self, limit: int) -> bytes:
            self.read_limit = limit
            return self.payload[:limit]

    def test_fixed_https_get_uses_environment_token_and_bounded_read(self) -> None:
        response = self.Response(canonical_json_bytes({"id": 7001}))
        requests = []

        def opener(api_request, timeout):
            requests.append(api_request)
            self.assertEqual(timeout, 10)
            return response

        result = github_actions_rest_fetch(
            self.ENDPOINT,
            environ={"GITHUB_TOKEN": "synthetic-token"},
            urlopen=opener,
        )
        self.assertEqual(result, {"id": 7001})
        self.assertEqual(len(requests), 1)
        api_request = requests[0]
        self.assertEqual(api_request.full_url, GITHUB_API_ROOT + self.ENDPOINT)
        self.assertEqual(api_request.get_method(), "GET")
        self.assertIsNone(api_request.data)
        self.assertEqual(
            api_request.get_header("Authorization"), "Bearer synthetic-token"
        )
        self.assertEqual(api_request.get_header("X-github-api-version"), "2026-03-10")
        self.assertEqual(GITHUB_API_VERSION, "2026-03-10")
        self.assertEqual(response.read_limit, MAX_API_RESPONSE_BYTES + 1)

    def test_spec_cites_exact_current_attempt_endpoints(self) -> None:
        self.assertIn(
            "https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run-attempt",
            FACT_VERIFIER_SPEC["apiReferences"],
        )
        self.assertIn(
            "https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#list-jobs-for-a-workflow-run-attempt",
            FACT_VERIFIER_SPEC["apiReferences"],
        )

    def test_arbitrary_endpoint_redirect_pagination_and_oversize_fail_closed(
        self,
    ) -> None:
        attempted = False

        def forbidden(*args, **kwargs):
            nonlocal attempted
            attempted = True
            raise AssertionError("network must not be reached")

        with self.assertRaises(ExternalFactError) as endpoint:
            github_actions_rest_fetch(
                "https://example.invalid/",
                environ={"GITHUB_TOKEN": "synthetic-token"},
                urlopen=forbidden,
            )
        self.assertEqual(endpoint.exception.code, "unsafe_github_api_endpoint")
        self.assertFalse(attempted)

        redirect = self.Response(
            canonical_json_bytes({"id": 7001}),
            final_url="https://example.invalid/copied",
        )
        with self.assertRaises(ExternalFactError) as redirected:
            github_actions_rest_fetch(
                self.ENDPOINT,
                environ={"GITHUB_TOKEN": "synthetic-token"},
                urlopen=lambda *_args, **_kwargs: redirect,
            )
        self.assertEqual(redirected.exception.code, "github_api_request_failed")

        paged = self.Response(
            canonical_json_bytes({"id": 7001}),
            headers={
                "Content-Type": "application/json",
                "Link": '<https://api.github.com/copied>; rel="next"',
            },
        )
        with self.assertRaises(ExternalFactError) as pagination:
            github_actions_rest_fetch(
                self.ENDPOINT,
                environ={"GITHUB_TOKEN": "synthetic-token"},
                urlopen=lambda *_args, **_kwargs: paged,
            )
        self.assertEqual(pagination.exception.code, "github_api_pagination_unresolved")

        oversized = self.Response(b"x" * (MAX_API_RESPONSE_BYTES + 1))
        with self.assertRaises(ExternalFactError) as too_large:
            github_actions_rest_fetch(
                self.ENDPOINT,
                environ={"GITHUB_TOKEN": "synthetic-token"},
                urlopen=lambda *_args, **_kwargs: oversized,
            )
        self.assertEqual(too_large.exception.code, "github_api_response_too_large")

    def test_token_is_required_and_never_copied_into_errors(self) -> None:
        attempted = False

        def forbidden(*args, **kwargs):
            nonlocal attempted
            attempted = True
            raise AssertionError("network must not be reached")

        with self.assertRaises(ExternalFactError) as missing:
            github_actions_rest_fetch(
                self.ENDPOINT,
                environ={},
                urlopen=forbidden,
            )
        self.assertEqual(missing.exception.code, "missing_github_token")
        self.assertFalse(attempted)

        secret = "synthetic-secret-that-must-not-appear"

        def failed(*args, **kwargs):
            raise urlerror.URLError(secret)

        with self.assertRaises(ExternalFactError) as request_failed:
            github_actions_rest_fetch(
                self.ENDPOINT,
                environ={"GITHUB_TOKEN": secret},
                urlopen=failed,
            )
        self.assertEqual(request_failed.exception.code, "github_api_request_failed")
        self.assertNotIn(secret, str(request_failed.exception))


if __name__ == "__main__":
    unittest.main()
