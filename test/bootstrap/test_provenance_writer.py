"""Real-OIDC and seal-boundary tests for protected provenance writers."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.digest import canonical_json_bytes, sha256_bytes  # noqa: E402
from tools.phasegate.gate_runner import (  # noqa: E402
    combine_phase_runs,
    record_phase_run,
)
from tools.phasegate.lifecycle_evidence import (  # noqa: E402
    BLOCKER_RESOLUTION_KIND,
    BLOCKER_RESOLUTION_NAMESPACE,
    BLOCKER_RESOLUTION_SCHEMA,
    verify_blocker_resolution,
)
from tools.phasegate.oidc_provenance import (  # noqa: E402
    OIDC_PROVENANCE_AUDIENCE_PREFIX,
    OidcProvenanceError,
    OidcProvenanceVerifier,
    _mark_verified as _mark_oidc_verified,
)
from tools.phasegate.p00_evaluators import (  # noqa: E402
    AGGREGATE_CRITERIA,
    build_paired_input,
    evaluate_strict,
)
from tools.phasegate.protected import (  # noqa: E402
    ProtectedVerificationError,
    document_digest,
)
from tools.phasegate.provenance import (  # noqa: E402
    ACTIVATION_PROOF_NAMESPACE,
    LIFECYCLE_PROOF_NAMESPACE,
    PHASE_CRITERION_NAMESPACES,
    PHASE_PROOF_NAMESPACE,
    PROOF_NAMESPACE,
    CriterionBinding,
    PhaseSubject,
    PhaseUnitStateBinding,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedPhaseStateContext,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    VerifiedWorkUnitStateContext,
    _mark_verified as _mark_provenance_verified,
    verify_verified_transition_proof,
)
from tools.phasegate.provenance_writer import (  # noqa: E402
    ProvenanceWriterError,
    create_signed_activation_proof,
    create_signed_lifecycle_proof,
    create_signed_phase_machine_criterion_result,
    create_signed_phase_transition_proof,
    create_signed_work_unit_transition_proof,
)


def D(character: str) -> str:
    return "sha256:" + character * 64


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


class ProvenanceWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="provenance-writer-")
        cls.private_key = Path(cls.temporary.name) / "oidc-test.pem"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(cls.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        modulus = subprocess.run(
            [
                "/usr/bin/openssl",
                "rsa",
                "-in",
                str(cls.private_key),
                "-noout",
                "-modulus",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        cls.jwk = {
            "kid": "provenance-writer-test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(bytes.fromhex(modulus.removeprefix("Modulus="))),
            "e": "AQAB",
        }
        cls.git_repo = Path(cls.temporary.name) / "repo"
        (cls.git_repo / "evidence").mkdir(parents=True)
        (cls.git_repo / "evidence/blocker-resolution.json").write_text(
            '{"status":"resolved"}\n', encoding="utf-8"
        )
        subprocess.run(
            ["/usr/bin/git", "init", "-q", str(cls.git_repo)],
            check=True,
            timeout=10,
        )
        for key, value in (
            ("user.email", "test@example.invalid"),
            ("user.name", "Writer Test"),
        ):
            subprocess.run(
                ["/usr/bin/git", "-C", str(cls.git_repo), "config", key, value],
                check=True,
                timeout=10,
            )
        subprocess.run(
            ["/usr/bin/git", "-C", str(cls.git_repo), "add", "."],
            check=True,
            timeout=10,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(cls.git_repo),
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
            check=True,
            timeout=10,
        )
        cls.git_commit = subprocess.run(
            ["/usr/bin/git", "-C", str(cls.git_repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.source_commit = self.git_commit
        self.control_digest = D("1")
        self.contract_digest = D("2")
        self.aggregate_contract_digest = D("3")
        self.state_digest = D("4")
        self.chain_head_digest = D("5")
        self.issued_at = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)
        self.inputs = {
            "planDigest": D("6"),
            "supportLockDigest": D("7"),
            "toolchainDigest": D("8"),
            "dependencySetDigest": D("9"),
            "gateRunnerDigest": D("a"),
            "evaluatorSetDigest": D("b"),
            "metricDefinitionsDigest": D("c"),
            "protectedAcceptanceDigest": D("d"),
        }
        self.machine = CriterionBinding(
            criterion_id="P00-M-REPRO",
            kind="MACHINE",
            evaluator="evaluator://corpus/reproduction/v1",
            evaluator_digest=D("e"),
            evidence_schema="evidence-schema://test/machine/v1",
            evidence_schema_digest=D("f"),
            dataset_digest=D("1"),
            threshold_digest=D("2"),
        )
        self.subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            contract_digest=self.contract_digest,
        )
        self.freeze = self._work_freeze(self.machine)
        self.machine_result = _mark_provenance_verified(
            VerifiedCriterionResult(
                attestation_digest=D("3"),
                statement_digest=D("4"),
                result_id="machine-result",
                freeze_digest=self.freeze.attestation_digest,
                subject=self.subject,
                criterion=self.machine,
                outcome="PASS",
                evidence_digest=D("5"),
                run_pair_digest=D("5"),
                signature_verified=True,
                fact_status="not_applicable",
                criterion_satisfied=True,
                signer=self._reviewer_signer(PROOF_NAMESPACE),
            )
        )

    def _reviewer_signer(self, namespace: str) -> VerifiedSignerResult:
        return VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=namespace,
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest=D("6"),
            authority_digest=D("7"),
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
        )

    def _work_freeze(self, criterion: CriterionBinding) -> VerifiedProtectedInputFreeze:
        return _mark_provenance_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=D("8"),
                statement_digest=D("9"),
                freeze_id="freeze-work-writer",
                subject=self.subject,
                contract_approval_digest=D("a"),
                protected_inputs=tuple(sorted(self.inputs.items())),
                criteria=(criterion,),
                signer=self._reviewer_signer(
                    "agentapi-doctor/protected-input-freeze/v1"
                ),
            )
        )

    def _work_state(self, status: str) -> VerifiedWorkUnitStateContext:
        return _mark_provenance_verified(
            VerifiedWorkUnitStateContext(
                state_digest=self.state_digest,
                chain_head_digest=self.chain_head_digest,
                control_plane_digest=self.control_digest,
                phase="P00",
                work_unit="P00.W01",
                status=status,
                contract_digest=self.contract_digest,
                recorded_source_commit=(
                    self.source_commit
                    if status not in {"NOT_STARTED", "READY"}
                    else None
                ),
                prerequisites=(),
                phase_unit_statuses=(("P00.W01", status),),
            )
        )

    def _reviewer_callback(self, *, namespace: str):
        def verify(payload: bytes, signature: dict, observed_namespace: str):
            self.assertEqual(observed_namespace, namespace)
            self.assertEqual(signature["namespace"], namespace)
            return VerifiedSignerResult(
                scheme="openssh-sshsig-v1",
                namespace=namespace,
                principal="reviewer@test.invalid",
                role="independent-reviewer",
                organization="review-test",
                statement_digest=sha256_bytes(payload),
                authority_digest=D("7"),
                source_commit=self.source_commit,
                control_plane_digest=self.control_digest,
            )

        return verify

    def _human_evidence_envelope(
        self, *, schema: str, kind: str, namespace: str, body: dict
    ) -> dict:
        envelope = {
            "schemaVersion": schema,
            "kind": kind,
            "body": body,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": namespace,
                "principal": "reviewer@test.invalid",
                # Cryptographic SSHSIG behavior is covered by
                # test_lifecycle_evidence; this writer suite uses its trusted
                # callback boundary to exercise seal consumption.
                "value": "writer-suite-trusted-adapter",
            },
            "attestationDigest": None,
        }
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        return envelope

    def _blocker_resolution(self, state: VerifiedWorkUnitStateContext):
        body = {
            "resolutionId": "writer-blocker-resolution",
            "subject": {
                "phase": self.subject.phase,
                "workUnit": self.subject.work_unit,
                "sourceCommit": self.subject.source_commit,
                "controlPlaneDigest": self.subject.control_plane_digest,
                "contractDigest": self.subject.contract_digest,
            },
            "fromState": "BLOCKED",
            "toState": "ACTIVE",
            "priorStateDigest": state.state_digest,
            "priorChainHeadDigest": state.chain_head_digest,
            "artifactDigestAlgorithm": "git-blob-content-sha256-v1",
            "resolutionArtifacts": [
                {
                    "path": "evidence/blocker-resolution.json",
                    "digest": sha256_bytes(
                        (self.git_repo / "evidence/blocker-resolution.json").read_bytes()
                    ),
                    "validator": "evaluator://blocker-resolution/v1",
                    "assertions": ["blocker-cleared", "regression-pass"],
                }
            ],
            "reasonCode": "approved-blocker-resolution",
            "reason": "Independent review confirmed the blocker has been resolved.",
            "conflictOfInterest": {
                "independent": True,
                "requesterPrincipal": "agent@test.invalid",
                "requesterOrganization": "implementation-test",
                "declaration": "No financial, employment, or reporting conflict exists.",
            },
            "issuedAt": "2026-07-11T11:00:00Z",
            "validUntil": "2026-07-12T11:00:00Z",
            "actor": {
                "principal": "reviewer@test.invalid",
                "role": "independent-reviewer",
                "organization": "review-test",
            },
            "authorityDigest": D("7"),
        }
        return verify_blocker_resolution(
            self._human_evidence_envelope(
                schema=BLOCKER_RESOLUTION_SCHEMA,
                kind=BLOCKER_RESOLUTION_KIND,
                namespace=BLOCKER_RESOLUTION_NAMESPACE,
                body=body,
            ),
            repo_root=self.git_repo,
            state_context=state,
            expected_subject=self.subject,
            expected_authority_digest=D("7"),
            signer_verifier=self._reviewer_callback(
                namespace=BLOCKER_RESOLUTION_NAMESPACE
            ),
            verification_time=self.issued_at,
        )

    def _phase_freeze(
        self, criterion: CriterionBinding
    ) -> VerifiedPhaseProtectedInputFreeze:
        subject = PhaseSubject(
            phase="P00",
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            aggregate_contract_digest=self.aggregate_contract_digest,
        )
        return _mark_provenance_verified(
            VerifiedPhaseProtectedInputFreeze(
                attestation_digest=D("b"),
                statement_digest=D("c"),
                freeze_id="freeze-phase-writer",
                subject=subject,
                aggregate_contract_approval_digest=D("d"),
                unit_contract_digests=tuple(
                    (f"P00.W0{index}", D(str(index))) for index in range(1, 6)
                ),
                protected_inputs=tuple(sorted(self.inputs.items())),
                criteria=(criterion,),
                signer=self._reviewer_signer(
                    "agentapi-doctor/phase-protected-input-freeze/v1"
                ),
            )
        )

    def _phase_state(self) -> VerifiedPhaseStateContext:
        units = tuple(
            PhaseUnitStateBinding(
                work_unit=f"P00.W0{index}",
                status="CONVERGED",
                contract_digest=D(str(index)),
                source_commit=self.source_commit,
                approval_digest=D("e"),
            )
            for index in range(1, 6)
        )
        return _mark_provenance_verified(
            VerifiedPhaseStateContext(
                state_digest=self.state_digest,
                chain_head_digest=self.chain_head_digest,
                control_plane_digest=self.control_digest,
                phase="P00",
                status="ACTIVE",
                aggregate_contract_digest=self.aggregate_contract_digest,
                base_commit=self.source_commit,
                units=units,
            )
        )

    def _expected_claims(self, commit: str) -> dict[str, str]:
        return {
            "repository": "whyiug/agentapi-doctor",
            "repository_id": "1296831403",
            "repository_owner": "whyiug",
            "repository_owner_id": "6668626",
            "repository_visibility": "public",
            "event_name": "workflow_dispatch",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "ref_protected": "true",
            "runner_environment": "github-hosted",
            "actor_id": "6668626",
            "workflow_ref": "whyiug/agentapi-doctor/.github/workflows/p00-protected-state-writer.yml@refs/heads/main",
            "workflow_sha": commit,
            "sha": commit,
        }

    def _verifier(
        self,
        namespace: str,
        *,
        source_commit: str | None = None,
        state_digest: str | None = None,
        chain_head_digest: str | None = None,
    ) -> OidcProvenanceVerifier:
        commit = source_commit or self.source_commit
        return _mark_oidc_verified(
            OidcProvenanceVerifier(
                namespace=namespace,
                principal="github-actions:test/provenance-writer",
                role="protected-workflow",
                organization="github-actions",
                policy_digest=D("f"),
                jwks_snapshot_digest=D("1"),
                control_plane_digest=self.control_digest,
                source_commit=commit,
                workflow_execution_commit=commit,
                approval_digest=D("2"),
                bootstrap_request_digest=D("3"),
                chain_head_digest=chain_head_digest or self.chain_head_digest,
                state_digest=state_digest or self.state_digest,
                component_set_digest=D("4"),
                component_digests=(("execution/impact-map.yaml", D("5")),),
                expected_claims=tuple(sorted(self._expected_claims(commit).items())),
                authority_digest=D("6"),
                approved_jwks_json=canonical_json_bytes([self.jwk]).decode(),
            )
        )

    def _claims(
        self,
        audience: str,
        *,
        issued_at: datetime,
        commit: str,
        run: int,
        overrides: dict | None = None,
    ) -> dict:
        epoch = int(issued_at.timestamp())
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": audience,
            **self._expected_claims(commit),
            "sub": "repo:whyiug/agentapi-doctor:ref:refs/heads/main",
            "jti": f"provenance-writer-jti-{run}",
            "run_id": str(1000 + run),
            "run_number": str(run),
            "run_attempt": "1",
            "check_run_id": str(2000 + run),
            "nbf": epoch - 5,
            "iat": epoch,
            "exp": epoch + 300,
        }
        claims.update(overrides or {})
        return claims

    def _token(self, claims: dict) -> str:
        header = {"alg": "RS256", "kid": self.jwk["kid"], "typ": "JWT"}
        signing_input = (
            b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        ).encode("ascii")
        signature = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self.private_key),
            ],
            input=signing_input,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout
        return signing_input.decode() + "." + b64url(signature)

    def _provider(
        self,
        *,
        issued_at: datetime | None = None,
        commit: str | None = None,
        run: int = 1,
        overrides: dict | None = None,
    ):
        timestamp = issued_at or self.issued_at
        source = commit or self.source_commit

        def provide(audience: str) -> str:
            self.assertTrue(audience.startswith(OIDC_PROVENANCE_AUDIENCE_PREFIX))
            return self._token(
                self._claims(
                    audience,
                    issued_at=timestamp,
                    commit=source,
                    run=run,
                    overrides=overrides,
                )
            )

        return provide

    def _aggregate_records(self) -> list[dict]:
        return [
            {
                "id": criterion,
                "criterionId": criterion,
                "kind": "MACHINE",
                "evaluator": evaluator,
                "result": "PASS",
                "evidenceDigest": D(format(index + 1, "x")),
                "verificationPairId": f"pair-child-{index:02d}",
                "sourceCommit": self.source_commit,
                "controlPlaneDigest": self.control_digest,
                "evaluatorDigest": D("7"),
                "datasetFreezeDigest": D("8"),
                "datasetDigest": D("9"),
                "verifierDigest": D("a"),
            }
            for index, (criterion, evaluator) in enumerate(
                sorted(AGGREGATE_CRITERIA.items())
            )
        ]

    def _command(self, label: str) -> dict:
        return {
            "exitCode": 0,
            "durationMs": 60_000,
            "startedAt": "2026-07-11T10:00:00Z",
            "finishedAt": "2026-07-11T10:01:00Z",
            "environmentDigest": D("b" if label == "A" else "c"),
            "logDigest": D("d" if label == "A" else "e"),
            "artifactManifestDigest": D("f" if label == "A" else "1"),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": label == "B",
            "semanticAssertions": [
                {
                    "id": "aggregate-evidence-recomputed",
                    "status": "PASS",
                    "evidenceDigest": D("2"),
                }
            ],
        }

    def _phase_material(self):
        payload = build_paired_input(
            "evaluator://phase/aggregate/v1",
            self._aggregate_records(),
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            evaluator_digest=D("e"),
            dataset_id="p00-phase-aggregate",
        )
        evidence = evaluate_strict("evaluator://phase/aggregate/v1", payload)
        criterion = CriterionBinding(
            criterion_id="P00-M-AGGREGATE",
            kind="MACHINE",
            evaluator="evaluator://phase/aggregate/v1",
            evaluator_digest=D("e"),
            evidence_schema="evidence-schema://phase/aggregate-report/v1",
            evidence_schema_digest=D("f"),
            dataset_digest=payload["datasetDigest"],
            threshold_digest=D("1"),
        )
        freeze = self._phase_freeze(criterion)
        runs = [
            record_phase_run(
                freeze=freeze,
                criterion_id=criterion.criterion_id,
                label=label,
                command_result=self._command(label),
                evaluator_input=payload,
                evaluator_evidence=evidence,
            )
            for label in ("A", "B")
        ]
        pair = combine_phase_runs(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            run_a=runs[0],
            run_b=runs[1],
        )
        return freeze, criterion, pair

    def test_work_transition_activation_and_readiness_are_self_verified(self) -> None:
        proof_envelope, proof = create_signed_work_unit_transition_proof(
            freeze=self.freeze,
            criterion_results=[self.machine_result],
            state_context=self._work_state("ACTIVE"),
            verifier=self._verifier(PROOF_NAMESPACE),
            issued_at=self.issued_at,
            token_provider=self._provider(run=1),
        )
        self.assertEqual(proof.to_state, "MACHINE_CONVERGED")
        self.assertEqual(proof_envelope["body"]["actor"]["role"], "protected-workflow")
        activation_envelope, activation = create_signed_activation_proof(
            freeze=self.freeze,
            state_context=self._work_state("READY"),
            verifier=self._verifier(ACTIVATION_PROOF_NAMESPACE),
            issued_at=self.issued_at,
            token_provider=self._provider(run=2),
        )
        self.assertEqual(activation.prior_state_digest, self.state_digest)
        self.assertEqual(activation_envelope["body"]["impactMapDigest"], D("5"))
        lifecycle_envelope, lifecycle = create_signed_lifecycle_proof(
            freeze=self.freeze,
            state_context=self._work_state("NOT_STARTED"),
            verifier=self._verifier(LIFECYCLE_PROOF_NAMESPACE),
            issued_at=self.issued_at,
            token_provider=self._provider(run=3),
        )
        self.assertEqual(lifecycle.transition_type, "READINESS")
        self.assertIsNone(lifecycle_envelope["body"]["invalidationDigest"])

    def test_phase_machine_result_and_transition_proof_are_self_verified(self) -> None:
        freeze, criterion, pair = self._phase_material()
        machine_envelope, machine_result = create_signed_phase_machine_criterion_result(
            freeze=freeze,
            criterion_id=criterion.criterion_id,
            run_pair=pair,
            verifier=self._verifier(PHASE_CRITERION_NAMESPACES["MACHINE"]),
            issued_at=self.issued_at,
            token_provider=self._provider(run=4),
        )
        self.assertTrue(machine_result.criterion_satisfied)
        self.assertEqual(
            machine_envelope["body"]["runPairDigest"], machine_result.evidence_digest
        )
        proof_envelope, proof = create_signed_phase_transition_proof(
            freeze=freeze,
            criterion_results=[machine_result],
            state_context=self._phase_state(),
            verifier=self._verifier(PHASE_PROOF_NAMESPACE),
            issued_at=self.issued_at,
            token_provider=self._provider(run=5),
        )
        self.assertEqual(proof.to_state, "MACHINE_CONVERGED")
        self.assertEqual(len(proof_envelope["body"]["unitStates"]), 5)

    def test_forged_inputs_namespace_and_commit_fail_before_token(self) -> None:
        def forbidden(_audience: str) -> str:
            self.fail("invalid sealed inputs must fail before token acquisition")

        cases = (
            (
                "unverified_internal_result",
                {"freeze": deepcopy(self.freeze)},
            ),
            (
                "unverified_internal_result",
                {"criterion_results": [deepcopy(self.machine_result)]},
            ),
            (
                "provenance_namespace_mismatch",
                {"verifier": self._verifier(ACTIVATION_PROOF_NAMESPACE)},
            ),
            (
                "source_commit_mismatch",
                {"verifier": self._verifier(PROOF_NAMESPACE, source_commit="b" * 40)},
            ),
            (
                "unverified_oidc_authority",
                {"verifier": deepcopy(self._verifier(PROOF_NAMESPACE))},
            ),
        )
        base = {
            "freeze": self.freeze,
            "criterion_results": [self.machine_result],
            "state_context": self._work_state("ACTIVE"),
            "verifier": self._verifier(PROOF_NAMESPACE),
            "issued_at": self.issued_at,
            "token_provider": forbidden,
        }
        for code, changes in cases:
            with self.subTest(code=code):
                arguments = {**base, **changes}
                with self.assertRaises(ProvenanceWriterError) as caught:
                    create_signed_work_unit_transition_proof(**arguments)
                self.assertEqual(caught.exception.code, code)

    def test_oidc_token_cannot_replay_across_statement_or_pr_context(self) -> None:
        verifier = self._verifier(PROOF_NAMESPACE)
        captured: dict[str, str] = {}

        def first_provider(audience: str) -> str:
            token = self._provider(run=10)(audience)
            captured["token"] = token
            return token

        create_signed_work_unit_transition_proof(
            freeze=self.freeze,
            criterion_results=[self.machine_result],
            state_context=self._work_state("ACTIVE"),
            verifier=verifier,
            issued_at=self.issued_at,
            token_provider=first_provider,
        )
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_work_unit_transition_proof(
                freeze=self.freeze,
                criterion_results=[self.machine_result],
                state_context=self._work_state("ACTIVE"),
                verifier=verifier,
                issued_at=self.issued_at + timedelta(seconds=1),
                token_provider=lambda _audience: captured["token"],
            )
        self.assertEqual(caught.exception.code, "oidc_audience_mismatch")
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_work_unit_transition_proof(
                freeze=self.freeze,
                criterion_results=[self.machine_result],
                state_context=self._work_state("ACTIVE"),
                verifier=verifier,
                issued_at=self.issued_at,
                token_provider=self._provider(
                    run=11, overrides={"head_ref": "refs/heads/topic"}
                ),
            )
        self.assertEqual(caught.exception.code, "oidc_pull_request_claim_forbidden")

    def test_tampered_envelope_fails_normal_provenance_verifier(self) -> None:
        verifier = self._verifier(PROOF_NAMESPACE)
        envelope, _proof = create_signed_work_unit_transition_proof(
            freeze=self.freeze,
            criterion_results=[self.machine_result],
            state_context=self._work_state("ACTIVE"),
            verifier=verifier,
            issued_at=self.issued_at,
            token_provider=self._provider(run=12),
        )
        envelope["body"]["issuedAt"] = "2026-07-11T12:00:01Z"
        envelope["attestationDigest"] = document_digest(
            envelope, omit_field="attestationDigest"
        )
        with self.assertRaises(
            (ProtectedVerificationError, OidcProvenanceError)
        ) as caught:
            verify_verified_transition_proof(
                envelope,
                freeze=self.freeze,
                criterion_results=[self.machine_result],
                state_context=self._work_state("ACTIVE"),
                expected_to_state="MACHINE_CONVERGED",
                expected_authority_digest=verifier.authority_digest,
                signer_verifier=verifier,
            )
        self.assertEqual(
            getattr(caught.exception, "code", None), "oidc_audience_mismatch"
        )

    def test_lifecycle_generation_fails_closed_without_dedicated_evidence(self) -> None:
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_lifecycle_proof(
                freeze=self.freeze,
                state_context=self._work_state("BLOCKED"),
                verifier=self._verifier(LIFECYCLE_PROOF_NAMESPACE),
                issued_at=self.issued_at,
                token_provider=lambda _audience: self.fail(
                    "unsupported lifecycle operation must fail before token acquisition"
                ),
            )
        self.assertEqual(caught.exception.code, "unsupported_lifecycle_operation")

    def test_resume_writer_consumes_only_exact_blocker_resolution_seal(self) -> None:
        state = self._work_state("BLOCKED")
        resolution = self._blocker_resolution(state)
        envelope, proof = create_signed_lifecycle_proof(
            freeze=self.freeze,
            state_context=state,
            verifier=self._verifier(LIFECYCLE_PROOF_NAMESPACE),
            issued_at=self.issued_at,
            lifecycle_evidence=resolution,
            token_provider=self._provider(run=40),
        )
        self.assertEqual(proof.transition_type, "RESUME")
        self.assertEqual(proof.to_state, "ACTIVE")
        self.assertEqual(
            envelope["body"]["blockerResolutionDigest"],
            resolution.attestation_digest,
        )
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_lifecycle_proof(
                freeze=self.freeze,
                state_context=state,
                verifier=self._verifier(LIFECYCLE_PROOF_NAMESPACE),
                issued_at=self.issued_at,
                lifecycle_evidence=replace(resolution),
                token_provider=lambda _audience: self.fail(
                    "reconstructed evidence must fail before OIDC acquisition"
                ),
            )
        self.assertEqual(caught.exception.code, "unverified_lifecycle_evidence")

    def test_copied_phase_pair_is_rejected_before_oidc(self) -> None:
        freeze, criterion, pair = self._phase_material()
        with self.assertRaises(ProvenanceWriterError) as caught:
            create_signed_phase_machine_criterion_result(
                freeze=freeze,
                criterion_id=criterion.criterion_id,
                run_pair=deepcopy(pair),
                verifier=self._verifier(PHASE_CRITERION_NAMESPACES["MACHINE"]),
                issued_at=self.issued_at,
                token_provider=lambda _audience: self.fail(
                    "copied pair must fail before token acquisition"
                ),
            )
        self.assertEqual(caught.exception.code, "unsealed_phase_run_pair")


if __name__ == "__main__":
    unittest.main()
