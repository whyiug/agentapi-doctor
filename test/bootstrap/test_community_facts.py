from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.community_facts import (
    DESIGN_PARTNERS,
    DESIGN_PARTNER_KIND,
    DESIGN_PARTNER_NAMESPACE,
    EVIDENCE_KIND,
    EVIDENCE_SCHEMA,
    FACT_VERIFIER_DIGEST,
    OUTREACH,
    OUTREACH_KIND,
    OUTREACH_NAMESPACE,
    REVIEW,
    REVIEW_KIND,
    REVIEW_NAMESPACE,
    STATEMENT_SCHEMA,
    CommunityFactError,
    build_p00_community_fact_verifier,
    serialize_community_fact_evidence,
)
from tools.phasegate.delegation import (
    DELEGATION_KIND,
    DELEGATION_SCHEMA,
    REVOCATION_KIND,
    REVOCATION_SCHEMA,
    build_effective_reviewer_roster,
)
from tools.phasegate.digest import canonical_json_bytes
from tools.phasegate.protected import (
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
)
from tools.phasegate.protected_v2 import REVIEWER_DELEGATION_NAMESPACE
from tools.phasegate.provenance import (
    EXTERNAL_CRITERION_NAMESPACE,
    CriterionBinding,
    SubjectBinding,
    VerifiedCriterionResult,
    VerifiedSignerResult,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def D(character: str) -> str:
    return "sha256:" + character * 64


class P00CommunityFactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="community-facts-")
        cls.key_root = Path(cls.temporary.name)
        cls.keys = {
            name: cls._generate_key(name)
            for name in (
                "root",
                "outreach",
                "partner-one",
                "partner-two",
                "partner-three",
                "reviewer",
                "collector",
                "alternate",
            )
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _generate_key(cls, name: str) -> Path:
        path = cls.key_root / name
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return path

    @staticmethod
    def _public_key(private_key: Path) -> str:
        return " ".join(
            private_key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
        )

    @classmethod
    def _sign(cls, payload: bytes, key_name: str, namespace: str) -> str:
        return subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(cls.keys[key_name]),
                "-n",
                namespace,
            ],
            input=payload,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout.decode("ascii")

    def setUp(self) -> None:
        self.now = datetime(2026, 7, 12, 12, 0, 0, tzinfo=timezone.utc)
        self.source_commit = "a" * 40
        self.control_digest = D("b")
        self.chain_head = D("c")
        self.freeze_digest = D("d")
        self.policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.policy["controlPlaneDigest"] = self.control_digest
        namespaces = self.policy["signatureSchemes"]["human"]["namespaces"]
        namespaces.update(
            {
                "communityOutreach": OUTREACH_NAMESPACE,
                "communityDesignPartner": DESIGN_PARTNER_NAMESPACE,
                "communityExternalReview": REVIEW_NAMESPACE,
            }
        )
        independent = self.policy["reviewerDelegation"]["roleGrants"][
            "independent-external-reviewer"
        ]
        independent["capabilities"] = [
            "attest-external-result",
            "attest-human-result",
        ]
        independent["criteria"] = ["P00-H-GO-NOGO", REVIEW]
        root = self.policy["sshPrincipals"][0]
        root["identity"] = "root@test.invalid"
        root["organization"] = "root-org"
        root["publicKey"] = self._public_key(self.keys["root"])
        root["fingerprint"] = _ssh_public_key_fingerprint(
            root["publicKey"], "test.root"
        )
        self.policy_digest = document_digest(self.policy)
        principals = {root["identity"]: root}
        self.policy_result = {
            "document": self.policy,
            "digest": self.policy_digest,
            "principals": principals,
            "delegationRoots": {root["identity"]: root},
            "reviewerDelegation": self.policy["reviewerDelegation"],
            "revokedFingerprints": set(self.policy["revokedFingerprints"]),
        }
        self.delegations = {
            "outreach": self._delegation(
                name="outreach",
                identity="recipient@test.invalid",
                organization="recipient-org",
                key_name="outreach",
                role="external-attestor",
                criteria=[OUTREACH],
            ),
            "partner-one": self._delegation(
                name="partner-one",
                identity="partner-one@test.invalid",
                organization="partner-one-org",
                key_name="partner-one",
                role="external-attestor",
                criteria=[DESIGN_PARTNERS],
            ),
            "partner-two": self._delegation(
                name="partner-two",
                identity="partner-two@test.invalid",
                organization="partner-two-org",
                key_name="partner-two",
                role="external-attestor",
                criteria=[DESIGN_PARTNERS],
            ),
            "partner-three": self._delegation(
                name="partner-three",
                identity="partner-three@test.invalid",
                organization="partner-three-org",
                key_name="partner-three",
                role="external-attestor",
                criteria=[DESIGN_PARTNERS],
            ),
            "reviewer": self._delegation(
                name="reviewer",
                identity="reviewer@test.invalid",
                organization="reviewer-org",
                key_name="reviewer",
                role="independent-external-reviewer",
                criteria=[REVIEW],
            ),
            "collector": self._delegation(
                name="collector",
                identity="collector@test.invalid",
                organization="collector-org",
                key_name="collector",
                role="external-attestor",
                criteria=[REVIEW],
            ),
        }
        self.roster = self._roster(list(self.delegations.values()))

    def _envelope(
        self,
        *,
        schema: str,
        kind: str,
        body: dict,
        key_name: str,
        principal: str,
        namespace: str,
    ) -> dict:
        unsigned = {"schemaVersion": schema, "kind": kind, "body": body}
        envelope = {
            **unsigned,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": namespace,
                "principal": principal,
                "value": self._sign(
                    canonical_json_bytes(unsigned), key_name, namespace
                ),
            },
        }
        envelope["attestationDigest"] = document_digest(envelope)
        return envelope

    def _delegation(
        self,
        *,
        name: str,
        identity: str,
        organization: str,
        key_name: str,
        role: str,
        criteria: list[str],
    ) -> dict:
        public_key = self._public_key(self.keys[key_name])
        role_policy = self.policy["reviewerDelegation"]["roleGrants"][role]
        body = {
            "delegationId": f"delegation-{name}",
            "policyDigest": self.policy_digest,
            "controlPlaneDigest": self.control_digest,
            "sourceCommit": self.source_commit,
            "priorChainHeadDigest": self.chain_head,
            "delegator": {
                "identity": "root@test.invalid",
                "organization": "root-org",
                "fingerprint": self.policy["sshPrincipals"][0]["fingerprint"],
            },
            "delegate": {
                "identity": identity,
                "organization": organization,
                "roles": [role],
                "publicKey": public_key,
                "fingerprint": _ssh_public_key_fingerprint(public_key, f"test.{name}"),
                "capabilities": sorted(role_policy["capabilities"]),
                "criterionAllowlist": sorted(criteria),
                "validFrom": "2026-07-12T10:00:00Z",
                "validUntil": "2026-08-11T10:00:00Z",
            },
            "issuedAt": "2026-07-12T10:00:00Z",
            "reason": f"Delegate synthetic {name} community fact scope.",
        }
        return self._envelope(
            schema=DELEGATION_SCHEMA,
            kind=DELEGATION_KIND,
            body=body,
            key_name="root",
            principal="root@test.invalid",
            namespace=REVIEWER_DELEGATION_NAMESPACE,
        )

    def _revocation(self, delegation: dict) -> dict:
        delegate = delegation["body"]["delegate"]
        body = {
            "revocationId": "revocation-" + delegation["body"]["delegationId"],
            "delegationDigest": delegation["attestationDigest"],
            "policyDigest": self.policy_digest,
            "controlPlaneDigest": self.control_digest,
            "sourceCommit": self.source_commit,
            "priorChainHeadDigest": self.chain_head,
            "delegator": {
                "identity": "root@test.invalid",
                "organization": "root-org",
                "fingerprint": self.policy["sshPrincipals"][0]["fingerprint"],
            },
            "delegateIdentity": delegate["identity"],
            "delegateFingerprint": delegate["fingerprint"],
            "issuedAt": "2026-07-12T11:00:00Z",
            "reason": "Withdraw exact synthetic community reviewer delegation.",
        }
        return self._envelope(
            schema=REVOCATION_SCHEMA,
            kind=REVOCATION_KIND,
            body=body,
            key_name="root",
            principal="root@test.invalid",
            namespace=REVIEWER_DELEGATION_NAMESPACE,
        )

    def _roster(self, delegations: list[dict], revocations: list[dict] | None = None):
        return build_effective_reviewer_roster(
            policy_result=self.policy_result,
            delegations=delegations,
            revocations=revocations or [],
            expected_policy_digest=self.policy_digest,
            expected_control_plane_digest=self.control_digest,
            expected_source_commit=self.source_commit,
            expected_prior_chain_head_digest=self.chain_head,
            now=self.now,
        )

    def _subject(self, criterion_id: str) -> SubjectBinding:
        return SubjectBinding(
            phase="P00",
            work_unit="P00.W05" if criterion_id == REVIEW else "P00.W02",
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
            contract_digest=D("e" if criterion_id == REVIEW else "f"),
        )

    @staticmethod
    def _criterion(criterion_id: str) -> CriterionBinding:
        values = {
            OUTREACH: (
                "attestation://upstream/outreach/v1",
                "evidence-schema://attestation/external-review/v1",
            ),
            DESIGN_PARTNERS: (
                "attestation://review/design-partners/v1",
                "evidence-schema://attestation/design-partners/v1",
            ),
            REVIEW: (
                "attestation://review/external-feedback/v1",
                "evidence-schema://attestation/external-review/v1",
            ),
        }
        evaluator, evidence_schema = values[criterion_id]
        return CriterionBinding(
            criterion_id=criterion_id,
            kind="EXTERNAL",
            evaluator=evaluator,
            evaluator_digest=D("1"),
            evaluator_status="external-only",
            evidence_schema=evidence_schema,
            evidence_schema_digest=D("2"),
            dataset_digest=D("3"),
            threshold_digest=D("4"),
        )

    @staticmethod
    def _subject_doc(subject: SubjectBinding) -> dict[str, str]:
        return {
            "phase": subject.phase,
            "workUnit": subject.work_unit,
            "sourceCommit": subject.source_commit,
            "controlPlaneDigest": subject.control_plane_digest,
            "contractDigest": subject.contract_digest,
        }

    @staticmethod
    def _criterion_doc(criterion: CriterionBinding) -> dict[str, str]:
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

    def _single_statement(
        self,
        *,
        kind: str,
        body: dict,
        key_name: str,
        principal: str,
        namespace: str,
    ) -> dict:
        return self._envelope(
            schema=STATEMENT_SCHEMA,
            kind=kind,
            body=body,
            key_name=key_name,
            principal=principal,
            namespace=namespace,
        )

    def _dual_statement(
        self,
        *,
        body: dict,
        maintainer_key: str = "root",
        external_key: str = "outreach",
        external_principal: str = "recipient@test.invalid",
    ) -> dict:
        unsigned = {
            "schemaVersion": STATEMENT_SCHEMA,
            "kind": OUTREACH_KIND,
            "body": body,
        }
        payload = canonical_json_bytes(unsigned)
        statement = {
            **unsigned,
            "signatures": {
                "maintainer": {
                    "scheme": "openssh-sshsig-v1",
                    "namespace": OUTREACH_NAMESPACE,
                    "principal": "root@test.invalid",
                    "value": self._sign(payload, maintainer_key, OUTREACH_NAMESPACE),
                },
                "externalAttestor": {
                    "scheme": "openssh-sshsig-v1",
                    "namespace": OUTREACH_NAMESPACE,
                    "principal": external_principal,
                    "value": self._sign(payload, external_key, OUTREACH_NAMESPACE),
                },
            },
        }
        statement["attestationDigest"] = document_digest(statement)
        return statement

    def _outreach_statement(self, *, status: str = "SENT") -> dict:
        subject = self._subject(OUTREACH)
        body = {
            "statementId": "outreach-001",
            "freezeDigest": self.freeze_digest,
            "subject": self._subject_doc(subject),
            "criterionId": OUTREACH,
            "contentDigest": D("5"),
            "scope": "Request a scoped technical review of the project plan.",
            "recipient": {
                "principal": "recipient@test.invalid",
                "organization": "recipient-org",
            },
            "channel": "email",
            "dispatchStatus": status,
            "sentAt": "2026-07-12T10:30:00Z",
            "receipt": {
                "receiptId": "receipt-001",
                "status": "DELIVERED",
                "receivedAt": "2026-07-12T10:31:00Z",
            },
            "issuedAt": "2026-07-12T10:32:00Z",
            "maintainer": {
                "principal": "root@test.invalid",
                "organization": "root-org",
                "role": "authorized-maintainer",
            },
            "externalAttestor": {
                "principal": "recipient@test.invalid",
                "organization": "recipient-org",
                "role": "external-attestor",
            },
        }
        return self._dual_statement(body=body)

    def _partner_statement(
        self,
        name: str,
        *,
        statement_id: str | None = None,
        organization: str | None = None,
    ) -> dict:
        subject = self._subject(DESIGN_PARTNERS)
        actor = {
            "principal": f"{name}@test.invalid",
            "organization": organization or f"{name}-org",
            "role": "external-attestor",
        }
        body = {
            "statementId": statement_id or f"willingness-{name}",
            "freezeDigest": self.freeze_digest,
            "subject": self._subject_doc(subject),
            "criterionId": DESIGN_PARTNERS,
            "commitment": "REVIEW_AND_TRY",
            "scope": "Review the P00 evidence model and try the bootstrap workflow.",
            "maintainerOf": f"project-{name}",
            "conflictOfInterest": {
                "independent": True,
                "statement": "No employment or control relationship with the project.",
            },
            "issuedAt": "2026-07-12T10:40:00Z",
            "actor": actor,
        }
        return self._single_statement(
            kind=DESIGN_PARTNER_KIND,
            body=body,
            key_name=name,
            principal=actor["principal"],
            namespace=DESIGN_PARTNER_NAMESPACE,
        )

    def _review_statement(self, *, manifest: list[dict] | None = None) -> dict:
        subject = self._subject(REVIEW)
        body = {
            "statementId": "review-001",
            "freezeDigest": self.freeze_digest,
            "subject": self._subject_doc(subject),
            "criterionId": REVIEW,
            "feedbackManifest": (
                [
                    {
                        "itemId": "feedback-001",
                        "reviewedArtifactDigest": D("6"),
                        "feedbackDigest": D("7"),
                        "summary": "The threat model omits a delegated reviewer replay boundary.",
                        "recommendation": "Bind every delegation and revocation to the exact chain head.",
                    }
                ]
                if manifest is None
                else manifest
            ),
            "conflictOfInterest": {
                "independent": True,
                "statement": "Reviewer is independent from the project organization.",
            },
            "issuedAt": "2026-07-12T10:50:00Z",
            "actor": {
                "principal": "reviewer@test.invalid",
                "organization": "reviewer-org",
                "role": "independent-external-reviewer",
            },
        }
        return self._single_statement(
            kind=REVIEW_KIND,
            body=body,
            key_name="reviewer",
            principal="reviewer@test.invalid",
            namespace=REVIEW_NAMESPACE,
        )

    def _raw_evidence(self, criterion_id: str, statements: list[dict]) -> bytes:
        subject = self._subject(criterion_id)
        criterion = self._criterion(criterion_id)
        candidate = {
            "schemaVersion": EVIDENCE_SCHEMA,
            "kind": EVIDENCE_KIND,
            "criterionId": criterion_id,
            "policyDigest": self.policy_digest,
            "priorChainHeadDigest": self.chain_head,
            "freezeDigest": self.freeze_digest,
            "subject": self._subject_doc(subject),
            "criterion": self._criterion_doc(criterion),
            "statements": sorted(
                statements, key=lambda item: item["body"]["statementId"]
            ),
            "factEvidenceDigest": D("0"),
        }
        return serialize_community_fact_evidence(candidate)

    def _result(
        self,
        criterion_id: str,
        raw_evidence: bytes,
        *,
        roster=None,
        outer: str | None = None,
    ) -> tuple[dict, VerifiedCriterionResult]:
        selected_roster = roster or self.roster
        principal_by_criterion = {
            OUTREACH: "recipient@test.invalid",
            DESIGN_PARTNERS: "partner-one@test.invalid",
            REVIEW: "collector@test.invalid",
        }
        principal = outer or principal_by_criterion[criterion_id]
        selected = next(
            item for item in selected_roster.principals if item.identity == principal
        )
        fact_digest = json.loads(raw_evidence)["factEvidenceDigest"]
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace=EXTERNAL_CRITERION_NAMESPACE,
            principal=selected.identity,
            role="external-attestor",
            organization=selected.organization,
            statement_digest=D("8"),
            authority_digest=selected_roster.authority_digest,
            source_commit=self.source_commit,
            control_plane_digest=self.control_digest,
        )
        result = VerifiedCriterionResult(
            attestation_digest=D("9"),
            statement_digest=D("a"),
            result_id="result-" + criterion_id,
            freeze_digest=self.freeze_digest,
            subject=self._subject(criterion_id),
            criterion=self._criterion(criterion_id),
            outcome="ATTESTED",
            evidence_digest=fact_digest,
            run_pair_digest=None,
            signature_verified=True,
            fact_status="signature_verified_fact_unverified",
            criterion_satisfied=False,
            signer=signer,
        )
        return (
            {
                "attestationDigest": result.attestation_digest,
                "body": {"evidenceDigest": fact_digest},
            },
            result,
        )

    def _verify(
        self,
        criterion_id: str,
        raw_evidence: bytes,
        *,
        roster=None,
        outer: str | None = None,
    ) -> dict:
        selected_roster = roster or self.roster
        envelope, result = self._result(
            criterion_id, raw_evidence, roster=selected_roster, outer=outer
        )
        verifier = build_p00_community_fact_verifier(
            criterion_id,
            raw_evidence,
            reviewer_roster=selected_roster,
            policy_result=self.policy_result,
            expected_policy_digest=self.policy_digest,
            expected_prior_chain_head_digest=self.chain_head,
            verification_time=self.now,
        )
        return dict(verifier(envelope, result))

    def _assert_code(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_three_reference_models_return_exact_fact_mapping(self) -> None:
        fixtures = {
            OUTREACH: self._raw_evidence(OUTREACH, [self._outreach_statement()]),
            DESIGN_PARTNERS: self._raw_evidence(
                DESIGN_PARTNERS,
                [
                    self._partner_statement("partner-one"),
                    self._partner_statement("partner-two"),
                    self._partner_statement("partner-three"),
                ],
            ),
            REVIEW: self._raw_evidence(REVIEW, [self._review_statement()]),
        }
        reviewer = next(
            item
            for item in self.roster.principals
            if item.identity == "reviewer@test.invalid"
        )
        self.assertEqual(reviewer.roles, ("independent-external-reviewer",))
        for criterion_id, raw in fixtures.items():
            with self.subTest(criterion_id=criterion_id):
                fact = self._verify(criterion_id, raw)
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
                self.assertEqual(fact["criterionId"], criterion_id)
                self.assertEqual(fact["factVerifierDigest"], FACT_VERIFIER_DIGEST)
                self.assertEqual(
                    fact["factEvidenceDigest"],
                    json.loads(raw)["factEvidenceDigest"],
                )
                self.assertIs(fact["satisfied"], True)

    def test_draft_insufficient_partners_and_empty_feedback_fail(self) -> None:
        draft = self._raw_evidence(OUTREACH, [self._outreach_statement(status="DRAFT")])
        self._assert_code("outreach_not_sent", self._verify, OUTREACH, draft)

        only_two = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                self._partner_statement("partner-one"),
                self._partner_statement("partner-two"),
            ],
        )
        self._assert_code(
            "insufficient_design_partners",
            self._verify,
            DESIGN_PARTNERS,
            only_two,
        )

        empty = self._raw_evidence(REVIEW, [self._review_statement(manifest=[])])
        self._assert_code("empty_external_feedback", self._verify, REVIEW, empty)

    def test_design_partner_principal_and_organization_duplicates_fail(self) -> None:
        duplicate_principal = self._partner_statement(
            "partner-one", statement_id="willingness-partner-four"
        )
        raw = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                self._partner_statement("partner-one"),
                self._partner_statement("partner-two"),
                duplicate_principal,
            ],
        )
        self._assert_code(
            "duplicate_design_partner_principal",
            self._verify,
            DESIGN_PARTNERS,
            raw,
        )

        alternate_two = self._delegation(
            name="partner-two-same-org",
            identity="partner-two@test.invalid",
            organization="partner-one-org",
            key_name="partner-two",
            role="external-attestor",
            criteria=[DESIGN_PARTNERS],
        )
        delegations = [
            item for name, item in self.delegations.items() if name != "partner-two"
        ] + [alternate_two]
        roster = self._roster(delegations)
        same_org = self._partner_statement(
            "partner-two", organization="partner-one-org"
        )
        raw = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                self._partner_statement("partner-one"),
                same_org,
                self._partner_statement("partner-three"),
            ],
        )
        self._assert_code(
            "duplicate_design_partner_organization",
            self._verify,
            DESIGN_PARTNERS,
            raw,
            roster=roster,
        )

    def test_source_freeze_coi_namespace_and_tamper_fail(self) -> None:
        raw = self._raw_evidence(REVIEW, [self._review_statement()])
        copied = json.loads(raw)
        copied["subject"]["sourceCommit"] = "b" * 40
        copied_raw = serialize_community_fact_evidence(copied)
        self._assert_code(
            "community_fact_subject_mismatch",
            self._verify,
            REVIEW,
            copied_raw,
        )

        statement = self._review_statement()
        statement["body"]["freezeDigest"] = D("e")
        statement = self._single_statement(
            kind=REVIEW_KIND,
            body=statement["body"],
            key_name="reviewer",
            principal="reviewer@test.invalid",
            namespace=REVIEW_NAMESPACE,
        )
        wrong_freeze = self._raw_evidence(REVIEW, [statement])
        self._assert_code(
            "community_fact_freeze_mismatch",
            self._verify,
            REVIEW,
            wrong_freeze,
        )

        statement = self._review_statement()
        statement["body"]["criterionId"] = OUTREACH
        statement = self._single_statement(
            kind=REVIEW_KIND,
            body=statement["body"],
            key_name="reviewer",
            principal="reviewer@test.invalid",
            namespace=REVIEW_NAMESPACE,
        )
        wrong_criterion = self._raw_evidence(REVIEW, [statement])
        self._assert_code(
            "community_fact_criterion_mismatch",
            self._verify,
            REVIEW,
            wrong_criterion,
        )

        statement = self._review_statement()
        statement["body"]["conflictOfInterest"]["independent"] = False
        statement = self._single_statement(
            kind=REVIEW_KIND,
            body=statement["body"],
            key_name="reviewer",
            principal="reviewer@test.invalid",
            namespace=REVIEW_NAMESPACE,
        )
        coi = self._raw_evidence(REVIEW, [statement])
        self._assert_code(
            "community_reviewer_not_independent", self._verify, REVIEW, coi
        )

        statement = self._review_statement()
        statement["body"]["issuedAt"] = "2026-07-12T10:50:00+00:00"
        statement = self._single_statement(
            kind=REVIEW_KIND,
            body=statement["body"],
            key_name="reviewer",
            principal="reviewer@test.invalid",
            namespace=REVIEW_NAMESPACE,
        )
        non_utc = self._raw_evidence(REVIEW, [statement])
        self._assert_code("invalid_community_fact_time", self._verify, REVIEW, non_utc)

        statement = self._partner_statement("partner-one")
        statement["signature"]["namespace"] = OUTREACH_NAMESPACE
        statement["attestationDigest"] = document_digest(
            statement, omit_field="attestationDigest"
        )
        namespace = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                statement,
                self._partner_statement("partner-two"),
                self._partner_statement("partner-three"),
            ],
        )
        self._assert_code(
            "signature_namespace_mismatch",
            self._verify,
            DESIGN_PARTNERS,
            namespace,
        )

        statement = self._partner_statement("partner-one")
        statement["body"]["scope"] = "Tampered after signature creation."
        statement["attestationDigest"] = document_digest(
            statement, omit_field="attestationDigest"
        )
        tampered = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                statement,
                self._partner_statement("partner-two"),
                self._partner_statement("partner-three"),
            ],
        )
        self._assert_code(
            "invalid_ed25519_signature",
            self._verify,
            DESIGN_PARTNERS,
            tampered,
        )

    def test_outer_roster_revocation_cannot_be_omitted_by_community_evidence(
        self,
    ) -> None:
        revocation = self._revocation(self.delegations["partner-three"])
        roster = self._roster(list(self.delegations.values()), [revocation])
        raw = self._raw_evidence(
            DESIGN_PARTNERS,
            [
                self._partner_statement("partner-one"),
                self._partner_statement("partner-two"),
                self._partner_statement("partner-three"),
            ],
        )
        self._assert_code(
            "signer_not_allowed",
            self._verify,
            DESIGN_PARTNERS,
            raw,
            roster=roster,
        )

        extra = json.loads(raw)
        extra["revocations"] = []
        with self.assertRaises(CommunityFactError) as caught:
            build_p00_community_fact_verifier(
                DESIGN_PARTNERS,
                canonical_json_bytes(extra),
                reviewer_roster=self.roster,
                policy_result=self.policy_result,
                expected_policy_digest=self.policy_digest,
                expected_prior_chain_head_digest=self.chain_head,
                verification_time=self.now,
            )
        self.assertEqual(caught.exception.code, "invalid_community_fact_schema")

        self._assert_code(
            "unverified_internal_result",
            self._verify,
            DESIGN_PARTNERS,
            raw,
            roster=replace(self.roster),
        )

    def test_same_key_alias_copy_digest_and_review_self_attestation_fail(self) -> None:
        alias = self._delegation(
            name="partner-alias",
            identity="partner-alias@test.invalid",
            organization="partner-alias-org",
            key_name="partner-one",
            role="external-attestor",
            criteria=[DESIGN_PARTNERS],
        )
        self._assert_code(
            "key_identity_alias",
            self._roster,
            [*self.delegations.values(), alias],
        )

        raw = self._raw_evidence(REVIEW, [self._review_statement()])
        with self.assertRaises(CommunityFactError) as noncanonical:
            build_p00_community_fact_verifier(
                REVIEW,
                raw + b"\n",
                reviewer_roster=self.roster,
                policy_result=self.policy_result,
                expected_policy_digest=self.policy_digest,
                expected_prior_chain_head_digest=self.chain_head,
                verification_time=self.now,
            )
        self.assertEqual(noncanonical.exception.code, "noncanonical_community_fact")

        copied = json.loads(raw)
        copied["factEvidenceDigest"] = D("f")
        with self.assertRaises(CommunityFactError) as copied_error:
            build_p00_community_fact_verifier(
                REVIEW,
                canonical_json_bytes(copied),
                reviewer_roster=self.roster,
                policy_result=self.policy_result,
                expected_policy_digest=self.policy_digest,
                expected_prior_chain_head_digest=self.chain_head,
                verification_time=self.now,
            )
        self.assertEqual(copied_error.exception.code, "community_fact_digest_mismatch")

        self._assert_code(
            "role_not_authorized",
            self._verify,
            REVIEW,
            raw,
            outer="reviewer@test.invalid",
        )


if __name__ == "__main__":
    unittest.main()
