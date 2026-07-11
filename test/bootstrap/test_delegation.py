"""Adversarial tests for chain-bound P00 reviewer delegation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.phasegate.delegation import (
    DELEGATION_KIND,
    DELEGATION_SCHEMA,
    REVOCATION_KIND,
    REVOCATION_SCHEMA,
    authorize_criterion_signer,
    build_effective_reviewer_roster,
    make_provenance_signer_verifier,
    verify_reviewer_delegation,
)
from tools.phasegate.digest import canonical_json_bytes
from tools.phasegate.oidc import jwks_snapshot_digest
from tools.phasegate.protected import (
    ProtectedVerificationError,
    _ssh_public_key_fingerprint,
    document_digest,
)
from tools.phasegate.protected_v2 import (
    REVIEWER_DELEGATION_NAMESPACE,
    validate_trust_policy_v2,
)
from tools.phasegate.provenance import (
    EXTERNAL_CRITERION_NAMESPACE,
    HUMAN_CRITERION_NAMESPACE,
    VerifiedSignerResult,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class ReviewerDelegationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="reviewer-delegation-")
        cls.root = Path(cls.temporary.name)
        cls.keys = {
            name: cls._generate_key(name)
            for name in (
                "root",
                "rights",
                "technical",
                "external",
                "external-two",
                "alternate",
            )
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _generate_key(cls, name: str) -> Path:
        path = cls.root / name
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
            private_key.with_suffix(".pub")
            .read_text(encoding="utf-8")
            .split()[:2]
        )

    def setUp(self) -> None:
        self.now = datetime(2026, 7, 12, 12, 0, 0, tzinfo=timezone.utc)
        self.source_commit = "a" * 40
        self.control_digest = "sha256:" + "b" * 64
        self.chain_head = "sha256:" + "c" * 64
        self.snapshot = json.loads(
            (
                REPO_ROOT
                / "execution/protected-verifier/github-actions-oidc-jwks.json"
            ).read_text(encoding="utf-8")
        )
        self.snapshot_digest = jwks_snapshot_digest(self.snapshot)
        self.policy = json.loads(
            (REPO_ROOT / "execution/protected-verifier/trust-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.policy["controlPlaneDigest"] = self.control_digest
        self.policy["signatureSchemes"]["stateEvent"][
            "jwksSnapshotDigest"
        ] = self.snapshot_digest
        root = self.policy["sshPrincipals"][0]
        root["identity"] = "root@test.invalid"
        root["organization"] = "root-org"
        root["publicKey"] = self._public_key(self.keys["root"])
        root["fingerprint"] = _ssh_public_key_fingerprint(
            root["publicKey"], "test.root"
        )
        self.policy_digest = document_digest(self.policy)
        self.policy_result = validate_trust_policy_v2(
            self.policy,
            jwks_snapshot=self.snapshot,
            expected_policy_digest=self.policy_digest,
            expected_jwks_snapshot_digest=self.snapshot_digest,
            expected_control_plane_digest=self.control_digest,
        )

    def _sign(self, payload: bytes, key: Path, namespace: str) -> str:
        return subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                namespace,
            ],
            input=payload,
            check=True,
            capture_output=True,
            timeout=10,
        ).stdout.decode("ascii")

    def _envelope(
        self,
        *,
        schema: str,
        kind: str,
        body: dict,
        key: Path | None = None,
        principal: str = "root@test.invalid",
        namespace: str = REVIEWER_DELEGATION_NAMESPACE,
    ) -> dict:
        unsigned = {"schemaVersion": schema, "kind": kind, "body": body}
        envelope = {
            **unsigned,
            "signature": {
                "scheme": "openssh-sshsig-v1",
                "namespace": namespace,
                "principal": principal,
                "value": self._sign(
                    canonical_json_bytes(unsigned), key or self.keys["root"], namespace
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
        roles: list[str],
        criteria: list[str],
        capabilities: list[str] | None = None,
        valid_from: str = "2026-07-12T10:00:00Z",
        valid_until: str = "2026-08-11T10:00:00Z",
        delegator: dict | None = None,
        signing_key: Path | None = None,
        signing_principal: str = "root@test.invalid",
    ) -> dict:
        public_key = self._public_key(self.keys[key_name])
        if capabilities is None:
            role_policy = self.policy["reviewerDelegation"]["roleGrants"]
            capabilities = sorted(
                {
                    capability
                    for role in roles
                    for capability in role_policy.get(role, {}).get(
                        "capabilities", []
                    )
                }
            )
        root = self.policy["sshPrincipals"][0]
        body = {
            "delegationId": f"delegation-{name}",
            "policyDigest": self.policy_digest,
            "controlPlaneDigest": self.control_digest,
            "sourceCommit": self.source_commit,
            "priorChainHeadDigest": self.chain_head,
            "delegator": delegator
            or {
                "identity": root["identity"],
                "organization": root["organization"],
                "fingerprint": root["fingerprint"],
            },
            "delegate": {
                "identity": identity,
                "organization": organization,
                "roles": roles,
                "publicKey": public_key,
                "fingerprint": _ssh_public_key_fingerprint(
                    public_key, f"test.{name}"
                ),
                "capabilities": capabilities,
                "criterionAllowlist": criteria,
                "validFrom": valid_from,
                "validUntil": valid_until,
            },
            "issuedAt": "2026-07-12T10:00:00Z",
            "reason": f"Delegate the exact synthetic {name} review scope.",
        }
        return self._envelope(
            schema=DELEGATION_SCHEMA,
            kind=DELEGATION_KIND,
            body=body,
            key=signing_key,
            principal=signing_principal,
        )

    def _rights(self, **overrides: object) -> dict:
        values = {
            "name": "rights",
            "identity": "rights@test.invalid",
            "organization": "rights-org",
            "key_name": "rights",
            "roles": ["independent-rights-reviewer"],
            "criteria": ["P00-H-CORPUS-RIGHTS"],
        }
        values.update(overrides)
        return self._delegation(**values)

    def _external(self, **overrides: object) -> dict:
        values = {
            "name": "external",
            "identity": "external@test.invalid",
            "organization": "external-org",
            "key_name": "external",
            "roles": ["external-attestor"],
            "criteria": ["P00-X-REVIEW"],
        }
        values.update(overrides)
        return self._delegation(**values)

    def _external_reviewer(self, **overrides: object) -> dict:
        values = {
            "name": "external-reviewer",
            "identity": "external-reviewer@test.invalid",
            "organization": "external-review-org",
            "key_name": "external-two",
            "roles": ["independent-external-reviewer"],
            "criteria": ["P00-H-GO-NOGO"],
        }
        values.update(overrides)
        return self._delegation(**values)

    def _revocation(self, delegation: dict, **overrides: object) -> dict:
        root = self.policy["sshPrincipals"][0]
        delegate = delegation["body"]["delegate"]
        body = {
            "revocationId": "revocation-rights",
            "delegationDigest": delegation["attestationDigest"],
            "policyDigest": self.policy_digest,
            "controlPlaneDigest": self.control_digest,
            "sourceCommit": self.source_commit,
            "priorChainHeadDigest": self.chain_head,
            "delegator": {
                "identity": root["identity"],
                "organization": root["organization"],
                "fingerprint": root["fingerprint"],
            },
            "delegateIdentity": delegate["identity"],
            "delegateFingerprint": delegate["fingerprint"],
            "issuedAt": "2026-07-12T11:00:00Z",
            "reason": "Withdraw the exact synthetic reviewer delegation.",
        }
        body.update(overrides)
        return self._envelope(
            schema=REVOCATION_SCHEMA,
            kind=REVOCATION_KIND,
            body=body,
        )

    def _roster(
        self, delegations: list[dict], revocations: list[dict] | None = None
    ):
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

    def _assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ProtectedVerificationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_effective_roster_and_adapter_preserve_real_role(self) -> None:
        rights = self._rights()
        external = self._external()
        roster = self._roster([rights, external])
        reordered = self._roster([external, rights])
        self.assertEqual(roster.authority_digest, reordered.authority_digest)
        self.assertEqual(
            tuple(value.identity for value in roster.principals),
            ("external@test.invalid", "rights@test.invalid", "root@test.invalid"),
        )
        authorization = authorize_criterion_signer(
            roster,
            principal="rights@test.invalid",
            criterion_id="P00-H-CORPUS-RIGHTS",
            required_role="independent-rights-reviewer",
            required_capability="attest-human-result",
            at=self.now,
        )
        self.assertEqual(authorization.role, "independent-rights-reviewer")
        self.assertEqual(authorization.authority_digest, roster.authority_digest)
        self._assert_error(
            "unverified_internal_result",
            authorize_criterion_signer,
            replace(roster),
            principal="rights@test.invalid",
            criterion_id="P00-H-CORPUS-RIGHTS",
            required_role="independent-rights-reviewer",
            required_capability="attest-human-result",
            at=self.now,
        )

        verifier = make_provenance_signer_verifier(
            roster,
            criterion_id="P00-H-CORPUS-RIGHTS",
            required_role="independent-rights-reviewer",
            required_capability="attest-human-result",
            expected_namespace=HUMAN_CRITERION_NAMESPACE,
            expected_source_commit=self.source_commit,
            expected_control_plane_digest=self.control_digest,
            verification_time=self.now,
        )
        payload = b"criterion-scoped rights statement"
        signature = {
            "scheme": "openssh-sshsig-v1",
            "namespace": HUMAN_CRITERION_NAMESPACE,
            "principal": "rights@test.invalid",
            "value": self._sign(
                payload, self.keys["rights"], HUMAN_CRITERION_NAMESPACE
            ),
        }
        result = verifier(payload, signature, HUMAN_CRITERION_NAMESPACE)
        self.assertIsInstance(result, VerifiedSignerResult)
        self.assertEqual(result.role, "independent-rights-reviewer")
        self.assertNotEqual(result.role, "independent-reviewer")
        self.assertEqual(result.organization, "rights-org")
        self.assertEqual(result.authority_digest, roster.authority_digest)

        external_verifier = make_provenance_signer_verifier(
            roster,
            criterion_id="P00-X-REVIEW",
            required_role="external-attestor",
            required_capability="attest-external-result",
            expected_namespace=EXTERNAL_CRITERION_NAMESPACE,
            expected_source_commit=self.source_commit,
            expected_control_plane_digest=self.control_digest,
            verification_time=self.now,
        )
        external_payload = b"criterion-scoped external statement"
        external_result = external_verifier(
            external_payload,
            {
                "scheme": "openssh-sshsig-v1",
                "namespace": EXTERNAL_CRITERION_NAMESPACE,
                "principal": "external@test.invalid",
                "value": self._sign(
                    external_payload,
                    self.keys["external"],
                    EXTERNAL_CRITERION_NAMESPACE,
                ),
            },
            EXTERNAL_CRITERION_NAMESPACE,
        )
        self.assertEqual(external_result.role, "external-attestor")

    def test_scope_capability_and_criterion_expansion_fail_closed(self) -> None:
        cases = [
            (
                self._rights(roles=["independent-reviewer"]),
                "delegation_scope_exceeded",
            ),
            (
                self._rights(
                    capabilities=["attest-human-result", "delegate-reviewer"]
                ),
                "delegation_scope_exceeded",
            ),
            (
                self._rights(
                    capabilities=["approve-control-plane", "attest-human-result"]
                ),
                "delegation_scope_exceeded",
            ),
            (
                self._rights(criteria=["P00-H-SPIKE-ADR"]),
                "delegation_scope_exceeded",
            ),
            (
                self._rights(capabilities=["attest-external-result"]),
                "delegation_capability_mismatch",
            ),
        ]
        for statement, code in cases:
            with self.subTest(code=code):
                self._assert_error(code, self._roster, [statement])

    def test_self_delegation_and_key_identity_aliases_are_rejected(self) -> None:
        root = self.policy["sshPrincipals"][0]
        self._assert_error(
            "self_delegation",
            self._roster,
            [self._rights(identity=root["identity"])],
        )
        self._assert_error(
            "self_delegation",
            self._roster,
            [self._rights(key_name="root")],
        )
        aliased = self._rights(
            name="rights-alias",
            identity="rights-alias@test.invalid",
            organization="other-org",
            key_name="rights",
        )
        self._assert_error(
            "key_identity_alias", self._roster, [self._rights(), aliased]
        )
        duplicate_identity = self._rights(
            name="rights-duplicate",
            key_name="alternate",
        )
        self._assert_error(
            "ambiguous_signer",
            self._roster,
            [self._rights(), duplicate_identity],
        )

    def test_policy_control_source_chain_namespace_and_body_replay_fail(self) -> None:
        statement = self._rights()
        pin_cases = [
            (
                {"expected_policy_digest": "sha256:" + "0" * 64},
                "trust_policy_digest_mismatch",
            ),
            (
                {"expected_control_plane_digest": "sha256:" + "1" * 64},
                "control_plane_digest_mismatch",
            ),
            (
                {"expected_source_commit": "d" * 40},
                "delegation_binding_mismatch",
            ),
            (
                {"expected_prior_chain_head_digest": "sha256:" + "e" * 64},
                "prior_chain_head_mismatch",
            ),
        ]
        base = {
            "policy_result": self.policy_result,
            "expected_policy_digest": self.policy_digest,
            "expected_control_plane_digest": self.control_digest,
            "expected_source_commit": self.source_commit,
            "expected_prior_chain_head_digest": self.chain_head,
            "now": self.now,
        }
        for overrides, code in pin_cases:
            with self.subTest(code=code):
                self._assert_error(
                    code,
                    verify_reviewer_delegation,
                    statement,
                    **{**base, **overrides},
                )

        wrong_namespace = deepcopy(statement)
        wrong_namespace["signature"]["namespace"] = "agentapi-doctor/other/v1"
        wrong_namespace["attestationDigest"] = document_digest(
            wrong_namespace, omit_field="attestationDigest"
        )
        self._assert_error(
            "signature_namespace_mismatch", self._roster, [wrong_namespace]
        )

        tampered = deepcopy(statement)
        tampered["body"]["reason"] = "Tampered after the root signature."
        tampered["attestationDigest"] = document_digest(
            tampered, omit_field="attestationDigest"
        )
        self._assert_error("invalid_ed25519_signature", self._roster, [tampered])

    def test_revocation_is_exact_signed_and_removes_authority(self) -> None:
        rights = self._rights()
        revocation = self._revocation(rights)
        roster = self._roster([rights], [revocation])
        self.assertNotIn(
            "rights@test.invalid",
            {principal.identity for principal in roster.principals},
        )
        self._assert_error(
            "signer_not_allowed",
            authorize_criterion_signer,
            roster,
            principal="rights@test.invalid",
            criterion_id="P00-H-CORPUS-RIGHTS",
            required_role="independent-rights-reviewer",
            required_capability="attest-human-result",
            at=self.now,
        )

        unknown = self._revocation(
            rights, delegationDigest="sha256:" + "0" * 64
        )
        self._assert_error("unknown_delegation", self._roster, [rights], [unknown])

        wrong_identity = self._revocation(
            rights, delegateIdentity="other@test.invalid"
        )
        self._assert_error(
            "revocation_target_mismatch",
            self._roster,
            [rights],
            [wrong_identity],
        )

        wrong_chain = self._revocation(
            rights, priorChainHeadDigest="sha256:" + "f" * 64
        )
        self._assert_error(
            "prior_chain_head_mismatch",
            self._roster,
            [rights],
            [wrong_chain],
        )

        duplicate = deepcopy(revocation)
        duplicate["body"]["revocationId"] = "revocation-rights-again"
        duplicate = self._envelope(
            schema=REVOCATION_SCHEMA,
            kind=REVOCATION_KIND,
            body=duplicate["body"],
        )
        self._assert_error(
            "duplicate_revocation",
            self._roster,
            [rights],
            [revocation, duplicate],
        )

    def test_delegates_cannot_redelegate_and_go_no_go_stays_multisignature(self) -> None:
        rights = self._rights()
        delegate = rights["body"]["delegate"]
        attempted_redelegation = self._delegation(
            name="technical-by-delegate",
            identity="technical@test.invalid",
            organization="technical-org",
            key_name="technical",
            roles=["independent-technical-reviewer"],
            criteria=["P00-H-SPIKE-ADR"],
            delegator={
                "identity": delegate["identity"],
                "organization": delegate["organization"],
                "fingerprint": delegate["fingerprint"],
            },
            signing_key=self.keys["rights"],
            signing_principal=delegate["identity"],
        )
        self._assert_error(
            "delegator_not_authorized", self._roster, [attempted_redelegation]
        )

        external_reviewer = self._external_reviewer()
        roster = self._roster([external_reviewer])
        root_authorization = authorize_criterion_signer(
            roster,
            principal="root@test.invalid",
            criterion_id="P00-H-GO-NOGO",
            required_role="authorized-maintainer",
            required_capability="attest-human-result",
            at=self.now,
        )
        external_authorization = authorize_criterion_signer(
            roster,
            principal="external-reviewer@test.invalid",
            criterion_id="P00-H-GO-NOGO",
            required_role="independent-external-reviewer",
            required_capability="attest-human-result",
            at=self.now,
        )
        self.assertNotEqual(
            root_authorization.principal, external_authorization.principal
        )
        self.assertNotEqual(
            root_authorization.organization, external_authorization.organization
        )
        self._assert_error(
            "multisignature_verifier_required",
            make_provenance_signer_verifier,
            roster,
            criterion_id="P00-H-GO-NOGO",
            required_role="independent-external-reviewer",
            required_capability="attest-human-result",
            expected_namespace=HUMAN_CRITERION_NAMESPACE,
            expected_source_commit=self.source_commit,
            expected_control_plane_digest=self.control_digest,
            verification_time=self.now,
        )

        too_long = self._rights(
            valid_until="2026-10-11T10:00:01Z"
        )
        self._assert_error(
            "delegation_validity_too_long", self._roster, [too_long]
        )


if __name__ == "__main__":
    unittest.main()
