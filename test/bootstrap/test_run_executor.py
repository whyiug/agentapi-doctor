from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.phasegate.gate_runner import FIXED_COMMANDS  # noqa: E402
from tools.phasegate.execution_artifact import TOOL_SCHEMA, toolchain_digest  # noqa: E402
from tools.phasegate.p00_evaluators import build_paired_input  # noqa: E402
from tools.phasegate.p00_evaluators import evaluate_strict  # noqa: E402
from tools.phasegate.provenance import (  # noqa: E402
    CriterionBinding,
    SubjectBinding,
    VerifiedProtectedInputFreeze,
    VerifiedSignerResult,
    _mark_verified,
)
from tools.phasegate.run_executor import (  # noqa: E402
    ExecutionLimits,
    ProtectedExecutionError,
    ensure_distinct_run_roots,
    execute_pair,
)
from tools.phasegate import run_executor as run_executor_module  # noqa: E402


CONTROL_EVALUATOR = "evaluator://bootstrap/control-plane/v1"
CONTROL_CRITERION = "P00-M-BOOTSTRAP-CONTROL"
ANTI_EVALUATOR = "evaluator://bootstrap/anti-placeholder/v1"
ANTI_CRITERION = "P00-M-ANTI-PLACEHOLDER"
REPRO_EVALUATOR = "evaluator://corpus/reproduction/v1"
REPRO_CRITERION = "P00-M-REPRO"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def executable_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def actual_toolchain_digest() -> str:
    return toolchain_digest(
        {
            "schemaVersion": TOOL_SCHEMA,
            "gitDigest": executable_digest(Path("/usr/bin/git").resolve(strict=True)),
            "pythonDigest": executable_digest(
                Path(sys.executable).resolve(strict=True)
            ),
            "unshareDigest": executable_digest(
                Path("/usr/bin/unshare").resolve(strict=True)
            ),
            "unshareArguments": ["--user", "--map-root-user", "--net", "--"],
        }
    )


class TemporaryGateRepository:
    def __init__(
        self, *, test_sleep_seconds: float = 0, loopback_port: int = 9
    ) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="agentapi-doctor-run-executor-test-"
        )
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(
            REPO_ROOT / "tools/phasegate",
            self.root / "tools/phasegate",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (self.root / "test/bootstrap").mkdir(parents=True)
        control_result = {
            "schemaVersion": "urn:agentapi-doctor:phasegate-result:v1",
            "status": "pass",
            "reasonCode": "candidate_valid",
            "controlPlaneDigest": digest("1"),
            "componentCount": 3,
        }
        (self.root / "tools/phasegate/main.py").write_text(
            textwrap.dedent(
                f"""
                import json
                import os
                import socket

                forbidden = [
                    key for key in os.environ
                    if key.startswith("RUN_EXECUTOR_SENTINEL_")
                ]
                if forbidden:
                    raise SystemExit(91)
                if os.environ.get("PYTHONNOUSERSITE") != "1":
                    raise SystemExit(92)
                for address in (("127.0.0.1", {loopback_port}), ("192.0.2.1", 9)):
                    connection = socket.socket()
                    connection.settimeout(0.1)
                    if connection.connect_ex(address) == 0:
                        raise SystemExit(93)
                    connection.close()
                print(json.dumps({control_result!r}, sort_keys=True))
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (self.root / "test/bootstrap/test_phasegate.py").write_text(
            textwrap.dedent(
                f"""
                import os
                import time
                import unittest


                class FixedBootstrapTest(unittest.TestCase):
                    def test_real_execution(self):
                        self.assertFalse(any(
                            key.startswith("RUN_EXECUTOR_SENTINEL_")
                            for key in os.environ
                        ))
                        self.assertEqual(os.environ.get("PYTHONNOUSERSITE"), "1")
                        time.sleep({test_sleep_seconds!r})
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self._git("init", "--quiet")
        self._git("config", "user.name", "Executor Test")
        self._git("config", "user.email", "executor@test.invalid")
        self._git("add", ".")
        self._git("commit", "--quiet", "-m", "fixture")
        self.commit = self._git("rev-parse", "HEAD").strip()

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

    def close(self) -> None:
        self.temporary.cleanup()


class RunExecutorTests(unittest.TestCase):
    @contextmanager
    def repository(self, *, test_sleep_seconds: float = 0, loopback_port: int = 9):
        fixture = TemporaryGateRepository(
            test_sleep_seconds=test_sleep_seconds,
            loopback_port=loopback_port,
        )
        try:
            yield fixture
        finally:
            fixture.close()

    def _criterion(
        self,
        criterion_id: str,
        evaluator: str,
        dataset_digest: str,
    ) -> CriterionBinding:
        return CriterionBinding(
            criterion_id=criterion_id,
            kind="MACHINE",
            evaluator=evaluator,
            evaluator_digest=digest("2"),
            evidence_schema="evidence-schema://test/machine/v1",
            evidence_schema_digest=digest("3"),
            dataset_digest=dataset_digest,
            threshold_digest=digest("4"),
        )

    def _freeze(
        self,
        source_commit: str,
        *,
        criterion_id: str,
        evaluator: str,
        dataset_digest: str = digest("5"),
    ) -> VerifiedProtectedInputFreeze:
        subject = SubjectBinding(
            phase="P00",
            work_unit="P00.W01",
            source_commit=source_commit,
            control_plane_digest=digest("6"),
            contract_digest=digest("7"),
        )
        signer = VerifiedSignerResult(
            scheme="openssh-sshsig-v1",
            namespace="agentapi-doctor/protected-input-freeze/v1",
            principal="reviewer@test.invalid",
            role="independent-reviewer",
            organization="review-test",
            statement_digest=digest("8"),
            authority_digest=digest("9"),
            source_commit=source_commit,
            control_plane_digest=digest("6"),
        )
        inputs = {
            "planDigest": digest("a"),
            "supportLockDigest": digest("b"),
            "toolchainDigest": actual_toolchain_digest(),
            "dependencySetDigest": digest("d"),
            "gateRunnerDigest": digest("e"),
            "evaluatorSetDigest": digest("f"),
            "metricDefinitionsDigest": digest("0"),
            "protectedAcceptanceDigest": digest("1"),
        }
        return _mark_verified(
            VerifiedProtectedInputFreeze(
                attestation_digest=digest("2"),
                statement_digest=digest("8"),
                freeze_id="freeze-run-executor-test",
                subject=subject,
                contract_approval_digest=digest("3"),
                protected_inputs=tuple(sorted(inputs.items())),
                criteria=(
                    self._criterion(
                        criterion_id,
                        evaluator,
                        dataset_digest,
                    ),
                ),
                signer=signer,
            )
        )

    def _reproduction_records(self) -> list[dict]:
        records = []
        for index in range(20):
            fingerprint = f"failure-{index}"
            records.append(
                {
                    "id": f"repro-{index:02d}",
                    "executionStatus": "completed" if index < 16 else "errored",
                    "realCodePath": True,
                    "localOnly": True,
                    "publicTargetContacted": False,
                    "weaponizedPayload": False,
                    "expectedFailureFingerprint": fingerprint,
                    "observedFailureFingerprint": (fingerprint if index < 16 else None),
                }
            )
        return records

    def test_fixed_bootstrap_command_runs_twice_with_isolated_environment(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            with mock.patch.dict(
                os.environ,
                {"RUN_EXECUTOR_SENTINEL_SECRET": "must-not-be-inherited"},
            ):
                pair = execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                )
        self.assertEqual(pair.outcome, "PASS")
        self.assertEqual(
            pair["runA"]["commands"][0]["command"],
            FIXED_COMMANDS[CONTROL_EVALUATOR],
        )
        self.assertEqual(pair["runA"]["commands"][0]["exitCode"], 0)
        self.assertEqual(pair["runB"]["commands"][0]["exitCode"], 0)
        self.assertFalse(pair["runA"]["sourceDirtyBeforeRun"])
        self.assertFalse(pair["runA"]["cleanCheckout"])
        self.assertTrue(pair["runB"]["cleanCheckout"])
        self.assertNotEqual(
            pair["runA"]["environmentDigest"],
            pair["runB"]["environmentDigest"],
        )

    def test_bootstrap_cannot_reach_host_loopback_or_external_route(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            loopback_port = listener.getsockname()[1]
            with self.repository(loopback_port=loopback_port) as repository:
                freeze = self._freeze(
                    repository.commit,
                    criterion_id=CONTROL_CRITERION,
                    evaluator=CONTROL_EVALUATOR,
                )
                pair = execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                )
            listener.settimeout(0.05)
            with self.assertRaises(TimeoutError):
                listener.accept()
        self.assertEqual(pair.outcome, "PASS")

    def test_p00_evaluator_is_dispatched_in_isolated_subprocess_and_sealed(
        self,
    ) -> None:
        with self.repository() as repository:
            payload = build_paired_input(
                REPRO_EVALUATOR,
                self._reproduction_records(),
                source_commit=repository.commit,
                control_plane_digest=digest("6"),
                evaluator_digest=digest("2"),
                dataset_id="p00-reproduction",
            )
            freeze = self._freeze(
                repository.commit,
                criterion_id=REPRO_CRITERION,
                evaluator=REPRO_EVALUATOR,
                dataset_digest=payload["datasetDigest"],
            )
            pair = execute_pair(
                repo_root=repository.root,
                freeze=freeze,
                criterion_id=REPRO_CRITERION,
                evaluator_input=payload,
            )
        self.assertEqual(pair.outcome, "PASS")
        self.assertEqual(
            pair["runA"]["commands"][0]["command"],
            FIXED_COMMANDS[REPRO_EVALUATOR],
        )
        self.assertEqual(pair["runA"]["commands"][0]["summary"]["failed"], 0)
        self.assertEqual(
            pair["runA"]["deterministicResultSetDigest"],
            pair["runB"]["deterministicResultSetDigest"],
        )

    def test_forged_isolated_evaluator_output_cannot_bypass_parent_recompute(
        self,
    ) -> None:
        with self.repository() as repository:
            payload = build_paired_input(
                REPRO_EVALUATOR,
                self._reproduction_records(),
                source_commit=repository.commit,
                control_plane_digest=digest("6"),
                evaluator_digest=digest("2"),
                dataset_id="p00-reproduction",
            )
            freeze = self._freeze(
                repository.commit,
                criterion_id=REPRO_CRITERION,
                evaluator=REPRO_EVALUATOR,
                dataset_digest=payload["datasetDigest"],
            )
            forged = deepcopy(evaluate_strict(REPRO_EVALUATOR, payload))
            forged["result"] = "FAIL"
            encoded = json.dumps(
                {
                    "schemaVersion": run_executor_module.INTERNAL_EVALUATOR_SCHEMA,
                    "evaluator": REPRO_EVALUATOR,
                    "evidence": forged,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            observation = run_executor_module._CapturedProcess(
                return_code=0,
                stdout=encoded,
                stderr=b"",
                elapsed_ns=1_000_000,
            )
            with mock.patch.object(
                run_executor_module,
                "_run_isolated_process",
                return_value=observation,
            ):
                with self.assertRaises(ProtectedExecutionError) as caught:
                    execute_pair(
                        repo_root=repository.root,
                        freeze=freeze,
                        criterion_id=REPRO_CRITERION,
                        evaluator_input=payload,
                    )
        self.assertEqual(caught.exception.code, "isolated_evaluator_evidence_mismatch")

    def test_unavailable_network_namespace_fails_closed(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            unavailable = ProtectedExecutionError(
                "network_isolation_unavailable",
                "executor.networkNamespace",
                "mocked unsupported namespace",
            )
            with mock.patch.object(
                run_executor_module,
                "_verify_network_isolation",
                side_effect=unavailable,
            ):
                with self.assertRaises(ProtectedExecutionError) as caught:
                    execute_pair(
                        repo_root=repository.root,
                        freeze=freeze,
                        criterion_id=CONTROL_CRITERION,
                    )
        self.assertEqual(caught.exception.code, "network_isolation_unavailable")

    def test_dirty_source_is_rejected_before_execution(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            (repository.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(ProtectedExecutionError) as caught:
                execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                )
        self.assertEqual(caught.exception.code, "dirty_source")

    def test_wrong_head_is_rejected_before_execution(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                "f" * 40,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            with self.assertRaises(ProtectedExecutionError) as caught:
                execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                )
        self.assertEqual(caught.exception.code, "wrong_source_commit")

    def test_fixed_command_timeout_terminates_and_rejects_run(self) -> None:
        with self.repository(test_sleep_seconds=2) as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=ANTI_CRITERION,
                evaluator=ANTI_EVALUATOR,
            )
            with self.assertRaises(ProtectedExecutionError) as caught:
                execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=ANTI_CRITERION,
                    limits=ExecutionLimits(timeout_seconds=0.05),
                )
        self.assertEqual(caught.exception.code, "run_timeout")

    def test_command_injection_cannot_select_an_executable(self) -> None:
        with self.repository() as repository:
            marker = repository.root.parent / "injected"
            injected_evaluator = f"{CONTROL_EVALUATOR};touch {marker}"
            freeze = self._freeze(
                repository.commit,
                criterion_id="P00-M-INJECTION",
                evaluator=injected_evaluator,
            )
            with self.assertRaises(ProtectedExecutionError) as caught:
                execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id="P00-M-INJECTION",
                )
            self.assertFalse(marker.exists())
        self.assertEqual(caught.exception.code, "unknown_evaluator")

    def test_a_b_checkout_root_reuse_and_aliases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="run-root-reuse-") as raw:
            root = Path(raw) / "checkout"
            root.mkdir()
            with self.assertRaises(ProtectedExecutionError) as caught:
                ensure_distinct_run_roots(root, root / ".")
        self.assertEqual(caught.exception.code, "run_root_reuse")

    def test_run_a_is_sealed_and_destroyed_before_run_b_is_created(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            original_clone = run_executor_module._clone_checkout
            observed: list[str] = []

            def observe_clone(**kwargs):
                target = kwargs["target_root"]
                if target.name == "run-b":
                    workspace = target.parents[1]
                    prior = (
                        workspace / "checkouts/run-a",
                        workspace / "homes/run-a",
                        workspace / "tmp/run-a",
                    )
                    self.assertTrue(all(not os.path.lexists(path) for path in prior))
                    observed.append("A-absent-before-B")
                return original_clone(**kwargs)

            with mock.patch.object(
                run_executor_module, "_clone_checkout", side_effect=observe_clone
            ):
                pair = execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                )
        self.assertEqual(observed, ["A-absent-before-B"])
        self.assertEqual(pair.outcome, "PASS")

    def test_output_ceiling_rejects_fixed_command(self) -> None:
        with self.repository() as repository:
            freeze = self._freeze(
                repository.commit,
                criterion_id=CONTROL_CRITERION,
                evaluator=CONTROL_EVALUATOR,
            )
            with self.assertRaises(ProtectedExecutionError) as caught:
                execute_pair(
                    repo_root=repository.root,
                    freeze=freeze,
                    criterion_id=CONTROL_CRITERION,
                    limits=ExecutionLimits(output_limit_bytes=8),
                )
        self.assertEqual(caught.exception.code, "output_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
