"""CLI-level tests for protected raw-chain replay and append."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.phasegate.chain_artifact import parse_chain_artifact
from tools.phasegate.serialized_bundle import OP_CONVERGENCE
from tools.phasegate import main as phasegate_main
from tools.phasegate.workflow_orchestrator import replay_protected_chain

import test_workflow_orchestrator as _workflow_fixture


class ProtectedChainCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_type = _workflow_fixture.WorkflowOrchestratorTests
        fixture_type.setUpClass()
        cls.fixture = fixture_type(methodName="runTest")
        cls.root = fixture_type.root
        cls.repo = fixture_type.repo
        cls.request_commit = fixture_type.request_commit
        cls.genesis = fixture_type.genesis
        cls.raw_chain = fixture_type.raw_chain

    @classmethod
    def tearDownClass(cls) -> None:
        _workflow_fixture.WorkflowOrchestratorTests.tearDownClass()

    def _write(self, name: str, raw: bytes) -> Path:
        path = self.root / name
        path.write_bytes(raw)
        return path

    def _replay_arguments(self, *, output: Path, **overrides: str):
        values = {
            "chain": str(self._write("cli-chain.json", self.raw_chain)),
            "bootstrap_request_commit": self.request_commit,
            "expected_chain_head_digest": self.genesis["eventDigest"],
            "current_workflow_execution_commit": self.request_commit,
            "output": str(output),
        }
        values.update(overrides)
        return phasegate_main._parser().parse_args(
            [
                "protected-chain-replay",
                "--chain",
                values["chain"],
                "--bootstrap-request-commit",
                values["bootstrap_request_commit"],
                "--expected-chain-head-digest",
                values["expected_chain_head_digest"],
                "--current-workflow-execution-commit",
                values["current_workflow_execution_commit"],
                "--output",
                values["output"],
            ]
        )

    def _append_arguments(
        self,
        *,
        bundle: bytes,
        output: Path,
        expected_bundle_digest: str | None = None,
        **overrides: str,
    ):
        chain_path = self._write(
            f"{output.name}-chain.json", self.raw_chain
        )
        bundle_path = self._write(
            f"{output.name}-authorization-bundle.json", bundle
        )
        values = {
            "chain": str(chain_path),
            "bundle": str(bundle_path),
            "bootstrap_request_commit": self.request_commit,
            "expected_current_chain_head_digest": self.genesis["eventDigest"],
            "current_workflow_execution_commit": self.request_commit,
            "operation": OP_CONVERGENCE,
            "to_state": "MACHINE_CONVERGED",
            "work_unit": "P00.W01",
            "output": str(output),
        }
        values.update(overrides)
        arguments = [
            "protected-chain-append",
            "--chain",
            values["chain"],
            "--bootstrap-request-commit",
            values["bootstrap_request_commit"],
            "--expected-current-chain-head-digest",
            values["expected_current_chain_head_digest"],
            "--current-workflow-execution-commit",
            values["current_workflow_execution_commit"],
            "--operation",
            values["operation"],
            "--to-state",
            values["to_state"],
            "--work-unit",
            values["work_unit"],
            "--bundle",
            values["bundle"],
            "--output",
            values["output"],
        ]
        if expected_bundle_digest is not None:
            arguments.extend(
                ["--expected-bundle-digest", expected_bundle_digest]
            )
        return phasegate_main._parser().parse_args(arguments)

    def test_replay_requires_all_pins_and_atomically_writes_derived_outputs(
        self,
    ) -> None:
        output = self.root / "cli-replay-output"
        parsed = self._replay_arguments(output=output)
        code, result = phasegate_main.run(parsed, self.repo)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["reasonCode"], "protected_chain_replayed")
        self.assertEqual(result["headDigest"], self.genesis["eventDigest"])
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {"phase-state.yaml", "verification-result.json"},
        )
        view = json.loads((output / "phase-state.yaml").read_bytes())
        self.assertEqual(view["activeWorkUnit"], "P00.W01")
        before = {
            item.name: item.read_bytes()
            for item in output.iterdir()
        }
        code, result = phasegate_main.run(parsed, self.repo)
        self.assertEqual(code, 6)
        self.assertEqual(result["reasonCode"], "output_already_exists")
        self.assertEqual(
            before,
            {item.name: item.read_bytes() for item in output.iterdir()},
        )

        with self.assertRaises(SystemExit):
            phasegate_main._parser().parse_args(
                ["protected-chain-replay", "--chain", str(self.root / "x")]
            )

    def test_append_uses_injected_oidc_and_writes_exact_chain_event_view_summary(
        self,
    ) -> None:
        event_time = datetime(2026, 7, 11, 9, 10, tzinfo=timezone.utc)
        current = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        ).current
        bundle = self.fixture._convergence_or_attachment_bundle(
            current,
            event_time=event_time,
            seed=610,
            attachment=False,
        )
        bundle_digest = json.loads(bundle)["bundleDigest"]
        output = self.root / "cli-append-output"
        parsed = self._append_arguments(
            bundle=bundle,
            output=output,
            expected_bundle_digest=bundle_digest,
        )
        code, result = phasegate_main.run(
            parsed,
            self.repo,
            token_provider=lambda audience: self.fixture._token(
                audience,
                commit=self.request_commit,
                when=event_time,
                run_id=611,
            ),
            clock=lambda: event_time,
        )
        self.assertEqual(code, 0, result)
        self.assertEqual(result["reasonCode"], "protected_chain_appended")
        self.assertEqual(result["authorizationBundleDigest"], bundle_digest)
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {
                "chain.json",
                "event.json",
                "phase-state.yaml",
                "verification-result.json",
            },
        )
        updated = parse_chain_artifact((output / "chain.json").read_bytes())
        event = json.loads((output / "event.json").read_bytes())
        view = json.loads((output / "phase-state.yaml").read_bytes())
        summary = json.loads((output / "verification-result.json").read_bytes())
        self.assertEqual(updated.event_count, 2)
        self.assertEqual(event["eventDigest"], updated.head_digest)
        self.assertEqual(view["chain"]["headDigest"], updated.head_digest)
        self.assertEqual(
            view["phases"]["P00"]["workUnits"]["P00.W01"]["status"],
            "MACHINE_CONVERGED",
        )
        self.assertEqual(summary["resultingChainHeadDigest"], updated.head_digest)

    def test_append_rejects_commit_bundle_digest_and_canonical_mutants_before_oidc(
        self,
    ) -> None:
        event_time = datetime(2026, 7, 11, 9, 10, tzinfo=timezone.utc)
        current = replay_protected_chain(
            self.raw_chain,
            repo_root=self.repo,
            expected_bootstrap_request_commit=self.request_commit,
            expected_chain_head_digest=self.genesis["eventDigest"],
        ).current
        bundle = self.fixture._convergence_or_attachment_bundle(
            current,
            event_time=event_time,
            seed=620,
            attachment=False,
        )

        cases = (
            (
                self._append_arguments(
                    bundle=bundle,
                    output=self.root / "cli-bad-commit",
                    current_workflow_execution_commit="0" * 40,
                ),
                "workflow_execution_commit_mismatch",
            ),
            (
                self._append_arguments(
                    bundle=bundle,
                    output=self.root / "cli-bad-digest",
                    expected_bundle_digest="sha256:" + "0" * 64,
                ),
                "external_bundle_digest_mismatch",
            ),
            (
                self._append_arguments(
                    bundle=bundle + b"\n",
                    output=self.root / "cli-noncanonical",
                ),
                "noncanonical_bundle",
            ),
        )
        for parsed, expected in cases:
            with self.subTest(expected=expected):
                code, result = phasegate_main.run(
                    parsed,
                    self.repo,
                    token_provider=lambda _audience: self.fail(
                        "invalid pin reached OIDC provider"
                    ),
                    clock=lambda: event_time,
                )
                self.assertEqual(code, 6)
                self.assertEqual(result["reasonCode"], expected)

    def test_protected_input_fd_reader_rejects_symlink_and_in_place_replacement(
        self,
    ) -> None:
        target = self._write("fd-reader-target.json", b'{"ok":true}')
        link = self.root / "fd-reader-link.json"
        link.symlink_to(target)
        with self.assertRaises(phasegate_main.WorkflowOrchestratorError) as caught:
            phasegate_main._read_regular_file(
                str(link), label="chain", maximum=1024
            )
        self.assertEqual(caught.exception.code, "protected_input_unavailable")

        original_read = os.read
        changed = False

        def mutate_after_read(descriptor: int, count: int) -> bytes:
            nonlocal changed
            raw = original_read(descriptor, count)
            if raw and not changed:
                changed = True
                target.write_bytes(b'{"changed":true,"padding":1}')
            return raw

        with patch("tools.phasegate.main.os.read", side_effect=mutate_after_read):
            with self.assertRaises(
                phasegate_main.WorkflowOrchestratorError
            ) as caught:
                phasegate_main._read_regular_file(
                    str(target), label="chain", maximum=1024
                )
        self.assertEqual(caught.exception.code, "protected_input_changed")

    def test_phase_append_cli_uses_phase_scope_without_fake_work_unit(self) -> None:
        parsed = phasegate_main._parser().parse_args(
            [
                "protected-chain-append",
                "--chain",
                "chain.json",
                "--bootstrap-request-commit",
                self.request_commit,
                "--expected-current-chain-head-digest",
                self.genesis["eventDigest"],
                "--current-workflow-execution-commit",
                self.request_commit,
                "--operation",
                "phase-transition",
                "--to-state",
                "MACHINE_CONVERGED",
                "--phase",
                "P00",
                "--bundle",
                "authorization-bundle.json",
                "--output",
                "output",
            ]
        )
        self.assertEqual(parsed.operation, "phase-transition")
        self.assertEqual(parsed.phase, "P00")
        self.assertIsNone(parsed.work_unit)


if __name__ == "__main__":
    unittest.main()
