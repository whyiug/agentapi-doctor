"""Regression checks for the bounded Doctor-only release workflow."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowTests(unittest.TestCase):
    def workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

    def test_expressions_and_shell_parameters_are_not_backslash_escaped(self) -> None:
        self.assertNotIn(
            r"\${",
            self.workflow(),
            "release variables would be treated as literals instead of expanded values",
        )

    def test_manual_dispatch_is_dry_run_and_tag_commit_must_belong_to_main(self) -> None:
        workflow = self.workflow()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("if: github.event_name == 'push'", workflow)
        self.assertIn('git merge-base --is-ancestor "$GITHUB_SHA" origin/main', workflow)
        self.assertNotIn(".verification.verified", workflow)
        self.assertNotIn("git verify-tag", workflow)

    def test_first_release_contains_only_doctor_archives_and_trust_files(self) -> None:
        workflow = self.workflow()
        self.assertIn("Build six native Doctor archives", workflow)
        self.assertIn("agentapi-doctor.spdx.json", workflow)
        self.assertIn("checksums.txt.sigstore.json", workflow)
        self.assertIn("actions/attest-build-provenance", workflow)
        for excluded in (
            "docker/build-push-action",
            "docker/setup-qemu-action",
            "integrations/homebrew",
            "integrations/scoop",
            "agentapi-doctor-registry",
            "agentapi-doctor-reference-server",
            "oci-images.json",
            "make check",
        ):
            self.assertNotIn(excluded, workflow)

    def test_archive_and_public_smoke_cover_three_representative_platforms(self) -> None:
        workflow = self.workflow()
        for runner in ("ubuntu-24.04", "macos-15", "windows-2025"):
            self.assertGreaterEqual(workflow.count(runner), 2)
        self.assertIn("--started-at-epoch", workflow)
        self.assertIn("--max-seconds 120", workflow)
        self.assertIn("Anonymous public smoke", workflow)
        self.assertIn("releases/download/$TAG", workflow)
        self.assertEqual(workflow.count("cosign verify-blob"), 2)
        self.assertEqual(workflow.count("--certificate-identity"), 2)
        self.assertIn("raw.githubusercontent.com/$GITHUB_REPOSITORY/$TAG/install.sh", workflow)
        self.assertIn('AGENTAPI_DOCTOR_INSTALL_DIR="$install_root"', workflow)
        self.assertNotIn("Authorization:", workflow)

    def test_release_is_published_once_from_an_exact_allowlist(self) -> None:
        workflow = self.workflow()
        release_edits = [
            line.strip()
            for line in workflow.splitlines()
            if "gh release edit" in line
        ]
        self.assertEqual(release_edits, ['run: gh release edit "$TAG" --draft=false'])
        self.assertIn('test "${#assets[@]}" -eq 9', workflow)
        self.assertIn("(.immutable|tostring)", workflow)
        self.assertNotIn('"repos/$GITHUB_REPOSITORY/immutable-releases"', workflow)
        self.assertIn('test "${existing[1]}" = true', workflow)
        self.assertIn('test "${existing[2]}" = false', workflow)
        self.assertIn("gh api --method DELETE", workflow)

    def test_goreleaser_uses_windows_zip_and_no_service_archives(self) -> None:
        configuration = (ROOT / ".goreleaser.yaml").read_text(encoding="utf-8")
        self.assertIn("format_overrides:", configuration)
        self.assertIn("formats: [zip]", configuration)
        self.assertNotIn("id: registry", configuration)
        self.assertNotIn("id: reference-server", configuration)

    def test_release_repeats_the_hash_locked_real_sdk_gate(self) -> None:
        workflow = self.workflow()
        for required in (
            "python-version: '3.12.12'",
            "requirements-linux-x86_64-py312.lock",
            "--require-hashes",
            "--no-index",
            "TestRealPinnedSDK",
            "-count=2",
        ):
            self.assertIn(required, workflow)
        self.assertIn("Reproduce every pinned real-SDK case twice", workflow)


if __name__ == "__main__":
    unittest.main()
