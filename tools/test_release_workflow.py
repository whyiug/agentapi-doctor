"""Regression checks for release workflow expression expansion."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_expressions_and_shell_parameters_are_not_backslash_escaped(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            r"\${",
            workflow,
            "release variables would be treated as literals instead of expanded values",
        )

    def test_tag_release_and_oci_identities_remain_immutable(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("git/ref/tags/$TAG"), 2)
        self.assertEqual(workflow.count(".verification.verified"), 4)
        self.assertEqual(workflow.count('test "${tag_facts[5]}" = valid'), 2)
        self.assertIn("repos/$GITHUB_REPOSITORY/immutable-releases", workflow)
        self.assertIn("--jq '.enabled'", workflow)
        self.assertIn("(.immutable|tostring)", workflow)
        self.assertNotIn("git verify-tag", workflow)
        self.assertNotIn("imagetools create --tag", workflow)
        self.assertNotIn("--prerelease=false", workflow)
        self.assertIn("for platform in linux/amd64 linux/arm64", workflow)
        self.assertEqual(workflow.count('docker run --platform "$platform"'), 2)
        self.assertIn("release-dist/oci-images.json", workflow)
        self.assertIn("sha256sum oci-images.json >> checksums.txt", workflow)
        release_edits = [
            line.strip()
            for line in workflow.splitlines()
            if "gh release edit" in line
        ]
        self.assertEqual(release_edits, ['run: gh release edit "$TAG" --draft=false'])


if __name__ == "__main__":
    unittest.main()
