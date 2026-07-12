from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.check_docs import check, destinations


class DocumentationLinkCheckTests(unittest.TestCase):
    def test_accepts_existing_local_and_ignores_external_links(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
            (root / "README.md").write_text(
                "[guide](docs/guide.md#start) [web](https://example.invalid/x) [heading](#local)\n",
                encoding="utf-8",
            )
            self.assertEqual(check(root), [])

    def test_reports_missing_escape_and_backslash(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text(
                "[missing](docs/no.md) [escape](../outside.md) [bad](docs\\bad.md)\n",
                encoding="utf-8",
            )
            failures = check(root)
            self.assertEqual(len(failures), 3)
            self.assertTrue(any("missing local link target" in item for item in failures))
            self.assertTrue(any("escapes repository" in item for item in failures))

    def test_parses_inline_angle_and_reference_targets(self) -> None:
        content = "[one](one.md) [two](<two words.md>)\n[three]: three.md\n"
        self.assertEqual(destinations(content), ["one.md", "two words.md", "three.md"])


if __name__ == "__main__":
    unittest.main()
