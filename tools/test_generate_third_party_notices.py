from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.generate_third_party_notices import render


class ThirdPartyNoticeTests(unittest.TestCase):
    def test_render_is_deterministic_and_includes_module_files(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "vendor" / "example.com" / "module"
            module.mkdir(parents=True)
            (root / "vendor" / "modules.txt").write_text(
                "# example.com/module v1.2.3\n## explicit; go 1.22\n",
                encoding="utf-8",
            )
            (module / "LICENSE").write_text("license text\n", encoding="utf-8")
            (module / "NOTICE").write_text("notice text\n", encoding="utf-8")

            first = render(root)
            second = render(root)
            self.assertEqual(first, second)
            text = first.decode("utf-8")
            self.assertIn("MODULE: example.com/module", text)
            self.assertIn("--- LICENSE ---", text)
            self.assertIn("license text", text)
            self.assertIn("--- NOTICE ---", text)

    def test_render_rejects_missing_notice(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "vendor" / "example.com" / "module"
            module.mkdir(parents=True)
            (root / "vendor" / "modules.txt").write_text(
                "# example.com/module v1.2.3\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "no license or notice"):
                render(root)


if __name__ == "__main__":
    unittest.main()
