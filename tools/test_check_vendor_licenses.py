from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.check_vendor_licenses import check, modules


class VendorLicenseInventoryTests(unittest.TestCase):
    def test_requires_one_notice_per_module(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_root = root / "vendor" / "example.test" / "module"
            module_root.mkdir(parents=True)
            manifest = root / "vendor" / "modules.txt"
            manifest.write_text("# example.test/module v1.2.3\n## explicit; go 1.24\n", encoding="utf-8")
            self.assertEqual(check(root), ["example.test/module: no root LICENSE, COPYING, or NOTICE file"])
            (module_root / "LICENSE.txt").write_text("synthetic license\n", encoding="utf-8")
            self.assertEqual(check(root), [])

    def test_module_parser_ignores_replacement_metadata(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "modules.txt"
            path.write_text(
                "# one.test/a v1.0.0\n# two.test/b v2.0.0 => ./local\n# => ./local\n",
                encoding="utf-8",
            )
            self.assertEqual(modules(path), ["one.test/a", "two.test/b"])


if __name__ == "__main__":
    unittest.main()
