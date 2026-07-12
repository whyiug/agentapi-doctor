from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import check_release_notes


def valid_notes(tag: str) -> str:
    sections = [f"# AgentAPI Doctor {tag}", ""]
    for heading in check_release_notes.REQUIRED_HEADINGS:
        sections.extend((heading, "", "Reviewed release-specific statement.", ""))
    return "\n".join(sections)


class ReleaseNotesTests(unittest.TestCase):
    def test_exact_complete_notes_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v1.2.3-rc.4.md"
            path.write_text(valid_notes("v1.2.3-rc.4"), encoding="utf-8")
            check_release_notes.validate(path, "v1.2.3-rc.4")

    def test_wrong_tag_missing_content_and_placeholders_fail(self) -> None:
        mutations = {
            "wrong-tag": valid_notes("v1.2.4"),
            "empty": valid_notes("v1.2.3").replace("Reviewed release-specific statement.", "", 1),
            "placeholder": valid_notes("v1.2.3").replace(
                "Reviewed release-specific statement.", "TBD", 1
            ),
        }
        for name, content in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "notes.md"
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(check_release_notes.NotesError):
                    check_release_notes.validate(path, "v1.2.3")

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.md"
            target.write_text(valid_notes("v1.2.3"), encoding="utf-8")
            link = root / "link.md"
            link.symlink_to(target)
            with self.assertRaises(check_release_notes.NotesError):
                check_release_notes.validate(link, "v1.2.3")


if __name__ == "__main__":
    unittest.main()
