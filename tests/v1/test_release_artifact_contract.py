import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from tools import build_release_artifacts as builder


ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0"


class ReleaseArtifactContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.runtime = self.root / "runtime"
        self.repo.mkdir()
        self.runtime.mkdir()
        shutil.copytree(ROOT / "skills", self.repo / "skills")
        (self.runtime / "delivery_system-0.1.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
        (self.runtime / "delivery_system-0.1.0.tar.gz").write_bytes(b"sdist-bytes")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self, name: str = "out") -> dict[str, Path]:
        with patch.object(builder, "current_release_id", return_value=VERSION):
            return builder.build_release_artifacts(self.repo, self.runtime, self.root / name)

    def test_two_identical_builds_are_byte_identical(self) -> None:
        first = self._build("first")
        second = self._build("second")
        self.assertEqual(first["plugin"].read_bytes(), second["plugin"].read_bytes())
        self.assertEqual(first["manifest"].read_bytes(), second["manifest"].read_bytes())
        self.assertEqual(
            hashlib.sha256(first["plugin"].read_bytes()).hexdigest(),
            hashlib.sha256(second["plugin"].read_bytes()).hexdigest(),
        )

    def test_plugin_shape_content_and_manifest_are_exact(self) -> None:
        artifacts = self._build()
        with ZipFile(artifacts["plugin"]) as archive:
            names = archive.namelist()
            root_name = "delivery-system-plugin-0.1.0/"
            self.assertTrue(names)
            self.assertTrue(all(name.startswith(root_name) for name in names))
            self.assertEqual(names, sorted(names))
            self.assertNotIn(root_name + "mcp.json", names)
            self.assertNotIn(root_name + ".mcp.json", names)
            self.assertNotIn(root_name + ".app.json", names)
            self.assertNotIn(root_name + ".codex-plugin/plugin.json", names)
            manifest = json.loads(archive.read(root_name + "plugin.json"))
            self.assertEqual(manifest["$schema"], builder.PLUGIN_SCHEMA)
            self.assertEqual(manifest["name"], "delivery-system")
            self.assertEqual(manifest["version"], VERSION)
            self.assertEqual(manifest["description"], builder.PLUGIN_DESCRIPTION)
            expected = {root_name + "plugin.json"}
            for skill in builder.CANONICAL_SKILLS:
                for path in (self.repo / "skills" / skill).rglob("*"):
                    if path.is_file():
                        expected.add(root_name + "skills/" + skill + "/" + path.relative_to(self.repo / "skills" / skill).as_posix())
            self.assertEqual(set(names), expected)
            for name in names:
                self.assertNotIn("..", Path(name).parts)
                self.assertFalse(Path(name).is_absolute())
                self.assertEqual(archive.getinfo(name).date_time, (1980, 1, 1, 0, 0, 0))

    def test_skill_bytes_and_metadata_are_preserved(self) -> None:
        artifacts = self._build()
        with ZipFile(artifacts["plugin"]) as archive:
            root_name = "delivery-system-plugin-0.1.0/"
            for skill in builder.CANONICAL_SKILLS:
                for relative in ("SKILL.md", "agents/openai.yaml"):
                    source = (self.repo / "skills" / skill / relative).read_bytes()
                    self.assertEqual(archive.read(root_name + "skills/" + skill + "/" + relative), source)

    def test_release_manifest_has_exact_artifacts_and_correct_hashes(self) -> None:
        artifacts = self._build()
        manifest = json.loads(artifacts["manifest"].read_text(encoding="utf-8"))
        self.assertEqual(manifest["format"], builder.RELEASE_FORMAT)
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual([item["kind"] for item in manifest["artifacts"]], ["wheel", "sdist", "plugin"])
        for item in manifest["artifacts"]:
            path = artifacts[item["kind"]]
            self.assertEqual(item["filename"], path.name)
            self.assertEqual(item["size"], path.stat().st_size)
            self.assertEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_builder_rejects_extra_skill_and_symlink_skill(self) -> None:
        extra = self.repo / "skills" / "extra-skill"
        extra.mkdir()
        (extra / "SKILL.md").write_text("---\nname: extra\n---\n", encoding="utf-8")
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "skill_set_invalid"):
                builder.build_release_artifacts(self.repo, self.runtime, self.root / "extra")

        shutil.rmtree(extra)
        symlink_target = self.repo / "skills" / "plan-github-work-items" / "SKILL.md"
        symlink_path = self.repo / "skills" / "plan-github-work-items" / "linked.md"
        try:
            symlink_path.symlink_to(symlink_target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "skill_symlink"):
                builder.build_release_artifacts(self.repo, self.runtime, self.root / "symlink")

    def test_builder_rejects_runtime_input_errors(self) -> None:
        missing = self.root / "missing-runtime"
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "runtime_directory_invalid"):
                builder.build_release_artifacts(self.repo, missing, self.root / "missing")

        wrong = self.root / "wrong-runtime"
        wrong.mkdir()
        (wrong / "delivery_system-0.2.0-py3-none-any.whl").write_bytes(b"wheel")
        (wrong / "delivery_system-0.2.0.tar.gz").write_bytes(b"sdist")
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "wheel_invalid"):
                builder.build_release_artifacts(self.repo, wrong, self.root / "wrong")

    def test_builder_rejects_output_inside_repository_and_overwrite(self) -> None:
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "output_inside_repository"):
                builder.build_release_artifacts(self.repo, self.runtime, self.repo / "out")
        self._build("output")
        with patch.object(builder, "current_release_id", return_value=VERSION):
            with self.assertRaisesRegex(builder.ReleaseArtifactError, "output_exists"):
                builder.build_release_artifacts(self.repo, self.runtime, self.root / "output")


if __name__ == "__main__":
    unittest.main()
