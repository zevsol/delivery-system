import importlib
from importlib import metadata as importlib_metadata
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from delivery_system import release_identity
from delivery_system import sqlite_maintenance
from mcp_server.server import SERVER_VERSION


ROOT = Path(__file__).resolve().parents[2]


class ReleaseIdentityContractTests(unittest.TestCase):
    def test_installed_metadata_and_source_metadata_match(self) -> None:
        self.assertEqual(release_identity.current_release_id(), "0.1.0")
        self.assertEqual(SERVER_VERSION, release_identity.current_release_id())

    def test_source_only_fallback_returns_canonical_version(self) -> None:
        with patch.object(
            release_identity.importlib_metadata,
            "version",
            side_effect=importlib_metadata.PackageNotFoundError("delivery-system"),
        ):
            self.assertEqual(release_identity.current_release_id(), "0.1.0")

    def test_matching_metadata_and_source_succeed(self) -> None:
        with patch.object(release_identity, "_distribution_version", return_value="0.1.0"):
            with patch.object(release_identity, "_source_project_version", return_value="0.1.0"):
                self.assertEqual(release_identity.current_release_id(), "0.1.0")

    def test_contradictory_metadata_and_source_fail_closed(self) -> None:
        with patch.object(release_identity, "_distribution_version", return_value="0.1.0"):
            with patch.object(release_identity, "_source_project_version", return_value="0.2.0"):
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity.current_release_id()

    def test_metadata_exception_other_than_package_not_found_does_not_fallback(self) -> None:
        with patch.object(
            release_identity,
            "_distribution_version",
            side_effect=release_identity.ReleaseIdentityError(),
        ):
            with patch.object(release_identity, "_source_project_version") as source_version:
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity.current_release_id()
                source_version.assert_not_called()

    def test_missing_metadata_and_source_fail_closed(self) -> None:
        with patch.object(
            release_identity.importlib_metadata,
            "version",
            side_effect=importlib_metadata.PackageNotFoundError("delivery-system"),
        ):
            with patch.object(
                release_identity,
                "_source_project_path",
                return_value=ROOT / "missing-pyproject.toml",
            ):
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity.current_release_id()

    def test_malformed_and_duplicate_source_versions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pyproject.toml"
            for text in (
                "[project]\nversion = \"\"\n",
                "[project]\nversion = not-a-string\n",
                '[project]\nversion = "0.1.0"\nversion = "0.2.0"\n',
            ):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity._source_project_version(path)

    def test_sqlite_maintenance_maps_identity_failure(self) -> None:
        with patch.object(
            sqlite_maintenance,
            "current_release_id",
            side_effect=release_identity.ReleaseIdentityError(),
        ):
            with self.assertRaisesRegex(
                sqlite_maintenance.SQLiteMaintenanceError,
                "^sqlite_maintenance_release_unavailable$",
            ):
                sqlite_maintenance._current_release_id()

    def test_sqlite_maintenance_preserves_exact_release_identity(self) -> None:
        self.assertEqual(sqlite_maintenance._current_release_id(), "0.1.0")

    def test_server_import_and_reload_fail_closed_on_contradiction(self) -> None:
        code = """
import importlib
from delivery_system import release_identity

release_identity.current_release_id = lambda: "0.1.0"
import mcp_server.server as server
assert server.SERVER_VERSION == "0.1.0"

def fail():
    raise release_identity.ReleaseIdentityError()

release_identity.current_release_id = fail
try:
    importlib.reload(server)
except release_identity.ReleaseIdentityError:
    pass
else:
    raise AssertionError("server reload accepted a release identity failure")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
