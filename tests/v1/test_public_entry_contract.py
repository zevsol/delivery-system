import re
import unittest
from pathlib import Path

from mcp_server.server import SERVER_VERSION


ROOT = Path(__file__).parents[2]


def relative_markdown_links(path: Path):
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        yield target.split("#", 1)[0]


class PublicEntryContractTests(unittest.TestCase):
    def test_public_entry_links_resolve(self):
        for document in (ROOT / "README.md", ROOT / "docs" / "getting-started.md"):
            for target in relative_markdown_links(document):
                self.assertTrue(target, f"empty relative link in {document}")
                resolved = (document.parent / target).resolve()
                self.assertTrue(resolved.is_relative_to(ROOT.resolve()), resolved)
                self.assertTrue(resolved.exists(), f"broken link {target!r} in {document}")

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for target in (
            "docs/getting-started.md",
            "docs/host-configuration.md",
            "docs/architecture-and-lifecycle.md",
            "docs/debt-register.md",
        ):
            self.assertIn(f"]({target})", readme)

    def test_getting_started_owns_source_first_run_contract(self):
        text = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
        required_tokens = (
            "Python 3.10",
            "pylock.toml",
            "python -m venv .venv",
            "python -B -m mcp_server.server --workspace-root <absolute-path>",
            "stdio",
            "mcp_server.server",
            "--workspace-root",
            "--host-profile",
            "plan-github-work-items",
            "skills/plan-github-work-items",
            ".delivery-system/state.sqlite3",
            "GitHub was not modified",
            "Preview-only is the safe first path",
            "not a formal installation",
        )
        for token in required_tokens:
            self.assertIn(token, text)

    def test_getting_started_orders_isolated_dependency_setup(self):
        text = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
        environment_position = text.index("python -m venv .venv")
        install_position = text.index("-m pip --isolated install")
        server_position = text.index("python -B -m mcp_server.server")
        self.assertLess(environment_position, install_position)
        self.assertLess(install_position, server_position)
        self.assertIn(".venv\\Scripts\\python.exe -m pip", text)
        self.assertIn(".venv/bin/python -m pip", text)

    def test_readme_exposes_user_facing_safety_boundary(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        required_tokens = (
            "plan does not write github",
            "audit does not write github",
            "human approval does not write github",
            "apply is the github-write boundary",
            "automatic retry is not authorized",
            "ambiguous execution outcomes stop safely",
            "source-usable prototype software",
        )
        for token in required_tokens:
            self.assertIn(token, text)

    def test_public_version_is_owned_by_project_metadata(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r"(?ms)^\[project\].*?^version\s*=\s*[\"']([^\"']+)[\"']", pyproject)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), SERVER_VERSION)


if __name__ == "__main__":
    unittest.main()
