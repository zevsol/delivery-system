import asyncio
import re
import unittest
from pathlib import Path

from mcp import Client

from delivery_system import sqlite_schema
from mcp_server.server import SERVER_VERSION, mcp


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs" / "release-compatibility.md"

POLICY_IDS = (
    "REL-VERSION",
    "REL-BASELINE",
    "REL-CROSS-RELEASE",
    "MCP-CONTRACT",
    "SKILL-CONTRACT",
    "WORKFLOW-CONTRACT",
    "SQLITE-CURRENT",
    "SQLITE-OLDER",
    "SQLITE-NEWER",
    "SQLITE-DOWNGRADE",
    "SQLITE-ROLLBACK",
    "BACKUP-COMPAT",
    "WORKSPACE-IDENTITY",
    "CONFIG-CONTRACT",
    "PACKAGE-CONTRACT",
    "PYTHON-CONTRACT",
    "INSTALL-UPGRADE",
    "SUPPORT-WINDOW",
    "BREAKING-CHANGE",
    "GUARANTEE-EVIDENCE",
)


def _section(document: str, policy_id: str) -> str:
    match = re.search(
        rf"(?ms)^### {re.escape(policy_id)} — .*?(?=^### |^## |\Z)",
        document,
    )
    if match is None:
        raise AssertionError(f"missing policy section: {policy_id}")
    return match.group(0)


def _declared_code_list(section: str) -> list[str]:
    return re.findall(r"(?m)^- `([^`]+)`$", section)


_NEGATION = r"(?:\b(?:not|never|without|no)\b|\bdoes\s+not\b|\bdoesn't\b)"


def _has_bounded_negated_relationship(
    text: str,
    subject: str,
    object_: str,
    *,
    max_gap: int = 180,
) -> bool:
    compact = re.sub(r"\s+", " ", text)
    patterns = (
        rf"{subject}.{{0,{max_gap}}}{_NEGATION}.{{0,{max_gap}}}{object_}",
        rf"{_NEGATION}.{{0,{max_gap}}}{subject}.{{0,{max_gap}}}{object_}",
        rf"{object_}.{{0,{max_gap}}}{_NEGATION}.{{0,{max_gap}}}{subject}",
    )
    return any(re.search(pattern, compact, re.IGNORECASE) for pattern in patterns)


def _has_bounded_positive_relationship(
    text: str,
    subject: str,
    relation: str,
    object_: str,
    *,
    max_gap: int = 100,
) -> bool:
    compact = re.sub(r"\s+", " ", text)
    pattern = rf"{subject}.{{0,{max_gap}}}{relation}.{{0,{max_gap}}}{object_}"
    return any(
        not re.search(_NEGATION, match.group(0), re.IGNORECASE)
        for match in re.finditer(pattern, compact, re.IGNORECASE)
    )


class ReleaseCompatibilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = POLICY_PATH.read_text(encoding="utf-8")

    def test_policy_ids_are_complete_and_unique(self) -> None:
        actual = re.findall(r"(?m)^### ([A-Z][A-Z0-9-]+) — ", self.policy)
        self.assertEqual(actual, list(POLICY_IDS))
        self.assertEqual(len(actual), len(set(actual)))

    def test_release_identity_and_unreleased_boundary_are_explicit(self) -> None:
        section = _section(self.policy, "REL-VERSION")
        baseline = _section(self.policy, "REL-BASELINE")
        self.assertIn("pyproject.toml", section)
        self.assertIn("mcp_server.SERVER_VERSION", section)
        self.assertIn("0.1.0", section)
        self.assertIn("does not constitute a release", section)
        self.assertIn("metadata only", section)
        self.assertTrue(
            _has_bounded_negated_relationship(
                self.policy,
                r"`?0\.1\.0`?",
                r"\bformal(?:ly)?\s+release(?:d)?\b",
            ),
            "current 0.1.0 must be explicitly non-declared as a formal release",
        )
        self.assertTrue(
            _has_bounded_negated_relationship(
                section,
                r"Semantic Versioning",
                r"\bcompatibility\s+semantics\b",
            ),
            "Semantic Versioning compatibility semantics must be explicitly excluded",
        )
        self.assertTrue(
            _has_bounded_positive_relationship(
                baseline,
                r"\bfirst\s+formal\s+release\b",
                r"\bestablish(?:es)?\b",
                r"\bfirst\s+formal\s+compatibility\s+baseline\b",
            ),
            "the first formal release must establish the first formal compatibility baseline",
        )
        self.assertEqual(SERVER_VERSION, "0.1.0")

    def test_mcp_policy_inventory_matches_current_public_tool_surface(self) -> None:
        declared = _declared_code_list(_section(self.policy, "MCP-CONTRACT"))

        async def list_tools() -> list[str]:
            async with Client(mcp, raise_exceptions=True) as client:
                return [tool.name for tool in (await client.list_tools()).tools]

        actual = asyncio.run(list_tools())
        self.assertEqual(len(declared), 9)
        self.assertEqual(set(declared), set(actual))

    def test_skill_policy_inventory_matches_four_bundled_skills(self) -> None:
        declared = _declared_code_list(_section(self.policy, "SKILL-CONTRACT"))
        actual = sorted(
            path.name
            for path in (ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        )
        self.assertEqual(set(declared), set(actual))
        self.assertEqual(len(actual), 4)
        self.assertIn("one release-bound set", _section(self.policy, "SKILL-CONTRACT"))

    def test_workflow_policy_preserves_stage_and_safety_boundaries(self) -> None:
        section = _section(self.policy, "WORKFLOW-CONTRACT")
        for marker in (
            "Plan → Audit → Human Approval → Apply → Result / Recovery",
            "Plan does not write GitHub",
            "Audit does not write GitHub",
            "Human Approval does not write GitHub",
            "Apply is the GitHub-write boundary",
            "Automatic retry is not authorized",
            "Ambiguous outcomes stop safely",
        ):
            self.assertIn(marker, section)

    def test_sqlite_policy_distinguishes_v7_legacy_and_transaction_rollback(self) -> None:
        current = _section(self.policy, "SQLITE-CURRENT")
        older = _section(self.policy, "SQLITE-OLDER")
        newer = _section(self.policy, "SQLITE-NEWER")
        downgrade = _section(self.policy, "SQLITE-DOWNGRADE")
        rollback = _section(self.policy, "SQLITE-ROLLBACK")
        self.assertIn("V7 is the declared first-formal-release compatibility baseline", current)
        self.assertIn("V5 and V6 layers", current)
        self.assertIn("V3–V6 migration machinery", older)
        self.assertTrue(
            _has_bounded_negated_relationship(
                older,
                r"(?:V3[–-]V6|migration machinery|historical state)",
                r"\b(?:formal\s+)?release\s+guarantee\b",
            ),
            "V3–V6 implementation behavior must not become a formal release guarantee",
        )
        self.assertIn("must fail closed", newer)
        self.assertIn("Downgrade is not supported", downgrade)
        self.assertIn("Transaction rollback during a failed migration", rollback)
        self.assertIn("after a successfully committed migration is not supported", rollback)
        self.assertTrue(hasattr(sqlite_schema, "ensure_schema_v7"))
        self.assertTrue(hasattr(sqlite_schema, "_V7_DDL"))

    def test_explicit_non_guarantees_are_complete(self) -> None:
        for marker in (
            "prototype or pre-release states",
            "backward or forward compatibility",
            "SemVer compatibility semantics",
            "downgrade or reverse migration",
            "rollback after a committed migration",
            "cross-release backup or restore",
            "workspace relocation, rebinding, or portable restore",
            "universal upgrade support",
            "LTS, time-based, perpetual, or N-1 support window",
            "Install Tested, Host Tested, external Integration Tested, or Released status",
        ):
            self.assertIn(marker, self.policy)

    def test_configuration_python_and_install_boundaries_are_explicit(self) -> None:
        configuration = _section(self.policy, "CONFIG-CONTRACT")
        python = _section(self.policy, "PYTHON-CONTRACT")
        install = _section(self.policy, "INSTALL-UPGRADE")
        for marker in ("--workspace-root", "--host-profile", "github-app-write", "DELIVERY_SYSTEM_", ".delivery-system/state.sqlite3"):
            self.assertIn(marker, configuration)
        self.assertIn('requires-python = ">=3.10"', python)
        self.assertIn("not evidence that every Python version", python)
        self.assertIn("source-checkout to first-formal-release upgrade is not automatically supported", install)
        self.assertIn("no universal N-to-N+1 upgrade guarantee", install)

    def test_breaking_taxonomy_and_evidence_requirements_are_explicit(self) -> None:
        breaking = _section(self.policy, "BREAKING-CHANGE")
        evidence = _section(self.policy, "GUARANTEE-EVIDENCE")
        for label in (
            "BREAKING",
            "REVIEW REQUIRED",
            "INTERNAL/NONBREAKING",
            "DEPENDENT ON DECLARED GUARANTEE",
        ):
            self.assertIn(label, breaking)
        for marker in (
            "explicit product or architecture decision",
            "durable documentation",
            "deterministic contract tests",
            "CI evidence",
            "state fixtures",
            "lifecycle evidence",
            "Host evidence",
            "external integration evidence",
        ):
            self.assertIn(marker, evidence)

    def test_readme_and_architecture_point_to_canonical_policy(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        architecture = (ROOT / "docs" / "architecture-and-lifecycle.md").read_text(encoding="utf-8")
        self.assertIn("[Release compatibility](docs/release-compatibility.md)", readme)
        self.assertIn("[Release compatibility](release-compatibility.md)", architecture)
        self.assertIn("source-usable prototype software", readme)
        self.assertIn("not currently claimed as Install Tested", readme)
        self.assertIn("not formally Released", readme)


if __name__ == "__main__":
    unittest.main()
