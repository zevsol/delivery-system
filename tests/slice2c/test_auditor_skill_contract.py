from __future__ import annotations

import subprocess
import sys
import unittest
import os
from pathlib import Path
import shutil


ROOT = Path(__file__).parents[2]
SKILL_DIR = ROOT / "skills" / "audit-github-work-items"
SKILL_PATH = SKILL_DIR / "SKILL.md"
OPENAI_PATH = SKILL_DIR / "agents" / "openai.yaml"


def find_validator() -> Path | None:
    configured = os.environ.get("SKILL_CREATOR_VALIDATOR")
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        candidates.append(Path(codex_home) / "skills" / ".system" / "skill-creator" / "scripts" / "quick_validate.py")
    candidates.append(Path.home() / ".codex" / "skills" / ".system" / "skill-creator" / "scripts" / "quick_validate.py")
    on_path = shutil.which("quick_validate.py")
    if on_path:
        candidates.append(Path(on_path))
    return next((path for path in candidates if path.is_file()), None)


class AuditorSkillContractTests(unittest.TestCase):
    def read_skill(self) -> str:
        self.assertTrue(SKILL_PATH.is_file())
        return SKILL_PATH.read_text(encoding="utf-8")

    def test_skill_structure_passes_official_validator(self):
        validator = find_validator()
        if validator is None:
            self.skipTest("official Validator unavailable: quick_validate.py was not discovered")
        result = subprocess.run(
            [sys.executable, str(validator), str(SKILL_DIR)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if "ModuleNotFoundError: No module named 'yaml'" in result.stdout + result.stderr:
            self.skipTest("official Validator unavailable: PyYAML is not installed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(OPENAI_PATH.is_file())

    def test_frontmatter_and_trigger_boundary(self):
        skill = self.read_skill()
        frontmatter = skill.split("---", 2)[1]
        self.assertTrue(skill.startswith("---\nname: audit-github-work-items\n"))
        self.assertIn("description:", frontmatter)
        self.assertIn("without a Preview ID or Revision", frontmatter)
        for phrase in (
            "audit",
            "Preview ID",
            "Revision",
            "Passed",
            "NeedsInformation",
            "ChangesRequired",
            "Blocked",
        ):
            self.assertIn(phrase, skill)
        for phrase in (
            "planning new Idea",
            "create or modify Preview",
            "ordinary code review",
            "approve Preview",
            "create or modify GitHub Issue",
            "Applier",
        ):
            self.assertIn(phrase, skill)

    def test_workflow_uses_only_auditor_tools_and_sealed_context(self):
        skill = self.read_skill()
        for tool in ("delivery_get_audit_context", "delivery_record_audit"):
            self.assertIn(tool, skill)
        self.assertNotIn("Call `delivery_plan_preview`", skill)
        for phrase in (
            "Sealed Preview",
            "item_id",
            "Evidence ID",
            "audit_context_digest",
            "semantic_evaluations",
            "finding_drafts",
            "Planner Observation",
            "Duplicate Candidate",
        ):
            self.assertIn(phrase, skill)

    def test_runtime_owns_identity_result_and_approval_fields(self):
        skill = self.read_skill()
        for phrase in (
            "Audit ID",
            "Finding ID",
            "AuditResult",
            "AuditStatus",
            "Digest",
            "Approval eligibility",
            "Runtime Gate",
        ):
            self.assertIn(phrase, skill)
        self.assertIn("Passed Evaluation", skill)
        self.assertIn("NotApplicable", skill)
        self.assertIn("Conceptual Audit", skill)

    def test_skill_declares_no_external_write_or_new_tool(self):
        skill = self.read_skill()
        for phrase in (
            "does not write to GitHub",
            "does not create or modify a Preview",
            "does not approve",
            "does not implement the Applier",
            "does not add an MCP Tool",
        ):
            self.assertIn(phrase, skill)

    def test_stop_conditions_and_result_feedback_are_explicit(self):
        skill = self.read_skill()
        for phrase in (
            "Context Stale",
            "Runtime Gate",
            "no AuditRecord was created",
            "NeedsInformation",
            "ChangesRequired",
            "Blocked",
            "Missing Information",
            "Recommended Next Action",
            "Conceptual Audit",
        ):
            self.assertIn(phrase, skill)

    def test_evidence_and_item_boundaries_are_explicit(self):
        skill = self.read_skill()
        self.assertIn("only real immutable `item_id` values", skill)
        self.assertIn("only real evidence IDs", skill)
        self.assertIn("Planner Observations or Duplicate Candidates", skill)
        self.assertIn("Passed Evaluation has no Finding", skill)
        self.assertIn("Failed`, `Unknown`, or `Blocked`", skill)

    def test_openai_metadata_matches_skill(self):
        metadata = OPENAI_PATH.read_text(encoding="utf-8")
        interface_start = metadata.index("interface:")
        dependencies_start = metadata.index("dependencies:")
        interface_block = metadata[interface_start:dependencies_start]
        self.assertRegex(interface_block, r'(?m)^  default_prompt:\s*"')
        self.assertNotRegex(metadata, r'(?m)^default_prompt:\s*')
        self.assertIn("audit-github-work-items", metadata)
        self.assertIn("delivery_get_audit_context", metadata)
        self.assertIn("delivery_record_audit", metadata)
        self.assertIn("$audit-github-work-items", metadata)
        self.assertIn("delivery_get_audit_context", metadata)
        self.assertIn("delivery_record_audit", metadata)

    def test_no_speculative_skill_resources(self):
        self.assertEqual(
            sorted(path.name for path in SKILL_DIR.iterdir()),
            ["SKILL.md", "agents"],
        )
        self.assertEqual(sorted(path.name for path in (SKILL_DIR / "agents").iterdir()), ["openai.yaml"])


if __name__ == "__main__":
    unittest.main()
