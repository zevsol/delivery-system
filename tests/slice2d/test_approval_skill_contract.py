from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).parents[2]
SKILL_DIR = ROOT / "skills" / "approve-github-work-items"
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


class ApprovalSkillContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = SKILL_PATH.read_text(encoding="utf-8")
        cls.metadata = OPENAI_PATH.read_text(encoding="utf-8")

    def test_structure_and_official_validator(self):
        self.assertTrue(SKILL_PATH.is_file())
        self.assertTrue(OPENAI_PATH.is_file())
        self.assertEqual(sorted(path.name for path in SKILL_DIR.iterdir()), ["SKILL.md", "agents"])
        self.assertEqual(sorted(path.name for path in (SKILL_DIR / "agents").iterdir()), ["openai.yaml"])
        validator = find_validator()
        if validator is None:
            self.skipTest("official Validator unavailable: quick_validate.py was not discovered")
        result = subprocess.run([sys.executable, str(validator), str(SKILL_DIR)], cwd=ROOT,
                                capture_output=True, text=True, check=False,
                                env={**os.environ, "PYTHONUTF8": "1"})
        if "ModuleNotFoundError: No module named 'yaml'" in result.stdout + result.stderr:
            self.fail("official Validator dependency contract violated: PyYAML is not installed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_identity_and_trigger_boundaries(self):
        self.assertTrue(self.skill.startswith("---\nname: approve-github-work-items\n"))
        for phrase in ("Human Approval", "specific Delivery System Sealed Preview", "approve", "Preview ID", "Revision"):
            self.assertIn(phrase, self.skill)
        for phrase in ("planning", "auditing", "ordinary code review", "PR approval", "ApplicationAuthority", "Applier", "GitHub Issue"):
            self.assertIn(phrase, self.skill)

    def test_tool_boundary_and_metadata_dependencies(self):
        for phrase in ("delivery_get_audit_context", "delivery_record_approval", "delivery_issue_application_authority"):
            self.assertIn(phrase, self.skill)
        self.assertIn("Allowed MCP calls are exactly", self.skill)
        self.assertIn('value: "delivery_get_audit_context"', self.metadata)
        self.assertIn('value: "delivery_record_approval"', self.metadata)
        self.assertNotIn('value: "delivery_issue_application_authority"', self.metadata)
        self.assertNotIn('value: "delivery_record_audit"', self.metadata)
        self.assertNotIn('value: "delivery_plan_preview"', self.metadata)
        self.assertNotIn('value: "github"', self.metadata.split("dependencies:", 1)[1])

    def test_context_and_write_eligible_gate(self):
        body = self.skill.split("---", 2)[2]
        self.assertLess(body.index("delivery_get_audit_context"), body.index("delivery_record_approval"))
        self.assertIn('audit_scope` is not exactly `WriteEligible`', self.skill)
        for phrase in ("does not retrieve the current AuditRecord", "AuditResult=Passed", "approval_eligible=true", "Runtime remains final authority"):
            self.assertIn(phrase, self.skill)
        for field in ("sealed Preview digest", "plan digest", "operation-set digest", "remote-snapshot digest", "operation intents"):
            self.assertIn(field, self.skill)

    def test_exact_ceremony_order_and_no_synthesis(self):
        for phrase in ("批准写入 {preview_id} {revision}", "character-for-character", "human must type and send", "Do not trim", "yes/no", "displayed command is not approval", "must never construct `approval_command`"):
            self.assertIn(phrase, self.skill)
        claim = self.skill.index("Ask the human for a non-empty `approver_claim`")
        command = self.skill.index("Present the final required command")
        call = self.skill.index("immediately call `delivery_record_approval`")
        self.assertLess(claim, command)
        self.assertLess(command, call)
        self.assertIn("If the command is not exact, do not call `delivery_record_approval`", self.skill)

    def test_claim_provenance_and_pc4_boundary(self):
        for phrase in ("opaque, unverified provenance", "not authenticated identity", "Do not use a model-inferred identity", "Trusted Host provenance is deferred to PC4", "Do not rewrite, embellish, authenticate, or fabricate"):
            self.assertIn(phrase, self.skill)

    def test_toctou_conflict_replay_and_error_contract(self):
        for phrase in ("context_stale", "preview_stale", "audit_not_found", "audit_stale", "approval_audit_ambiguous", "approval_binding_mismatch", "approval_binding_conflict", "approval_stale", "do not automatically retry", "restart at `delivery_get_audit_context`", "never overwrite"):
            self.assertIn(phrase, self.skill)
        for phrase in ("Runtime approval replay is idempotent", "There is no read-Approval MCP tool", "current interaction"):
            self.assertIn(phrase, self.skill)

    def test_receipt_security_and_no_credentials(self):
        fields = ("approval_id", "audit_id", "audit_digest", "audit_result", "preview_id", "revision", "plan_digest", "remote_snapshot_digest", "operation_set_digest", "repository_identity", "approval_command", "approver_claim", "approved_at", "status")
        for field in fields:
            self.assertIn(field, self.skill)
        for phrase in ("Approval recorded", "Application authority was not issued", "No GitHub mutation was executed", "not ApplicationAuthority", "does not issue ApplicationAuthority", "without credentials or attestation bootstrap"):
            self.assertIn(phrase, self.skill)
        self.assertNotIn("token loading", self.skill.lower())
        self.assertNotIn("provider setup", self.skill.lower())

    def test_metadata_interface(self):
        self.assertIn('display_name: "Approve GitHub Work Items"', self.metadata)
        self.assertIn("$approve-github-work-items", self.metadata)
        self.assertIn('transport: "stdio"', self.metadata)
        self.assertEqual(self.metadata.count('type: "mcp"'), 2)


if __name__ == "__main__":
    unittest.main()
