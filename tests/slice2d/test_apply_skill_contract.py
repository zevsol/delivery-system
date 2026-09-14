from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).parents[2]
SKILL_DIR = ROOT / "skills" / "apply-github-work-items"
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


class ApplySkillContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = SKILL_PATH.read_text(encoding="utf-8")
        cls.metadata = OPENAI_PATH.read_text(encoding="utf-8")

    @staticmethod
    def section(document, heading):
        marker = f"## {heading}\n"
        start = document.index(marker) + len(marker)
        end = document.find("\n## ", start)
        return document[start:] if end == -1 else document[start:end]

    def test_structure_and_official_validator(self):
        self.assertTrue(SKILL_PATH.is_file())
        self.assertTrue(OPENAI_PATH.is_file())
        self.assertEqual(sorted(path.name for path in SKILL_DIR.iterdir()), ["SKILL.md", "agents"])
        self.assertEqual(sorted(path.name for path in (SKILL_DIR / "agents").iterdir()), ["openai.yaml"])
        validator = find_validator()
        if validator is None:
            self.skipTest("official Validator unavailable: quick_validate.py was not discovered")
        result = subprocess.run(
            [sys.executable, str(validator), str(SKILL_DIR)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        if "ModuleNotFoundError: No module named 'yaml'" in result.stdout + result.stderr:
            self.fail("official Validator dependency contract violated: PyYAML is not installed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_identity_and_user_job_boundaries(self):
        frontmatter, body = self.skill.split("---", 2)[1:]
        self.assertIn("name: apply-github-work-items", frontmatter)
        self.assertIn("Apply one exact Delivery System Sealed Preview", body)
        preconditions = self.section(self.skill, "Preconditions and handoff")
        self.assertIn("exact `preview_id` and positive integer `revision`", preconditions)
        self.assertIn("exact successful Human Approval context", preconditions)
        self.assertNotIn("Require the exact `application_authority_id`", preconditions)
        self.assertNotIn("Ask the user to construct", preconditions)

    def test_internal_orchestration_order_and_hidden_authority(self):
        workflow = self.section(self.skill, "Workflow")
        context = workflow.index("delivery_get_audit_context")
        issue = workflow.index("delivery_issue_application_authority")
        apply = workflow.index("delivery_apply_approved_work_items")
        self.assertLess(context, issue)
        self.assertLess(issue, apply)
        self.assertIn("Call `delivery_issue_application_authority` internally", workflow)
        self.assertIn("Pass only the Runtime-returned authority", workflow)
        self.assertIn("Do not ask the user to construct, copy, or manipulate an `ApplicationAuthority` ID", self.skill)
        self.assertIn("not a separate user objective", workflow)
        self.assertNotIn("delivery_record_approval", self.metadata)
        self.assertNotIn("delivery_record_audit", self.metadata)
        self.assertNotIn("delivery_plan_preview", self.metadata)

    def test_responsibility_boundary(self):
        boundary = self.section(self.skill, "Responsibility boundary")
        required_exclusions = (
            "planning",
            "audit creation",
            "Human Approval creation or modification",
            "credential discovery",
            "arbitrary GitHub writes",
            "arbitrary Driver invocation or use",
            "schema or database administration or migration",
            "revocation checks or authoritative revocation decisions",
            "any other post-V1 revocation lifecycle",
            "does not bypass the bounded Applier",
        )
        for exclusion in required_exclusions:
            self.assertIn(exclusion, boundary)
        for prohibited_instruction in (
            "Ask the user to construct an `ApplicationAuthority` ID",
            "Ask the user to copy an `ApplicationAuthority` ID",
            "Ask the user to manipulate an `ApplicationAuthority` ID",
            "Ask the user to derive an `ApplicationAuthority` ID",
        ):
            self.assertNotIn(prohibited_instruction, self.skill)

    def test_side_effect_and_result_contract(self):
        body = self.section(self.skill, "Result and recovery")
        self.assertIn("durable `Applied` result supported by the returned application receipt", body)
        self.assertIn("Report `Failed` or `Blocked` as a definitive failure", body)
        self.assertIn("Application is not read-only", self.skill)
        self.assertIn("may perform irreversible GitHub Issue mutations", self.skill)

    def test_ambiguity_is_terminal_and_no_retry(self):
        recovery = self.section(self.skill, "Result and recovery")
        for phrase in (
            "Treat `OutcomeUnknown`",
            "an ambiguous execution result",
            "a recovery-required result",
            "terminal for this Skill",
            "Stop immediately",
            "remote effect may already have occurred",
            "durable evidence has been retained",
            "operator or Host escalation is required",
            "Never automatically retry an ambiguous operation",
            "Do not perform built-in remote reconciliation or remote reobservation",
        ):
            self.assertIn(phrase, recovery)

    def test_status_inspection_is_read_only_and_non_reconciling(self):
        status = self.section(self.skill, "Status inspection")
        for phrase in (
            "existing application",
            "delivery_get_application_status",
            "Runtime-owned safe projection",
            "Never retry, resume, reobserve GitHub, reconcile",
            "mutate remote state",
        ):
            self.assertIn(phrase, status)
        self.assertIn("Do not perform built-in remote reconciliation or remote reobservation", self.skill)

    def test_outcome_unknown_relationship_observation_guidance_is_additive(self):
        guidance = self.section(self.skill, "OutcomeUnknown relationship observation")
        for phrase in (
            "Only an `OutcomeUnknown` `add_sub_issue` or `add_dependency` operation is eligible",
            "delivery_observe_application_postcondition",
            "`postcondition_confirmed` means the desired relationship currently exists",
            "`postcondition_absent` means the desired relationship does not currently exist",
            "`inconclusive` means the current relationship state cannot be safely classified",
            "historical causal attribution as `not_established`",
            "No observation result authorizes automatic retry or resume",
            "Do not invoke Apply again automatically",
            "do not mutate GitHub",
            "durable recovery state as `OutcomeUnknown`",
        ):
            self.assertIn(phrase, guidance)

    def test_metadata_has_exact_internal_mcp_surface(self):
        entries = re.findall(
            r'- type: "([^"]+)"\n\s+value: "([^"]+)"\n\s+description: "([^"]+)"\n\s+transport: "([^"]+)"',
            self.metadata,
        )
        self.assertEqual(
            [(kind, value, transport) for kind, value, _description, transport in entries],
            [
                ("mcp", "delivery_get_audit_context", "stdio"),
                ("mcp", "delivery_issue_application_authority", "stdio"),
                ("mcp", "delivery_apply_approved_work_items", "stdio"),
            ],
        )

    def test_approval_remains_separate_and_recovery_is_not_application(self):
        preconditions = self.section(self.skill, "Preconditions and handoff")
        recovery = self.section(self.skill, "Result and recovery")
        self.assertIn("Human Approval remains distinct from ApplicationAuthority and application", preconditions)
        self.assertIn("distinguish Approval from Application", self.skill)
        self.assertIn("definitive success or failure from recovery-required", self.skill)
        self.assertNotIn("OutcomeUnknown result is Applied", recovery)

    def test_existing_skill_boundaries_remain_distinct(self):
        plan = (ROOT / "skills" / "plan-github-work-items" / "SKILL.md").read_text(encoding="utf-8")
        audit = (ROOT / "skills" / "audit-github-work-items" / "SKILL.md").read_text(encoding="utf-8")
        approval = (ROOT / "skills" / "approve-github-work-items" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("delivery_plan_preview", plan)
        self.assertIn("delivery_record_audit", audit)
        self.assertIn("delivery_record_approval", approval)
        self.assertIn("does not issue ApplicationAuthority", approval)
        self.assertIn("does not execute the Applier", approval)

    def test_metadata_interface_and_dependencies(self):
        self.assertIn('display_name: "Apply GitHub Work Items"', self.metadata)
        self.assertIn('$apply-github-work-items', self.metadata)
        self.assertIn('transport: "stdio"', self.metadata)
        for tool in ("delivery_get_audit_context", "delivery_issue_application_authority", "delivery_apply_approved_work_items"):
            self.assertIn(f'value: "{tool}"', self.metadata)
        self.assertEqual(self.metadata.count('type: "mcp"'), 3)


if __name__ == "__main__":
    unittest.main()
