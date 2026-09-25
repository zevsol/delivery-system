import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WorkflowHandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.getting_started = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
        cls.workflow = (ROOT / "docs" / "user-workflow.md").read_text(encoding="utf-8")

    def test_public_workflow_owner_and_entry_links(self):
        self.assertTrue((ROOT / "docs" / "user-workflow.md").is_file())
        self.assertIn("[User Workflow](docs/user-workflow.md)", self.readme)
        self.assertIn("[User Workflow](user-workflow.md)", self.getting_started)

    def test_public_stage_order_is_exact(self):
        stage_sequence = []
        in_overview = False
        for line in self.workflow.splitlines():
            if line == "## Workflow at a glance":
                in_overview = True
                continue
            if in_overview and line.startswith("## "):
                break
            if in_overview and line.startswith("|"):
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if cells and cells[0] not in {"Stage", "---"} and not all(cell == "---" for cell in cells):
                    stage_sequence.append(cells[0])
        self.assertEqual(
            stage_sequence,
            ["Plan", "Audit", "Human Approval", "Apply", "Result / Recovery"],
        )
        stages = (
            "## 1. Plan",
            "## 2. Audit",
            "## 3. Human Approval",
            "## 4. Apply",
            "## Result and Recovery",
        )
        positions = [self.workflow.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Plan → Audit → Human Approval → Apply → Result / Recovery", self.readme)

    def test_public_skill_chain_is_complete_and_ordered(self):
        skills = (
            "plan-github-work-items",
            "audit-github-work-items",
            "approve-github-work-items",
            "apply-github-work-items",
        )
        positions = [self.workflow.index(skill) for skill in skills]
        self.assertEqual(positions, sorted(positions))

    def test_plan_handoff_preserves_exact_preview_identity(self):
        for phrase in (
            "`preview_id`",
            "positive `revision`",
            "Preview is not an Audit",
            "not Human Approval",
            "planning is blocked, incomplete, stale, or requires clarification",
            "Do not invent, infer, substitute",
        ):
            self.assertIn(phrase, self.workflow)

    def test_audit_handoff_is_eligibility_gated(self):
        for phrase in (
            "`audit_id`",
            "`audit_scope`",
            "`approval_eligible`",
            "`Passed` result alone",
            "Conceptual Audit may pass",
            "`WriteEligible`",
            "caller-supplied `audit_id`",
        ):
            self.assertIn(phrase, self.workflow)

    def test_approval_handoff_is_explicit_and_non_automatic(self):
        for phrase in (
            "`approval_id`",
            "no GitHub mutation occurred",
            "ApplicationAuthority was not issued",
            "Apply is a separate user job",
            "Do not invoke Apply automatically",
            "批准写入 {preview_id} {revision}",
        ):
            self.assertIn(phrase, self.workflow)

    def test_effect_boundaries_and_apply_scope_are_explicit(self):
        for phrase in (
            "Plan does not write GitHub",
            "Audit does not write GitHub",
            "It does not write GitHub and does not issue executable ApplicationAuthority",
            "Apply is the GitHub-write boundary",
            "exact operation set",
            "must not construct, copy, or manipulate ApplicationAuthority identifiers",
        ):
            self.assertIn(phrase, self.workflow)

    def test_result_recovery_and_no_retry_contract_is_explicit(self):
        for phrase in (
            "`Applied`",
            "`Failed`",
            "`Blocked`",
            "`OutcomeUnknown`",
            "`NO_AUTOMATIC_RETRY`",
            "does not retry, resume, reconcile",
            "does not establish historical causal attribution",
            "does not authorize retry or resume",
        ):
            self.assertIn(phrase, self.workflow)

    def test_evidence_boundary_excludes_unverified_claims(self):
        for phrase in (
            "Host Tested",
            "Install Tested",
            "external Integration Tested",
            "formal Released status",
            "a new Runtime capability",
        ):
            self.assertIn(phrase, self.workflow)


if __name__ == "__main__":
    unittest.main()
