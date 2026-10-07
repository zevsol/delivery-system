import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WorkflowHandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.getting_started = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
        cls.workflow = (ROOT / "docs" / "user-workflow.md").read_text(encoding="utf-8")
        cls.architecture = (ROOT / "docs" / "architecture-and-lifecycle.md").read_text(encoding="utf-8")

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

    def test_approval_and_authority_digest_handoffs_are_distinct(self):
        approval = self.workflow[
            self.workflow.index("## 3. Human Approval"):
            self.workflow.index("## 4. Apply")
        ]
        apply = self.workflow[
            self.workflow.index("## 4. Apply"):
            self.workflow.index("## Result and Recovery")
        ]
        self.assertIn("Human Approval handoff consists of `preview_id`, `revision`, and `approval_id`", apply)
        self.assertIn("it does not supply `approval_digest`", apply)
        self.assertIn("Runtime-returned ApplicationAuthority receipt supplies the Runtime-owned `approval_digest`", apply)
        self.assertIn("before Apply dispatch", apply)
        self.assertIn("model, Host, and user do not calculate or provide it", apply)
        self.assertIn("do not expect or request `approval_digest`", approval)
        self.assertIn("ApplicationAuthority is internal to the Skill, not a separate user-facing stage", apply)
        self.assertIn("Runtime ApplicationAuthority issuance independently resolves and validates the durable Approval", self.architecture)
        self.assertIn("canonical source for retaining the digest before Apply dispatch", self.architecture)

    def test_lost_apply_uses_retained_four_field_authority_context_without_retry(self):
        recovery = self.workflow[
            self.workflow.index("### Apply response lost before Application ID handoff"):
            self.workflow.index("## Terminology")
        ]
        self.assertIn("Do not call Apply again", recovery)
        self.assertIn("`preview_id`, `revision`, `approval_id`, and `approval_digest` retained from the Runtime-returned ApplicationAuthority receipt before Apply dispatch", recovery)
        self.assertIn("with those four fields and without an `application_id`", recovery)
        self.assertNotIn("from the approved handoff", recovery)

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
