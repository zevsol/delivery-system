from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
SKILL_PATH = ROOT / "skills" / "plan-github-work-items" / "SKILL.md"


class PlannerSkillContractTests(unittest.TestCase):
    def test_normative_decomposition_boundaries_are_present(self):
        skill = SKILL_PATH.read_text(encoding="utf-8")
        for phrase in (
            "one coherent outcome",
            "independently governable outcome boundaries",
            "Do not split merely for frontend/backend",
            "Stop before further decomposition",
            "Use siblings by default",
            "distinct integration/system outcome",
            "necessary for A to satisfy its Acceptance Criteria",
            "implementation order alone is insufficient",
            "bounded/verifiable outcome",
            "Technical outcomes are valid",
            "ask for clarification",
            "requested Issue count as user input",
            "remote Issues as duplicate/overlap evidence",
        ):
            self.assertIn(phrase, skill)


if __name__ == "__main__":
    unittest.main()
