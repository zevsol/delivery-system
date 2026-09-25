from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
SKILL_DIR = ROOT / "skills" / "plan-github-work-items"
SKILL_PATH = SKILL_DIR / "SKILL.md"


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


class PlannerSkillContractTests(unittest.TestCase):
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
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        if "ModuleNotFoundError: No module named 'yaml'" in result.stdout + result.stderr:
            self.fail("official Validator dependency contract violated: PyYAML is not installed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
