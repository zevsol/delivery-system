"""Validate Delivery System V0 repository structure without third-party packages."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def require(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"Missing required file: {path.relative_to(ROOT)}")


def load_json(path: Path) -> dict:
    require(path)
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    required = [
        "core/CORE-CONTRACT.md",
        "core/workflows/idea-to-delivery.md",
        "core/workflows/audit-delivery.md",
        "core/workflows/execute-delivery.md",
        "core/policies/role-boundaries.md",
        "core/policies/issue-granularity.md",
        "core/policies/change-management.md",
        "core/policies/quality-gates.md",
        "core/policies/traceability.md",
        "tests/conformance/core-behavior.md",
        "adapters/delivery-system-openai/ADAPTER-CONTRACT.md",
        "adapters/delivery-system-openai/SYNC-MANIFEST.json",
    ]
    for relative_path in required:
        require(ROOT / relative_path)

    schema_dir = ROOT / "core" / "schemas"
    for filename in (
        "artifact.schema.json",
        "issue.schema.json",
        "finding.schema.json",
        "change-request.schema.json",
    ):
        schema = load_json(schema_dir / filename)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"Unexpected schema draft: {filename}")
        if not str(schema.get("$id", "")).startswith("urn:delivery-system:schema:"):
            raise ValueError(f"Schema ID must be a Delivery System URN: {filename}")

    adapter_root = ROOT / "adapters" / "delivery-system-openai"
    manifest = load_json(adapter_root / ".codex-plugin" / "plugin.json")
    if manifest.get("name") != "delivery-system-openai":
        raise ValueError("OpenAI Adapter manifest name is invalid")
    if manifest.get("skills") != "./skills/":
        raise ValueError("OpenAI Adapter must declare the bundled skills directory")

    for skill_name in ("idea-to-delivery", "audit-delivery", "execute-delivery"):
        skill_path = adapter_root / "skills" / skill_name / "SKILL.md"
        require(skill_path)
        contents = skill_path.read_text(encoding="utf-8")
        if not contents.startswith("---\nname:") or "\ndescription:" not in contents:
            raise ValueError(f"Invalid Skill frontmatter: {skill_name}")
        projection = skill_path.parent / "references" / "core-projection.md"
        require(projection)
        projection_contents = projection.read_text(encoding="utf-8")
        if "受控同步投影" not in projection_contents or "0.1.0-draft" not in projection_contents:
            raise ValueError(f"Missing projection provenance: {skill_name}")

    sync_manifest = load_json(adapter_root / "SYNC-MANIFEST.json")
    if sync_manifest.get("mode") != "controlled-synchronized-projections":
        raise ValueError("Unexpected Core projection synchronization mode")
    for skill_name, clauses in sync_manifest.get("requiredClauses", {}).items():
        projection = adapter_root / "skills" / skill_name / "references" / "core-projection.md"
        projection_contents = projection.read_text(encoding="utf-8")
        for clause in clauses:
            if clause not in projection_contents:
                raise ValueError(f"Projection missing required clause: {skill_name}: {clause}")

    conformance = (ROOT / "tests" / "conformance" / "core-behavior.md").read_text(encoding="utf-8")
    for case in range(1, 8):
        case_id = f"CB-{case:03d}"
        if case_id not in conformance:
            raise ValueError(f"Missing conformance scenario: {case_id}")

    distribution_root = ROOT / "plugins" / "delivery-system-openai"
    distribution = load_json(distribution_root / "DISTRIBUTION-MANIFEST.json")
    if distribution.get("source") != "adapters/delivery-system-openai":
        raise ValueError("Unexpected distribution source")
    for relative_path, expected_hash in distribution.get("files", {}).items():
        source_file = adapter_root / relative_path
        distribution_file = distribution_root / relative_path
        require(source_file)
        require(distribution_file)
        if digest(source_file) != expected_hash or digest(distribution_file) != expected_hash:
            raise ValueError(f"Distribution is out of sync: {relative_path}")

    print("V0 repository, projection, and distribution validation passed.")


if __name__ == "__main__":
    main()
