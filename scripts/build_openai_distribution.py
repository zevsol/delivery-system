"""Build the generated OpenAI distribution package from the canonical adapter."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "adapters" / "delivery-system-openai"
TARGET = ROOT / "plugins" / "delivery-system-openai"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def main() -> None:
    if not (SOURCE / ".codex-plugin" / "plugin.json").is_file():
        raise ValueError("Canonical OpenAI Adapter is missing its manifest")

    copy(SOURCE / ".codex-plugin" / "plugin.json", TARGET / ".codex-plugin" / "plugin.json")
    copy(SOURCE / "ADAPTER-CONTRACT.md", TARGET / "ADAPTER-CONTRACT.md")
    copy(SOURCE / "SYNC-MANIFEST.json", TARGET / "SYNC-MANIFEST.json")

    hashes: dict[str, str] = {}
    for source_file in (SOURCE / "skills").rglob("*"):
        if source_file.is_file():
            relative = source_file.relative_to(SOURCE)
            copy(source_file, TARGET / relative)
            hashes[str(relative).replace("\\", "/")] = digest(source_file)

    manifest = {
        "generated": True,
        "source": "adapters/delivery-system-openai",
        "generator": "scripts/build_openai_distribution.py",
        "files": hashes,
    }
    (TARGET / "DISTRIBUTION-MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Built distribution package: {TARGET}")


if __name__ == "__main__":
    main()
