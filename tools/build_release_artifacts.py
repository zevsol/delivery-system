"""Build the release-owned Skills plugin and deterministic release manifest."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
from typing import Iterable
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from delivery_system.release_identity import current_release_id


CANONICAL_SKILLS = (
    "plan-github-work-items",
    "audit-github-work-items",
    "approve-github-work-items",
    "apply-github-work-items",
)
PLUGIN_DESCRIPTION = "Governed delivery control for auditable, human-approved GitHub work items."
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
RELEASE_FORMAT = "delivery-system-release"
RELEASE_FORMAT_VERSION = 1


class ReleaseArtifactError(RuntimeError):
    """Sanitized deterministic release-artifact failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ArtifactRecord:
    kind: str
    filename: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
        }


def _normalised_filename_version(version: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", version)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_external_directory(path: Path, repo_root: Path) -> None:
    resolved = path.resolve()
    if resolved == repo_root.resolve() or repo_root.resolve() in resolved.parents:
        raise ReleaseArtifactError("release_artifact_output_inside_repository")


def _runtime_artifacts(runtime_distribution_dir: Path, version: str) -> tuple[Path, Path]:
    if not runtime_distribution_dir.is_dir() or runtime_distribution_dir.is_symlink():
        raise ReleaseArtifactError("release_artifact_runtime_directory_invalid")
    filename_version = _normalised_filename_version(version)
    expected_wheel = f"delivery_system-{filename_version}-py3-none-any.whl"
    expected_sdist = f"delivery_system-{filename_version}.tar.gz"
    wheel_candidates = sorted(
        path for path in runtime_distribution_dir.iterdir()
        if path.name.startswith(f"delivery_system-{filename_version}-") and path.name.endswith(".whl")
    )
    sdist_candidates = sorted(
        path for path in runtime_distribution_dir.iterdir()
        if path.name.startswith(f"delivery_system-{filename_version}") and path.name.endswith(".tar.gz")
    )
    if len(wheel_candidates) != 1 or wheel_candidates[0].name != expected_wheel:
        raise ReleaseArtifactError("release_artifact_wheel_invalid")
    if len(sdist_candidates) != 1 or sdist_candidates[0].name != expected_sdist:
        raise ReleaseArtifactError("release_artifact_sdist_invalid")
    if any(path.is_symlink() or not path.is_file() for path in (wheel_candidates[0], sdist_candidates[0])):
        raise ReleaseArtifactError("release_artifact_runtime_file_invalid")
    return wheel_candidates[0], sdist_candidates[0]


def _skill_files(skill_root: Path) -> list[tuple[str, Path]]:
    if not skill_root.is_dir() or skill_root.is_symlink():
        raise ReleaseArtifactError("release_artifact_skill_directory_invalid")
    result: list[tuple[str, Path]] = []
    for path in sorted(skill_root.rglob("*"), key=lambda item: item.relative_to(skill_root).as_posix()):
        relative = path.relative_to(skill_root).as_posix()
        if not relative or ".." in Path(relative).parts or Path(relative).is_absolute():
            raise ReleaseArtifactError("release_artifact_skill_path_invalid")
        if path.is_symlink():
            raise ReleaseArtifactError("release_artifact_skill_symlink")
        if path.is_dir():
            continue
        if not path.is_file() or stat.S_ISREG(path.stat().st_mode) is False:
            raise ReleaseArtifactError("release_artifact_skill_file_invalid")
        result.append((relative, path))
    if not any(relative == "SKILL.md" for relative, _ in result):
        raise ReleaseArtifactError("release_artifact_skill_manifest_missing")
    return result


def _skill_source_files(repo_root: Path) -> list[tuple[str, Path]]:
    skills_root = repo_root / "skills"
    if not skills_root.is_dir() or skills_root.is_symlink():
        raise ReleaseArtifactError("release_artifact_skills_root_invalid")
    actual = sorted(
        path.name for path in skills_root.iterdir()
        if path.is_dir() or path.is_symlink()
    )
    if actual != sorted(CANONICAL_SKILLS):
        raise ReleaseArtifactError("release_artifact_skill_set_invalid")
    result: list[tuple[str, Path]] = []
    for skill_name in CANONICAL_SKILLS:
        for relative, path in _skill_files(skills_root / skill_name):
            result.append((f"skills/{skill_name}/{relative}", path))
    return result


def _plugin_manifest(version: str) -> bytes:
    return _canonical_json({
        "$schema": PLUGIN_SCHEMA,
        "description": PLUGIN_DESCRIPTION,
        "name": "delivery-system",
        "version": version,
    })


def _zip_info(name: str) -> ZipInfo:
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 << 16)
    return info


def _write_plugin_zip(path: Path, version: str, skill_files: Iterable[tuple[str, Path]]) -> None:
    root = f"delivery-system-plugin-{version}"
    members: list[tuple[str, bytes]] = [(f"{root}/plugin.json", _plugin_manifest(version))]
    for relative, source in skill_files:
        members.append((f"{root}/{relative}", source.read_bytes()))
    with ZipFile(path, mode="x", compression=ZIP_STORED) as archive:
        for name, content in sorted(members, key=lambda item: item[0]):
            archive.writestr(_zip_info(name), content)


def _copy_runtime_artifact(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ReleaseArtifactError("release_artifact_output_exists")
    shutil.copyfile(source, destination)


def build_release_artifacts(
    repo_root: Path,
    runtime_distribution_dir: Path,
    output_dir: Path,
) -> dict[str, Path]:
    """Build the release-owned artifacts without changing repository sources."""

    repo_root = repo_root.resolve()
    runtime_distribution_dir = runtime_distribution_dir.resolve()
    output_dir = output_dir.resolve()
    _require_external_directory(output_dir, repo_root)
    if output_dir.exists() and output_dir.is_symlink():
        raise ReleaseArtifactError("release_artifact_output_directory_invalid")
    output_dir.mkdir(parents=True, exist_ok=True)

    version = current_release_id()
    wheel, sdist = _runtime_artifacts(runtime_distribution_dir, version)
    skill_files = _skill_source_files(repo_root)
    filename_version = _normalised_filename_version(version)
    output_wheel = output_dir / wheel.name
    output_sdist = output_dir / sdist.name
    plugin = output_dir / f"delivery-system-plugin-{filename_version}.zip"
    release_manifest = output_dir / f"delivery-system-release-{filename_version}.json"
    targets = (output_wheel, output_sdist, plugin, release_manifest)
    if any(target.exists() or target.is_symlink() for target in targets):
        raise ReleaseArtifactError("release_artifact_output_exists")

    _copy_runtime_artifact(wheel, output_wheel)
    _copy_runtime_artifact(sdist, output_sdist)
    try:
        _write_plugin_zip(plugin, version, skill_files)
        records = [
            ArtifactRecord("wheel", output_wheel.name, output_wheel.stat().st_size, _sha256(output_wheel)),
            ArtifactRecord("sdist", output_sdist.name, output_sdist.stat().st_size, _sha256(output_sdist)),
            ArtifactRecord("plugin", plugin.name, plugin.stat().st_size, _sha256(plugin)),
        ]
        release_manifest.write_bytes(_canonical_json({
            "artifacts": [record.as_dict() for record in records],
            "format": RELEASE_FORMAT,
            "format_version": RELEASE_FORMAT_VERSION,
            "version": version,
        }))
    except Exception:
        for target in targets:
            if target.exists() and not target.is_dir():
                target.unlink()
        raise
    return {
        "wheel": output_wheel,
        "sdist": output_sdist,
        "plugin": plugin,
        "manifest": release_manifest,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-distribution-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    artifacts = build_release_artifacts(args.repo_root, args.runtime_distribution_dir, args.output_dir)
    for kind in ("wheel", "sdist", "plugin", "manifest"):
        print(f"{kind}={artifacts[kind]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
