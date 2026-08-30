"""Canonical, deterministic serialization primitives."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any, Mapping


def _text(value: str) -> str:
    value = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    return "\n".join(line.rstrip() for line in value.split("\n")).strip()


def _sort_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize(value: Any) -> Any:
    """Normalize supported values while preserving ordered sequence semantics."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, Mapping):
        normalized_keys: dict[str, str] = {}
        for key in value:
            if not isinstance(key, str):
                raise TypeError("Canonical mappings require string keys")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized_keys:
                raise ValueError("Canonical mapping keys collide after NFC normalization")
            normalized_keys[normalized_key] = key
        return {
            normalized_key: normalize(value[original_key])
            for normalized_key, original_key in sorted(normalized_keys.items())
        }
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [normalize(item) for item in value]
        return sorted(items, key=_sort_key)
    if isinstance(value, bool) or isinstance(value, int) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and infinite floats are not canonical values")
        return value
    raise TypeError(f"Unsupported canonical value: {type(value).__name__}")


def canonical_payload(value: Mapping[str, Any]) -> str:
    """Serialize a payload deterministically as UTF-8 JSON."""
    return json.dumps(normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_payload(value).encode("utf-8")).hexdigest()
