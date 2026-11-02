"""The sole temporary detection-core v1 JSON serialization capability."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from openultrasast.core.legacy_v1 import contracts


def trace_record(value: contracts.TraceRecord) -> dict[str, Any]:
    payload: dict[str, Any] = asdict(value)
    payload["judgment"] = value.judgment.value
    return cast(dict[str, Any], json.loads(json.dumps(payload, sort_keys=True)))


def trace_bytes(value: contracts.TraceRecord) -> bytes:
    return json.dumps(trace_record(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fact_pack_digest(family: str, facts: Sequence[Mapping[str, Any]]) -> str:
    encoded = json.dumps([family, tuple(dict(fact) for fact in facts)], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:12]


def text_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def input_digest(change_id: str, population_digest: str) -> str:
    payload = json.dumps([population_digest, change_id], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()[:12]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise contracts.FactPackError(f"pack {path}: root must be an object")
    return value


__all__ = ["fact_pack_digest", "input_digest", "read_json", "text_digest", "trace_bytes", "trace_record"]
