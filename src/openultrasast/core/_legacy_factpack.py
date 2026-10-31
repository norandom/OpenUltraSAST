"""Compatibility facade for the pre-v2 file-backed fact-pack API."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class FactPackError(ValueError):
    """A legacy fact pack is unreviewed or inconsistent."""


@dataclass(frozen=True)
class LegacyFactPack:
    family: str
    facts: tuple[dict[str, Any], ...]
    review_digest: str
    fact_set_digest: str


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:12]


def admit_fact_pack(family: str, facts: Sequence[Mapping[str, Any]], *, review_digest: str) -> LegacyFactPack:
    if not review_digest:
        raise FactPackError("unreviewed fact pack refused: no review digest")
    normalized = tuple(dict(fact) for fact in facts)
    return LegacyFactPack(family, normalized, review_digest, _digest([family, normalized]))


def verify_fact_pack(pack: LegacyFactPack, facts: Sequence[Mapping[str, Any]]) -> None:
    normalized = tuple(dict(fact) for fact in facts)
    if _digest([pack.family, normalized]) != pack.fact_set_digest:
        raise FactPackError(f"fact content does not match the stamped digest of pack {pack.family!r}")


def load_pack_file(path: str | Path) -> LegacyFactPack:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    review = payload.get("review", {})
    note = review.get("note", "")
    if not note or review.get("digest") != hashlib.sha256(note.encode()).hexdigest():
        raise FactPackError(f"pack {path} lacks a verifiable review attestation")
    facts = payload.get("facts")
    if not isinstance(facts, list) or not all(isinstance(fact, dict) for fact in facts):
        raise FactPackError(f"pack {path}: facts must be a list of objects")
    return admit_fact_pack(str(payload.get("family", "")), facts, review_digest=review["digest"])


def admit_pack_file(path: str | Path, *, review_digest: str) -> LegacyFactPack:
    pack = load_pack_file(path)
    if review_digest != pack.review_digest:
        raise FactPackError(f"pack {path}: supplied review digest does not match the embedded attestation")
    return pack
