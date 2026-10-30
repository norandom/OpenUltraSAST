"""Family fact-pack admission contract for the detection core (Req 10).

New vulnerability families enter only as reviewed fact packs: the pack carries its
family tag and a review digest, and its fact-set digest is stamped so consumers can
refuse tampered content. The core never reads pool or admission labels.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class FactPackError(ValueError):
    """A fact pack is unreviewed or its content does not match its digest."""


@dataclass(frozen=True)
class FactPack:
    """A reviewed family fact pack with provenance."""

    family: str
    facts: tuple[dict[str, Any], ...]
    review_digest: str
    fact_set_digest: str


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]


def admit_fact_pack(family: str, facts: Sequence[Mapping[str, Any]], *, review_digest: str) -> FactPack:
    """Admit a pack only with review evidence; stamp its fact-set digest (Req 10.1)."""
    if not review_digest:
        raise FactPackError("unreviewed fact pack refused: no review digest")
    normalized = tuple(dict(fact) for fact in facts)
    return FactPack(
        family=family,
        facts=normalized,
        review_digest=review_digest,
        fact_set_digest=_digest([family, normalized]),
    )


def verify_fact_pack(pack: FactPack, facts: Sequence[Mapping[str, Any]]) -> None:
    """Refuse content that does not match the pack's stamped digest."""
    normalized = tuple(dict(fact) for fact in facts)
    if _digest([pack.family, normalized]) != pack.fact_set_digest:
        raise FactPackError(f"fact content does not match the stamped digest of pack {pack.family!r}")


def load_pack_file(path: str | Path) -> FactPack:
    """Load a pack file whose embedded review attestation is self-consistent.

    ``review.digest`` must equal sha256 of ``review.note``; anything else is refused.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    review = payload.get("review", {})
    note = review.get("note", "")
    if not note or review.get("digest") != hashlib.sha256(note.encode()).hexdigest():
        raise FactPackError(f"pack {path} lacks a verifiable review attestation")
    facts = payload.get("facts")
    if not isinstance(facts, list) or not all(isinstance(fact, dict) for fact in facts):
        raise FactPackError(f"pack {path}: facts must be a list of objects")
    return admit_fact_pack(str(payload.get("family", "")), facts, review_digest=review["digest"])


def admit_pack_file(path: str | Path, *, review_digest: str) -> FactPack:
    """Admit a pack file only when its embedded attestation matches the supplied review digest."""
    pack = load_pack_file(path)
    if review_digest != pack.review_digest:
        raise FactPackError(f"pack {path}: supplied review digest does not match the embedded attestation")
    return pack


__all__ = ["FactPack", "FactPackError", "admit_fact_pack", "admit_pack_file", "load_pack_file", "verify_fact_pack"]
