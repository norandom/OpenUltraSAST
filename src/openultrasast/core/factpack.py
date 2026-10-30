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


__all__ = ["FactPack", "FactPackError", "admit_fact_pack", "verify_fact_pack"]
