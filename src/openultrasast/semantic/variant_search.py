"""Variant search over a scanned tree and its merge with overlay flows (corpus-seeded-mechanisms, Req 3).

Depends on the shapes (``variants``), the store (``mechanisms``), the overlay records and ``StaticFinding``; the shape
module itself stays free of those imports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from ..findings import StaticFinding
from ..preprocess import FileTarget
from .facts import SemanticFacts
from .ir import parse_file
from .mechanisms import MechanismStore, corpus_mechanisms
from .overlay import OverlayRecord
from .variants import Shape, VariantHit, match_shapes

LANGUAGE_UNSUPPORTED = "variants_language_unsupported"


@dataclass(frozen=True)
class SearchResult:
    hits: tuple[VariantHit, ...]
    mechanisms_searched: int
    files_searched: int
    degradations: tuple[dict[str, object], ...] = ()


def search_tree(
    root: Path,
    targets: Sequence[FileTarget],
    store: MechanismStore,
    facts: SemanticFacts,
    *,
    max_mechanisms: int,
) -> SearchResult:
    """Variant search over the parsed files of a tree with the store's corpus shapes (bounded by ``max_mechanisms``)."""
    records = corpus_mechanisms(store.load())[: max(max_mechanisms, 0)]
    shapes: list[Shape] = []
    ids: dict[str, str] = {}
    degradations: list[dict[str, object]] = []
    for record in records:
        assert record.shape is not None
        try:
            shape = Shape.from_dict(record.shape)
        except (ValueError, TypeError) as exc:  # one malformed operator-visible row must not abort the scan
            degradations.append(
                {"stage": "variants", "reason": "variants_store_row_invalid", "mechanism_id": record.id, "detail": str(exc)[:120]}
            )
            continue
        shapes.append(shape)
        ids[shape.key()] = record.id
    if not shapes:
        return SearchResult(hits=(), mechanisms_searched=0, files_searched=0, degradations=tuple(degradations))
    hits: list[VariantHit] = []
    files = 0
    unsupported: set[str] = set()
    for target in targets:
        try:
            text = (root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        ir = parse_file(target.path, text, target.language)
        if not ir.parse_ok:
            if ir.reason == "language_unsupported" and target.language not in unsupported:
                unsupported.add(target.language)
                degradations.append({"stage": "variants", "reason": "variants_language_unsupported", "language": target.language})
            continue
        files += 1
        hits.extend(match_shapes(ir, shapes, facts, mechanism_ids=ids))
    return SearchResult(hits=tuple(hits), mechanisms_searched=len(shapes), files_searched=files, degradations=tuple(degradations))


def hits_to_findings(
    hits: Sequence[VariantHit],
    records: Sequence[OverlayRecord],
    summaries: Mapping[str, tuple[str, tuple[str, ...], str]],
) -> tuple[list[StaticFinding], list[OverlayRecord]]:
    """Merge hits into overlay records at the same call site (Req 3.3); the rest become ``suspicion`` findings (Req 3.2)."""
    by_site: dict[tuple[str, int | None], list[int]] = {}
    for index, record in enumerate(records):
        if record.disposition in {"promote", "coverage"} and record.sources and record.sinks:
            by_site.setdefault((record.path, record.line), []).append(index)
    updated = list(records)
    findings: list[StaticFinding] = []
    emitted: set[str] = set()
    for hit in hits:
        indexes = by_site.get((hit.path, hit.line))
        if indexes:
            for index in indexes:
                if updated[index].mechanism_id is None:
                    updated[index] = replace(updated[index], mechanism_id=hit.mechanism_id)
            continue
        finding_id = f"variant:{hit.mechanism_id}:{hit.path}:{hit.line}"
        if finding_id in emitted:
            continue
        emitted.add(finding_id)
        summary, pairs, cwe = summaries.get(hit.mechanism_id, (hit.mechanism_id, (), ""))
        taught_by = ", ".join(pairs) if pairs else "the mechanism store"
        findings.append(
            StaticFinding(
                finding_id=finding_id,
                path=hit.path,
                title=f"Variant of known mechanism: {hit.sink_name}",
                severity="medium",
                confidence="low",
                evidence_level="suspicion",
                rationale=(
                    f"{summary}. Structural variant ({hit.source_kind} reaches {hit.sink_name}) of a mechanism learned from "
                    f"{taught_by}; suspicion until the overlay or the sandbox agrees."
                ),
                line=hit.line,
                function_name=None,
                reachability_status="unknown",
                reachability_evidence=[],
                reachability_conditions=[],
                tags=["variant", f"mechanism:{hit.mechanism_id}", *([f"cwe:{cwe}"] if cwe else [])],
                ranking_priority=0.0,
            )
        )
    return findings, updated
