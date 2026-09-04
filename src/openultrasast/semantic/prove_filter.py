"""Prove only promotions. Demotions are dropped; unadjudicated is not negative proof."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from ..complexity.map import Hotspot
from ..findings import StaticFinding
from .overlay import OverlayRecord


def filter_promoted_hotspots(
    hotspots: Sequence[Hotspot],
    records: Sequence[OverlayRecord],
    findings: Sequence[StaticFinding] | None = None,
) -> tuple[Hotspot, ...]:
    del findings
    promoted = {record.proposal_id for record in records if record.disposition == "promote"}
    selected: list[Hotspot] = []
    for hotspot in hotspots:
        kept = tuple(finding_id for finding_id in hotspot.inventory_finding_ids if finding_id in promoted)
        if kept:
            selected.append(replace(hotspot, inventory_finding_ids=kept))
    return tuple(selected)


def promoted_findings(findings: Sequence[StaticFinding], records: Sequence[OverlayRecord]) -> list[StaticFinding]:
    promoted = {record.proposal_id for record in records if record.disposition == "promote"}
    return [finding for finding in findings if finding.finding_id in promoted]
