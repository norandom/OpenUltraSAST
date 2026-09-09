"""The repository driver (contributor-scan, Req 3).

Pair scoring built one CPG per pair and asked about one region. A repository has thousands of regions, and the
two costs that were free at pair scale dominate here:

* **CPG construction.** A build takes 5-30 seconds on a forty-line excerpt. One per region would make a
  repository scan unusable, so this builds **one** and reuses it across every region.
* **Model calls.** The enumerator caps candidates at eight per region, which says nothing useful about a scan
  with two thousand regions. The budget is a **total for the run**, spent on the highest-ranked regions first,
  and whatever it does not reach is counted into ``regions_unjudged`` rather than quietly dropped. A tool that
  silently analyses a tenth of a repository and reports a clean result is worse than one that says what it
  did not look at.

Ordering puts rung before rank: what the model established outranks what the LLM merely proposed, whatever
the region's risk score said beforehand.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .candidates import enumerate_candidates
from .ladder import Rung
from .pipeline import ModelFinding, scan_region
from .regions import ScanRegion
from .specs import ConfigSpec, DominanceSpec, TaintSpec, config_specs, dominance_specs, taint_specs
from .taxonomy import load_families

logger = logging.getLogger(__name__)

_RUNG_ORDER = {Rung.ENTAILED: 0, Rung.CORROBORATED: 1, Rung.SUSPICION: 2, Rung.EXECUTION_CONFIRMED: -1}


@dataclass(frozen=True)
class ScanBudget:
    """A total for the run, not a per-region cap."""

    max_model_calls: int = 200
    max_regions: int = 500


@dataclass(frozen=True)
class ModelScanResult:
    findings: tuple[ModelFinding, ...] = ()
    by_rung: Mapping[str, int] = field(default_factory=dict)
    regions_scanned: int = 0
    regions_unjudged: int = 0
    model_calls: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0
    degradations: tuple[Mapping[str, object], ...] = ()


def scan_repository(
    root: Path,
    regions: Sequence[ScanRegion],
    *,
    backend: Any,
    client: Any | None = None,
    model: str = "",
    budget: ScanBudget | None = None,
) -> ModelScanResult:
    """Arbitrate a repository's regions under one CPG and one budget."""
    limits = budget if budget is not None else ScanBudget()
    started = time.monotonic()
    degradations: list[Mapping[str, object]] = []

    taxonomy = load_families()
    cpg = backend.build(root)
    if cpg is None:
        return ModelScanResult(
            by_rung=_empty_tally(),
            regions_unjudged=len(regions),
            seconds=round(time.monotonic() - started, 2),
            degradations=({"stage": "model", "reason": "cpg_build_failed"},),
        )

    # Count calls here rather than reading a client's own meter: the budget is this driver's contract and
    # must hold for any client, including one that keeps no usage log.
    counted = _CountingClient(client) if client is not None else None
    collected: list[tuple[ModelFinding, float]] = []
    scanned = 0

    # Sort here rather than trusting the caller. The budget decides what goes unexamined, so the order it is
    # spent in belongs to whoever holds the budget.
    ordered_regions = sorted(regions, key=lambda r: (-r.rank, r.path, r.function or ""))

    for region in ordered_regions:
        if scanned >= limits.max_regions or (counted is not None and counted.calls >= limits.max_model_calls):
            degradations.append({"stage": "model", "reason": "budget_exhausted", "regions_unjudged": len(regions) - scanned})
            break
        for family in region.families:
            spec = _spec_for(family, region.language)
            if spec is None:
                continue
            try:
                # Enumerate the region's candidate sites so the judge has something to answer about where the
                # model resolves nothing. Without this a repository scan reports only what taint, dominance
                # and constant abstraction establish unaided -- and the suspicion band, which supplied 15 of
                # 26 findings in the pair measurement, would never be populated at all.
                enumerated = enumerate_candidates(root, region, family, taxonomy=taxonomy)
                candidates = [{"id": c.id, "text": c.text, "line": c.line} for c in enumerated.candidates]
                found = scan_region(
                    cpg,
                    spec,
                    function=region.function or "",
                    client=counted,
                    model=model,
                    candidates=candidates,
                    parameter_sources=False,  # a repository's parameters are not all attacker input
                )
            except Exception as exc:  # noqa: BLE001 -- one bad region must not end the scan
                logger.warning("model scan failed for %s: %s", region.path, exc)
                degradations.append({"stage": "model", "reason": "region_failed", "path": region.path})
                continue
            collected.extend((finding, region.rank) for finding in found)
        scanned += 1

    findings = _ordered(collected)
    return ModelScanResult(
        findings=findings,
        by_rung=_tally(findings),
        regions_scanned=scanned,
        regions_unjudged=max(len(regions) - scanned, 0),
        model_calls=counted.calls if counted is not None else 0,
        cost_usd=round(_cost(counted), 4),
        seconds=round(time.monotonic() - started, 2),
        degradations=tuple(degradations),
    )


def _spec_for(family: str, language: str) -> TaintSpec | DominanceSpec | ConfigSpec | None:
    """The spec whose arbiter can decide this family. Routing stays a lookup; dispatch stays in `_arbitrate`."""
    if family == "access_control":
        return dominance_specs(language=language).get(family)
    if family == "config_secrets":
        return config_specs(language=language).get(family)
    return taint_specs(language=language).get(family)


def _ordered(collected: Sequence[tuple[ModelFinding, float]]) -> tuple[ModelFinding, ...]:
    """Rung first, then the region's rank, then the site — a total order, so two runs agree."""
    return tuple(finding for finding, _ in sorted(collected, key=lambda pair: (_RUNG_ORDER.get(pair[0].rung, 9), -pair[1], pair[0].site)))


def _empty_tally() -> dict[str, int]:
    return {rung.value: 0 for rung in Rung}


def _tally(findings: Sequence[ModelFinding]) -> dict[str, int]:
    tally = _empty_tally()
    for finding in findings:
        tally[finding.rung.value] = tally.get(finding.rung.value, 0) + 1
    return tally


class _CountingClient:
    """Wraps a chat client so the driver counts its own spend, whatever the client records."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls = 0

    def complete(self, **kwargs: Any) -> Any:
        self.calls += 1
        return self._inner.complete(**kwargs)

    def cost_usd(self) -> float:
        meter = getattr(self._inner, "cost_usd", None)
        return float(meter()) if callable(meter) else 0.0


def _cost(client: object | None) -> float:
    meter = getattr(client, "cost_usd", None)
    return float(meter()) if callable(meter) else 0.0


__all__ = ["ModelScanResult", "ScanBudget", "scan_repository"]
