"""Loop-owned complexity ledger: overlay hotspot scores without hiding sev-5 inventory."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from ..findings import StaticFinding

if TYPE_CHECKING:
    from .map import Hotspot

TRIGGERABLE_DELTA = 1.5
NOT_TRIGGERABLE_DELTA = -1.5
VERDICT_DELTAS = {
    "triggerable": TRIGGERABLE_DELTA,
    "not_triggerable": NOT_TRIGGERABLE_DELTA,
}
FORCED_CANDIDATE_SEVERITY = 5
FORCED_CANDIDATE_REACHABILITY = frozenset({"reachable", "inferred-file-surface"})


@dataclass(frozen=True)
class LedgerEntry:
    score_delta: float
    last_verdict: str
    round: int = 0


def hotspot_key(path: str, function_name: str | None) -> str:
    return f"{path}:{function_name or ''}"


def load_ledger(path: Path | None) -> dict[str, LedgerEntry]:
    if path is None or not path.exists():
        return {}
    payload = json.loads(path.read_text())
    entries: dict[str, LedgerEntry] = {}
    for key, value in payload.items():
        entry = _coerce_entry(value)
        if entry is not None:
            entries[str(key)] = entry
    return entries


def write_ledger(path: Path, ledger: Mapping[str, LedgerEntry | Mapping[str, object]]) -> None:
    payload: dict[str, dict[str, object]] = {}
    for key, value in ledger.items():
        entry = _coerce_entry(value)
        if entry is None:
            continue
        payload[str(key)] = asdict(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def persist_verdicts(path: Path, verdicts: Sequence[object]) -> dict[str, LedgerEntry]:
    """Record triggerable / not_triggerable outcomes into the loop-owned complexity ledger."""
    ledger = load_ledger(path)
    changed = False
    for item in verdicts:
        verdict = str(getattr(item, "verdict", ""))
        if verdict not in VERDICT_DELTAS:
            continue
        raw_function = getattr(item, "function_name", None)
        ledger = record_verdict(
            ledger,
            path=str(getattr(item, "path", "")),
            function_name=raw_function if isinstance(raw_function, str) else None,
            verdict=verdict,
        )
        changed = True
    if changed:
        write_ledger(path, ledger)
    return ledger


def record_verdict(
    ledger: Mapping[str, LedgerEntry | Mapping[str, object]],
    *,
    path: str,
    function_name: str | None,
    verdict: str,
) -> dict[str, LedgerEntry]:
    updated: dict[str, LedgerEntry] = {}
    for key, value in ledger.items():
        entry = _coerce_entry(value)
        if entry is not None:
            updated[str(key)] = entry
    key = hotspot_key(path, function_name)
    previous = updated.get(key)
    updated[key] = LedgerEntry(
        score_delta=round((previous.score_delta if previous else 0.0) + VERDICT_DELTAS.get(verdict, 0.0), 4),
        last_verdict=verdict,
        round=(previous.round if previous else 0) + 1,
    )
    return updated


def apply_overlay(
    hotspots: Sequence[Hotspot],
    ledger: Mapping[str, LedgerEntry | Mapping[str, object]],
) -> tuple[Hotspot, ...]:
    if not ledger:
        return tuple(hotspots)
    adjusted: list[Hotspot] = []
    for hotspot in hotspots:
        entry = _coerce_entry(ledger.get(hotspot_key(hotspot.path, hotspot.function_name)))
        if entry is None or entry.score_delta == 0.0:
            adjusted.append(hotspot)
            continue
        score = round(hotspot.score + entry.score_delta, 4)
        signals = dict(hotspot.signals)
        signals["ledger_delta"] = entry.score_delta
        adjusted.append(
            replace(
                hotspot,
                score=score,
                band=_band_for(score),
                signals=signals,
                rationale=(
                    f"{hotspot.rationale} ledger overlay last_verdict={entry.last_verdict} "
                    f"score_delta={entry.score_delta} (inventory retained)."
                ),
            )
        )
    return tuple(sorted(adjusted, key=lambda item: (-item.score, item.path, item.function_name or "")))


def must_keep_as_candidate(
    finding: StaticFinding,
    policy_severity: int | object,
    reachability: str | None = None,
) -> bool:
    status = finding.reachability_status if reachability is None else reachability
    return _as_severity(policy_severity) >= FORCED_CANDIDATE_SEVERITY and status in FORCED_CANDIDATE_REACHABILITY


def select_forced_candidates(
    findings: Sequence[StaticFinding],
    policy: Mapping[str, object],
    *,
    rule_cwe: Mapping[str, str] | None = None,
) -> tuple[StaticFinding, ...]:
    cwe_by_id = rule_cwe or {}
    return tuple(
        finding
        for finding in findings
        if must_keep_as_candidate(finding, _policy_severity_for(finding, policy, cwe_by_id), finding.reachability_status)
    )


def _policy_severity_for(finding: StaticFinding, policy: Mapping[str, object], cwe_by_id: Mapping[str, str]) -> int:
    if finding.finding_id in policy:
        return _as_severity(policy[finding.finding_id])
    cwe = cwe_by_id.get(finding.finding_id)
    if cwe is not None and cwe in policy:
        return _as_severity(policy[cwe])
    return 0


def _as_severity(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    severity = getattr(value, "severity", None)
    if isinstance(severity, bool) or not isinstance(severity, int):
        return 0
    return severity


def _coerce_entry(value: object) -> LedgerEntry | None:
    if isinstance(value, LedgerEntry):
        return value
    if not isinstance(value, Mapping):
        return None
    raw_delta = value.get("score_delta")
    if isinstance(raw_delta, bool) or not isinstance(raw_delta, int | float):
        return None
    raw_round = value.get("round", 0)
    round_n = raw_round if isinstance(raw_round, int) and not isinstance(raw_round, bool) else 0
    return LedgerEntry(
        score_delta=float(raw_delta),
        last_verdict=str(value.get("last_verdict", "")),
        round=round_n,
    )


def _band_for(score: float) -> str:
    from .map import _band

    return _band(score)
