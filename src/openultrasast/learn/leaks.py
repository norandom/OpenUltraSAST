"""The leakage audit: how well each signal *alone* tells the sides of a pair apart (``ousast learn audit-leaks``).

No model. A pair is one candidate (``path::function`` and family) on its vulnerable side and on its fixed side -- a
pair-corpus case, or a population case's vulnerable and fixed pins. Within a pair the code differs by the fix, so a
signal that differs between the sides *and whose difference names the side* is either real evidence about the fix or
an instrument artifact that tracks the label (the engine's "read the file, asked no question" state on a fixed side
that lost its sink). The audit cannot tell which; it ranks every signal so a person can.

For each feature of the profile, and for each instrument's state (``state.<instrument>``), over the ``N`` pairs:

- an ordered feature (``int``, ``float``, ``bool``; ``null`` ranks below every value) predicts the side by one global
  direction: ``correct`` = pairs where the vulnerable side is higher (or lower, whichever is more), ``wrong`` = the
  other direction;
- an unordered one (``enum``, an instrument state) by the majority side of each unordered pair of values;
- **separation** = ``(correct - wrong) / N``: the share of all pairs the signal alone puts on the right side, net of
  the pairs it puts on the wrong one. 0 is no information (or no difference), 1 is every pair.

A signal is **flagged** when its separation is at least :data:`THRESHOLD` (0.20) over at least :data:`MIN_PAIRS`
(10) pairs, over all pairs or within one family. The output is counts only: feature, instrument and family names.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .schema import FeatureSpec, features_for, instruments_for

THRESHOLD = 0.20
MIN_PAIRS = 10
ALL = "all"
Record = Mapping[str, Any]


@dataclass(frozen=True)
class Pair:
    family: str
    vulnerable: Record  # a feature record: x and instruments
    fixed: Record


@dataclass(frozen=True)
class Signal:
    """A feature (``spec``) or an instrument's state (``instrument``)."""

    name: str
    instrument: str
    ordered: bool
    spec: FeatureSpec | None = None

    def value(self, record: Record) -> Any:
        if self.spec is None:
            return str((record["instruments"].get(self.instrument) or {}).get("state", "none"))
        return record["x"].get(self.name)


def signals(profile: str) -> list[Signal]:
    out = [Signal(f"state.{name}", name, False) for name in instruments_for(profile) if name != "language"]
    out += [Signal(s.name, s.instrument, s.type != "enum", s) for s in features_for(profile)]
    return out


def _rank(value: Any) -> float:
    return -1.0 if value is None else float(value)


def separation(signal: Signal, pairs: Sequence[Pair]) -> dict[str, Any]:
    """``pairs``, ``differ``, ``correct``, ``wrong``, ``separation`` and (ordered) the ``direction`` of one signal."""
    n = len(pairs)
    values = [(signal.value(p.vulnerable), signal.value(p.fixed)) for p in pairs]
    out: dict[str, Any] = {"pairs": n}
    if signal.ordered:
        higher = sum(_rank(v) > _rank(f) for v, f in values)
        lower = sum(_rank(v) < _rank(f) for v, f in values)
        correct, wrong = max(higher, lower), min(higher, lower)
        if correct:
            out["direction"] = "higher on vulnerable" if higher >= lower else "higher on fixed"
    else:
        counts: Counter[tuple[str, str]] = Counter((repr(v), repr(f)) for v, f in values if v != f)
        correct = wrong = 0
        for a, b in {tuple(sorted(k)) for k in counts}:
            one, other = counts[(a, b)], counts[(b, a)]
            correct, wrong = correct + max(one, other), wrong + min(one, other)
    out.update({"differ": correct + wrong, "correct": correct, "wrong": wrong, "separation": round((correct - wrong) / n, 4) if n else 0.0})
    return out


def audit(pairs: Sequence[Pair], profile: str, *, threshold: float = THRESHOLD, min_pairs: int = MIN_PAIRS) -> dict[str, Any]:
    """Every signal's separation over all pairs and per family, and the flagged (signal, scope) cells, strongest first."""
    families = sorted({p.family for p in pairs})
    scopes = {ALL: list(pairs), **{f: [p for p in pairs if p.family == f] for f in families}}
    table: dict[str, dict[str, Any]] = {}
    flagged: list[dict[str, Any]] = []
    for signal in signals(profile):
        row = {scope: separation(signal, members) for scope, members in scopes.items() if members}
        table[signal.name] = row
        for scope, cell in row.items():
            if cell["pairs"] >= min_pairs and cell["separation"] >= threshold:
                flagged.append({"signal": signal.name, "instrument": signal.instrument, "scope": scope, **cell})
    flagged.sort(key=lambda c: (-c["separation"], c["signal"], c["scope"]))
    return {
        "profile": profile,
        "threshold": threshold,
        "min_pairs": min_pairs,
        "pairs": {scope: len(members) for scope, members in scopes.items()},
        "flagged": flagged,
        "flagged_signals": sorted({c["signal"] for c in flagged}),
        "signals": table,
    }


def pair_rows(rows: Iterable[Record], side_of: Mapping[str, tuple[str, str]], profile: str) -> tuple[list[Pair], dict[str, int]]:
    """Pairs from stored feature rows of ``profile``. ``side_of`` maps a row's ``task`` (the harvest unit) to
    ``(case reference, side)``; a row carrying ``pin_role`` and ``source_ref`` needs no entry. A candidate pairs when it
    has exactly one vulnerable and one fixed record in the same case; the rest are counted."""
    groups: dict[tuple[str, str, str], dict[str, list[Record]]] = {}
    skipped: Counter[str] = Counter()
    for row in rows:
        if row.get("profile") != profile:
            continue
        if row.get("pin_role") and row.get("source_ref"):
            ref, side = str(row["source_ref"]), str(row["pin_role"])
        elif str(row.get("task")) in side_of:
            ref, side = side_of[str(row["task"])]
        else:
            skipped["no side"] += 1
            continue
        if side not in ("vulnerable", "fixed"):
            skipped[f"side {side}"] += 1
            continue
        groups.setdefault((ref, str(row["candidate"]), str(row["family"])), {}).setdefault(side, []).append(row)
    pairs: list[Pair] = []
    for (_, _, family), sides in sorted(groups.items()):
        vulnerable, fixed = sides.get("vulnerable", []), sides.get("fixed", [])
        if len(vulnerable) == 1 and len(fixed) == 1:
            pairs.append(Pair(family, vulnerable[0], fixed[0]))
        elif not vulnerable or not fixed:
            skipped["one side only"] += 1
        else:
            skipped["ambiguous"] += 1
    return pairs, dict(sorted(skipped.items()))


def sides_from_units(units: Mapping[str, Mapping[str, Any]]) -> dict[str, tuple[str, str]]:
    """Harvest ``units.json`` -> unit name: (case reference, side)."""
    return {name: (str(unit["ref"]), str(unit["side"])) for name, unit in units.items()}


__all__ = ["ALL", "MIN_PAIRS", "THRESHOLD", "Pair", "Signal", "audit", "pair_rows", "separation", "sides_from_units", "signals"]
