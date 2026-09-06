"""The round journal, the per-family archive and the rejected buffer (learning-harness, Req 9.3, 9.6, 9.7, 11.3).

The journal is append-only, one JSON line per round, and a round number is never reused, so the record
of what was tried cannot be quietly rewritten by the thing that is trying. Every round writes a line
whether it was accepted or not: a rejection is evidence too, and the rejected hypotheses are what stop
the proposer from offering the same idea twice.

The archive keeps, per family, which configuration version wins which pair, rather than one champion.
Keeping only the best-overall candidate throws away a version that is the only one solving some pair,
which is how a search collapses onto one lineage. A later version takes a pair only by winning it.

Nothing is written without passing redaction, because a trajectory or a hypothesis may quote the code
it was reasoning about.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..redaction import redact_secrets
from .scoring import PairFamilyScore

Outcome = str  # accepted | rejected | reverted_cost | refused_holdout


def _as_int(value: object) -> int:
    return int(value) if isinstance(value, int | float | str) and not isinstance(value, bool) else 0


def _as_float(value: object) -> float:
    return float(value) if isinstance(value, int | float | str) and not isinstance(value, bool) else 0.0


def _as_strings(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in value) if isinstance(value, list | tuple) else ()


def _as_sweep(value: object) -> dict[str, int]:
    return {str(key): _as_int(item) for key, item in value.items()} if isinstance(value, Mapping) else {}


class JournalError(ValueError):
    """Raised when a round would overwrite history."""


@dataclass(frozen=True)
class Attribution:
    """Whether the round moved what it said it would move, and what it moved by accident."""

    flipped_predicted: int = 0
    flipped_unpredicted: int = 0
    precision: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "flipped_predicted": self.flipped_predicted,
            "flipped_unpredicted": self.flipped_unpredicted,
            "precision": self.precision,
        }

    @staticmethod
    def from_dict(payload: Mapping[str, object]) -> Attribution:
        return Attribution(
            flipped_predicted=_as_int(payload.get("flipped_predicted")),
            flipped_unpredicted=_as_int(payload.get("flipped_unpredicted")),
            precision=_as_float(payload.get("precision")),
        )


@dataclass(frozen=True)
class RoundRecord:
    round: int
    family: str
    hypothesis: str
    levers: tuple[str, ...]
    predicted_affected: tuple[str, ...]
    predicted_at_risk: tuple[str, ...]
    outcome: Outcome
    reason: str = ""
    target_train_delta: float = 0.0
    target_holdout_delta: float = 0.0
    sweep: dict[str, int] = field(default_factory=dict)  # family -> negative flips in the cross-family sweep
    attribution: Attribution = Attribution()
    cost_usd: float = 0.0
    taxonomy_version: str = ""
    config_version: str = ""
    # Pairs that moved each way in each stage, so the record can say whether the decision was distinguishable
    # from noise. The decision itself is Req 9.5's raw-delta rule; this is the evidence beside it.
    train_better: int = 0
    train_worse: int = 0
    holdout_better: int = 0
    holdout_worse: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "round": self.round,
            "family": self.family,
            "hypothesis": self.hypothesis,
            "levers": list(self.levers),
            "predicted_affected": list(self.predicted_affected),
            "predicted_at_risk": list(self.predicted_at_risk),
            "outcome": self.outcome,
            "reason": self.reason,
            "target_train_delta": self.target_train_delta,
            "target_holdout_delta": self.target_holdout_delta,
            "sweep": dict(sorted(self.sweep.items())),
            "attribution": self.attribution.to_dict(),
            "cost_usd": self.cost_usd,
            "taxonomy_version": self.taxonomy_version,
            "config_version": self.config_version,
            **{f"train_{key}": value for key, value in self._reliability(self.train_better, self.train_worse).items()},
            **{f"holdout_{key}": value for key, value in self._reliability(self.holdout_better, self.holdout_worse).items()},
        }

    @staticmethod
    def _reliability(better: int, worse: int) -> dict[str, object]:
        from .acceptance import reliability

        result = reliability(better=better, worse=worse)
        return {"better": result.better, "worse": result.worse, "p_value": result.p_value, "reliable": result.reliable}

    @staticmethod
    def from_dict(payload: Mapping[str, object]) -> RoundRecord:
        attribution = payload.get("attribution")
        return RoundRecord(
            round=_as_int(payload.get("round")),
            family=str(payload.get("family", "")),
            hypothesis=str(payload.get("hypothesis", "")),
            levers=_as_strings(payload.get("levers")),
            predicted_affected=_as_strings(payload.get("predicted_affected")),
            predicted_at_risk=_as_strings(payload.get("predicted_at_risk")),
            outcome=str(payload.get("outcome", "")),
            reason=str(payload.get("reason", "")),
            target_train_delta=_as_float(payload.get("target_train_delta")),
            target_holdout_delta=_as_float(payload.get("target_holdout_delta")),
            sweep=_as_sweep(payload.get("sweep")),
            attribution=Attribution.from_dict(attribution if isinstance(attribution, Mapping) else {}),
            cost_usd=_as_float(payload.get("cost_usd")),
            taxonomy_version=str(payload.get("taxonomy_version", "")),
            config_version=str(payload.get("config_version", "")),
        )


class LearningJournal:
    """Append-only history of rounds. What was tried, what it predicted, and what actually happened."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, record: RoundRecord) -> None:
        existing = {item.round for item in self.rounds()}
        if record.round in existing:
            raise JournalError(f"round {record.round} is already journaled; history is append-only")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = redact_secrets(json.dumps(record.to_dict(), sort_keys=True))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def rounds(self) -> tuple[RoundRecord, ...]:
        return tuple(RoundRecord.from_dict(payload) for payload in _read_jsonl(self.path))

    def next_round(self) -> int:
        rounds = self.rounds()
        return max((item.round for item in rounds), default=0) + 1

    def rejected_buffer(self, family: str) -> tuple[str, ...]:
        """Hypotheses this family already tried and lost, so the proposer is not handed the same idea twice."""
        return tuple(item.hypothesis for item in self.rounds() if item.family == family and item.outcome != "accepted" and item.hypothesis)


class Archive:
    """Per family, which configuration version wins which pair. Never one champion."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, family: str, config_version: str, score: PairFamilyScore) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "family": family,
            "config_version": config_version,
            "pair": score.pair,
            "outcome": score.outcome,
            "flips": score.flips,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(redact_secrets(json.dumps(payload, sort_keys=True)) + "\n")

    def winners(self, family: str) -> dict[str, str]:
        """pair -> the earliest configuration version that scored it correct.

        Earliest, not latest: the point of the archive is that a version which solves a pair keeps its
        claim to it, so a later version that loses the pair cannot quietly take it off the board.
        """
        winners: dict[str, str] = {}
        for payload in _read_jsonl(self.path):
            if str(payload.get("family")) != family or str(payload.get("outcome")) != "pair_correct":
                continue
            winners.setdefault(str(payload.get("pair")), str(payload.get("config_version")))
        return winners


def _read_jsonl(path: Path) -> list[Mapping[str, object]]:
    if not path.is_file():
        return []
    rows: list[Mapping[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def summarize(records: Sequence[RoundRecord]) -> dict[str, object]:
    """What the rounds add up to: how often a prediction landed, and what it cost."""
    accepted = [item for item in records if item.outcome == "accepted"]
    predicted = sum(item.attribution.flipped_predicted for item in records)
    unpredicted = sum(item.attribution.flipped_unpredicted for item in records)
    return {
        "rounds": len(records),
        "accepted": len(accepted),
        "flipped_predicted": predicted,
        "flipped_unpredicted": unpredicted,
        "prediction_precision": predicted / (predicted + unpredicted) if predicted + unpredicted else 0.0,
        "cost_usd": round(sum(item.cost_usd for item in records), 4),
    }


__all__ = ["Archive", "Attribution", "JournalError", "LearningJournal", "Outcome", "RoundRecord", "summarize"]
