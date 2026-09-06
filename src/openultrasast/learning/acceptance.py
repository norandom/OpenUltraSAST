"""When a round is kept, and how it is undone (learning-harness, Req 6.2, 9.5).

A round is accepted only when the family it targets does not go backwards on either the train or the
held-out pairs, at least one of them moves forward, and no other family flips more pairs than that
family showed against itself in round zero. A tie is a rejection: accepting one would let the loop
wander on noise and call it progress.

A family with no measured floor gets no budget. Unmeasured is not the same as unlimited, and the
alternative is a family that never ran in round zero quietly absorbing every regression.

Undoing is a directory restored byte for byte, files the round added removed, files it deleted put back.
A revert that only rewrites what it can see is not a revert.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .rounds import NoiseFloor


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: str
    offenders: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"accepted": self.accepted, "reason": self.reason, "offenders": list(self.offenders)}


def decide(
    *,
    target: str,
    train_delta: float,
    holdout_delta: float,
    sweep: Mapping[str, int],
    floors: Mapping[str, NoiseFloor],
) -> Verdict:
    """The acceptance rule, in one place, so no caller can soften it."""
    if train_delta < 0:
        return Verdict(accepted=False, reason="train_regressed")
    if holdout_delta < 0:
        return Verdict(accepted=False, reason="holdout_regressed")
    if train_delta == 0 and holdout_delta == 0:
        return Verdict(accepted=False, reason="tie")
    offenders = tuple(
        family for family, flips in sorted(sweep.items()) if family != target and _gates(family, floors) and flips > _budget(family, floors)
    )
    if offenders:
        return Verdict(accepted=False, reason="collateral_regression", offenders=offenders)
    return Verdict(accepted=True, reason="improved")


@dataclass(frozen=True)
class Reliability:
    """Whether a stage's movement could be told from a coin flip."""

    better: int
    worse: int
    p_value: float
    reliable: bool

    def to_dict(self) -> dict[str, object]:
        return {"better": self.better, "worse": self.worse, "p_value": self.p_value, "reliable": self.reliable}


def reliability(*, better: int, worse: int, alpha: float = 0.05) -> Reliability:
    """The two-sided sign test over the pairs that changed, for the record rather than for the decision.

    `decide` compares raw deltas, as Req 9.5 specifies. On a detector whose measured floor says half its pairs
    disagree with themselves between runs, a raw delta is mostly noise — which is what makes a deterministic
    decoder look necessary. It is not: the alternative is an acceptance rule that models the score as noisy, the
    way reflective-evolution and Bayesian prompt optimizers do, and keeps per-instance winners on a frontier
    instead of demanding a single global improvement. Changing the rule is a maintainer's call, so every round
    records this beside its decision and the journal can be read to answer the question with data.
    """
    from .scoring import sign_test

    p_value = sign_test(better, worse)
    return Reliability(better=better, worse=worse, p_value=p_value, reliable=bool(p_value < alpha and better != worse))


def _gates(family: str, floors: Mapping[str, NoiseFloor]) -> bool:
    floor = floors.get(family)
    return floor.gates if floor is not None else True


def _budget(family: str, floors: Mapping[str, NoiseFloor]) -> int:
    floor = floors.get(family)
    return floor.budget_flips if floor is not None else 0


def within_budget(spent_usd: float, cap_usd: float) -> bool:
    """A round may spend up to its cap; crossing it reverts the round rather than finishing it."""
    return spent_usd <= cap_usd


@dataclass(frozen=True)
class DirectorySnapshot:
    """Every file of one directory as it was, so a rejected round leaves nothing behind."""

    directory: Path
    files: tuple[tuple[str, bytes], ...]

    @staticmethod
    def of(directory: Path) -> DirectorySnapshot:
        entries = [(path.relative_to(directory).as_posix(), path.read_bytes()) for path in sorted(directory.rglob("*")) if path.is_file()]
        return DirectorySnapshot(directory=directory, files=tuple(entries))

    def restore(self) -> None:
        kept = {name for name, _ in self.files}
        for path in sorted(self.directory.rglob("*"), reverse=True):
            if path.is_file() and path.relative_to(self.directory).as_posix() not in kept:
                path.unlink()
        for name, content in self.files:
            target = self.directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


def digest_configs(configs_dir: Path) -> dict[str, str]:
    """One digest per family directory, so an untouched family can be shown to be untouched."""
    digests: dict[str, str] = {}
    for directory in sorted(path for path in configs_dir.iterdir() if path.is_dir()) if configs_dir.is_dir() else []:
        digest = hashlib.sha256()
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(directory).as_posix().encode())
                digest.update(path.read_bytes())
        digests[directory.name] = digest.hexdigest()
    return digests


def bump_version(directory: Path, version: str) -> None:
    """Write the accepted version into this family's settings, and only this family's."""
    settings = directory / "family.toml"
    lines = settings.read_text(encoding="utf-8").splitlines()
    rewritten = [f'version = "{version}"' if line.strip().startswith("version") else line for line in lines]
    settings.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


__all__ = ["DirectorySnapshot", "Reliability", "Verdict", "bump_version", "decide", "digest_configs", "reliability", "within_budget"]
