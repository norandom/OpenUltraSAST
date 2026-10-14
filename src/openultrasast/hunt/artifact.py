"""Content-addressed run metadata and budget accounting without a model runtime."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .table import canonical_json


def _exhausted(usage: Mapping[str, float], budget: Mapping[str, float]) -> bool:
    for name in ("usd", "calls"):
        if name in budget:
            bound = budget[name]
            if not math.isfinite(bound) or bound < 0:
                raise ValueError("budget bounds must be finite and non-negative")
            if usage.get(name, 0) >= bound:
                return True
    return False


@dataclass
class RunArtifact:
    program_id: str
    schema_version: int
    mask: tuple[str, ...] | list[str]
    data_digests: dict[str, str]
    configurations: list[dict[str, Any]]
    usage: dict[str, float]
    versions: dict[str, str]
    created: str

    @property
    def artifact_id(self) -> str:
        return hashlib.sha256(canonical_json(asdict(self)).encode("utf-8")).hexdigest()

    def finish(self, budget: Mapping[str, float]) -> RunArtifact | None:
        """Return no completed artifact when either registered budget is exhausted."""
        return None if _exhausted(self.usage, budget) else self

    def write(self, directory: Path | str, *, budget: Mapping[str, float] | None = None) -> Path | None:
        """Write metadata under its content id, after an optional final budget check."""
        if budget is not None and self.finish(budget) is None:
            return None
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.artifact_id}.json"
        path.write_text(canonical_json({**asdict(self), "artifact_id": self.artifact_id}) + "\n", encoding="utf-8")
        return path

    @classmethod
    def read(cls, path: Path | str) -> RunArtifact:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        identifier = payload.pop("artifact_id", None)
        payload["mask"] = tuple(payload["mask"])
        artifact = cls(**payload)
        if identifier != artifact.artifact_id:
            raise ValueError("run artifact id does not match its contents")
        return artifact


@dataclass
class UsageLedger:
    """Count paid calls, replay hits, spend and elapsed call time separately."""

    artifact: RunArtifact | None = None
    rows: list[dict[str, float]] = field(default_factory=list)

    @property
    def usage(self) -> dict[str, float]:
        return {name: sum(row[name] for row in self.rows) for name in ("usd", "calls", "replay_hits", "wall_seconds")}

    def add(self, call_row: Mapping[str, Any]) -> None:
        replay_hits = call_row.get("replay_hits", int(bool(call_row.get("replay_hit", False))))
        values = {
            "usd": call_row.get("usd", 0),
            "calls": call_row.get("calls", 0 if replay_hits else 1),
            "replay_hits": replay_hits,
            "wall_seconds": call_row.get("wall_seconds", 0),
        }
        if any(not isinstance(v, int | float) or not math.isfinite(v) or v < 0 for v in values.values()):
            raise ValueError("usage values must be finite and non-negative")
        if any(int(values[k]) != values[k] for k in ("calls", "replay_hits")):
            raise ValueError("call and replay counts must be integers")
        self.rows.append(values)

    def exhausted(self, budget: Mapping[str, float]) -> bool:
        return _exhausted(self.usage, budget)

    def finish(self, budget: Mapping[str, float], artifact: RunArtifact | None = None) -> RunArtifact | None:
        """Attach measured usage to a completed run, or retain only this partial ledger."""
        if self.exhausted(budget):
            return None
        result = artifact if artifact is not None else self.artifact
        if result is None:
            raise ValueError("finish needs a run artifact")
        result.usage = self.usage
        return result
