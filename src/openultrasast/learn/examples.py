"""The example store: the decision engine's local memory (learned-decision-engine design section 4.2, Req 3.2, 3.6).

No model. ``ousast learn memory build`` joins each verified label (``ousast learn labels``) with the feature record of
the same candidate and an excerpt of its function at the label's pin, and writes one ``example`` row per candidate
into the memory store, with the excerpt as a content-addressed blob ``excerpts/<sha>.txt``::

    envelope (id, kind=example, repo, pin, run, task, population=<source>, split, image)
    + {candidate, family, language, profile, label, source, group, frameworks, unit, direction, pin_role, weight,
       license, x, instruments, roles, excerpt_sha, label_set_digest}

Memory examples carry **no rationale** (code, signals, roles, family and label only). Refusals are loud:

- a row with ``origin: user`` (the opt-in adaptation layer never enters the generalisation memory, Req 7.5) or a
  source that ``sources.toml`` does not list stops the build (:class:`ExampleBuildError`);
- conditional rows (``benign_control``, ``assumed_benign``) are skipped until their condition is evaluated;
- a candidate whose excerpt is empty or whose function is not found is never stored; when more than 10% of a
  source's recorded candidates have no excerpt the build fails that source (exit 2 in the CLI): an unread clone is
  not a small memory. A fixed side whose file was read but no longer declares the labelled function is a label
  defect, counted apart as ``absent_fixed_side`` (the label builder emits a fixed-side negative only where the fixed
  side declares its candidate function, so this count should stay 0). A pair label names the function its side
  declares -- the labelled one, or the renamed one of a ``fixed_side_moved`` negative -- never the catalog's
  ``fix_function`` (a different handler of the same snapshot).

Pair labels have no commit pin (the corpus holds excerpts); their envelope pin is :func:`label_pin`, a stable
40-hex digest of the pair and its side, so the vulnerable and the fixed side stay distinct rows. The harvest keyed a
pair side's feature record by its unit's pin instead (the blob sha1 of the side's excerpt, ``plane/harvest.py``):
:func:`pair_pins` reads that mapping from the harvest ``units.json`` and the build uses it when given.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..plane.memory import MemoryStore, repo_key, row_id
from .excerpt import EXAMPLE, Bounds, delta_diff, excerpt, function_bounds, identities_of
from .labels import Label, Sources

EXAMPLE_KIND = "example"
RUN = "learn-memory"
TASK = "build"
IMAGE = "host"
NO_EXCERPT_LIMIT = 0.10
DERIVED_SOURCES = {"benign_control": "population"}  # sources the label builder derives from a listed source
_PIN = re.compile(r"[0-9a-f]{40}")


class ExampleBuildError(RuntimeError):
    """A label the memory must not hold (``origin: user``, a source outside ``sources.toml``) or a source whose
    excerpts could not be read."""


def label_pin(label: Mapping[str, Any]) -> str:
    """The envelope pin of a label: its commit, or for a pair (no commit) a stable digest of pair and side."""
    pin = str(label.get("pin") or "")
    if _PIN.fullmatch(pin):
        return pin
    subject = f"{label.get('source')}:{label.get('source_ref')}:{label.get('pin_role', 'vulnerable')}"
    return hashlib.sha1(subject.encode("utf-8")).hexdigest()  # noqa: S324 -- a name, not a security digest


def pair_pins(units: Mapping[str, Mapping[str, Any]]) -> dict[tuple[str, str], str]:
    """Harvest ``units.json`` -> ``(case reference, side) -> pin`` for the pair units (the pin their records carry)."""
    return {(str(u["ref"]), str(u["side"])): str(u["pin"]) for u in units.values() if u.get("source") == "pairs"}


def record_key(repo: str, pin: str, candidate: str, family: str, unit: str) -> tuple[str, str, str, str, str]:
    return repo_key(repo), pin, candidate, family, unit


def _as_dict(label: Label | Mapping[str, Any]) -> dict[str, Any]:
    return asdict(label) if isinstance(label, Label) else dict(label)


def label_set_digest(labels: Iterable[Label | Mapping[str, Any]]) -> str:
    lines = sorted(json.dumps(_as_dict(row), sort_keys=True, default=list) for row in labels)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


@dataclass
class SourceCount:
    labels: int = 0
    no_record: int = 0
    recorded: int = 0
    no_excerpt: int = 0  # unread side, or the labelled function not found where it must be (counts to the 10%)
    unread: int = 0
    absent_fixed_side: int = 0  # file read, the function is gone at the fix: a label defect, reported apart
    examples: int = 0


@dataclass
class MemoryBuild:
    rows: list[dict[str, Any]] = field(default_factory=list)
    sources: dict[str, SourceCount] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def failing(self, limit: float = NO_EXCERPT_LIMIT) -> list[str]:
        """Sources where more than ``limit`` of the recorded candidates have no excerpt."""
        return sorted(s for s, c in self.sources.items() if c.recorded and c.no_excerpt / c.recorded > limit)

    def summary(self) -> dict[str, Any]:
        return {
            "examples": len(self.rows),
            "by_source": {s: asdict(c) for s, c in sorted(self.sources.items())},
            "skipped": dict(sorted(self.skipped.items())),
            "failing_sources": self.failing(),
        }


LinesOf = Callable[[Mapping[str, Any], str], Sequence[str] | None]  # (label, pin_role) -> file lines at that side


def _counter_role(label: Mapping[str, Any]) -> str:
    return "vulnerable" if label.get("pin_role") == "fixed" else "fixed"


def build_examples(
    labels: Iterable[Label | Mapping[str, Any]],
    records: Mapping[tuple[str, str, str, str, str], Mapping[str, Any]],
    lines_of: LinesOf,
    *,
    sources: Sources,
    store: MemoryStore | None = None,
    profile: str = "static",
    roles_of: Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]] | None = None,
    license_of: Callable[[Mapping[str, Any]], str] | None = None,
    function_of: Callable[[Mapping[str, Any], str], str | None] | None = None,
    bounds: Bounds = EXAMPLE,
    pins: Mapping[tuple[str, str], str] | None = None,
) -> MemoryBuild:
    """Example rows for the verified labels that have a feature record (``records`` by :func:`record_key`) and an
    excerpt; with ``store`` the excerpt blobs and the rows are written. Delta units append the base->head diff.
    ``pins`` (:func:`pair_pins`) gives a pair side the pin its harvest record was stored under."""
    rows = [_as_dict(label) for label in labels]
    allowed = {s.id for s in sources.sources} | {d for d, kind in DERIVED_SOURCES.items() if any(s.kind == kind for s in sources.sources)}
    for row in rows:
        if row.get("origin") == "user":
            raise ExampleBuildError(f"label {row.get('candidate')!r} has origin: user -- the adaptation layer never enters the memory")
        if row.get("source") not in allowed:
            raise ExampleBuildError(f"label source {row.get('source')!r} is not in {sources.path}: it cannot enter the memory")
    digest = label_set_digest(rows)
    build = MemoryBuild()
    for label in rows:
        if label.get("conditional") is not None or label.get("source") == "assumed_benign":
            build.skip("conditional label (condition not evaluated)")
            continue
        count = build.sources.setdefault(str(label["source"]), SourceCount())
        count.labels += 1
        side = (str(label.get("source_ref")), str(label.get("pin_role") or "vulnerable"))
        pin = (pins or {}).get(side) if label.get("source") == "pairs" else None
        pin = pin or label_pin(label)
        candidate, family, unit = str(label["candidate"]), str(label["family"]), str(label["unit"])
        record = records.get(record_key(str(label["repo"]), pin, candidate, family, unit))
        if record is None or record.get("profile") != profile:
            count.no_record += 1
            continue
        count.recorded += 1
        path, _, function = candidate.partition("::")
        function = (function_of(label, str(label.get("pin_role") or "vulnerable")) if function_of else None) or function
        language = str(record.get("language") or label.get("language") or "other")
        identities = identities_of(str(label.get("repo") or ""), path, [str(label.get("pin") or "")])
        lines = lines_of(label, str(label.get("pin_role") or "vulnerable"))
        diff = None
        if unit == "delta" and lines:
            base = lines_of(label, _counter_role(label))
            head_span, base_span = function_bounds(lines, language, function), function_bounds(base or (), language, function)
            if base and head_span and base_span:
                diff = delta_diff(base[slice(*base_span)], lines[slice(*head_span)], language, identities=identities)
        shown = excerpt(lines, language, function, bounds=bounds, identities=identities, diff=diff)
        if shown is None:
            if not lines:
                count.unread += 1
            elif label.get("pin_role") == "fixed":
                count.absent_fixed_side += 1
                continue
            count.no_excerpt += 1
            continue
        if store is not None:
            store.put_blob("excerpts", shown.text.encode("utf-8"))
        subject = f"{candidate}\x00{family}\x00{unit}\x00{label.get('pin_role')}\x00{label.get('source_ref')}"
        build.rows.append(
            {
                "id": row_id(EXAMPLE_KIND, RUN, TASK, f"{label['repo']}\x00{pin}\x00{subject}"), "kind": EXAMPLE_KIND,
                "repo": repo_key(str(label["repo"])), "pin": pin, "run": RUN, "task": TASK, "population": str(label["source"]),
                "split": str(label.get("split") or label["source"]), "image": IMAGE,
                "candidate": candidate, "family": family, "language": language, "profile": profile, "label": int(label["label"]),
                "source": str(label["source"]), "group": str(label.get("group") or ""),
                "frameworks": list(label["frameworks"]) if label.get("frameworks") is not None else None, "unit": unit,
                "direction": label.get("direction"), "pin_role": label.get("pin_role", "vulnerable"),
                "weight": float(label.get("weight", 1.0)), "license": (license_of(label) if license_of else "") or "",
                "x": dict(record["x"]), "instruments": dict(record["instruments"]),
                "roles": list(roles_of(label)) if roles_of else [], "excerpt_sha": shown.sha, "label_set_digest": digest,
            }
        )  # fmt: skip
        count.examples += 1
    if store is not None and build.rows:
        store.put_rows(build.rows)
    return build


@dataclass(frozen=True)
class Example:
    """An example row as retrieval and the program use it (no envelope identity beyond ``id`` and ``group``)."""

    id: str
    group: str
    source: str
    frameworks: tuple[str, ...]
    family: str
    label: int
    language: str
    profile: str
    unit: str
    x: Mapping[str, Any]
    instruments: Mapping[str, Mapping[str, Any]]
    roles: tuple[Mapping[str, Any], ...]
    excerpt_sha: str
    license: str = ""

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Example:
        return cls(
            id=str(row["id"]), group=str(row.get("group") or ""), source=str(row["source"]), frameworks=tuple(row.get("frameworks") or ()),
            family=str(row["family"]), label=int(row["label"]), language=str(row.get("language") or "other"),
            profile=str(row.get("profile") or "static"), unit=str(row.get("unit") or "pin"), x=dict(row["x"]),
            instruments={k: dict(v) for k, v in row["instruments"].items()}, roles=tuple(row.get("roles") or ()),
            excerpt_sha=str(row["excerpt_sha"]), license=str(row.get("license") or ""),
        )  # fmt: skip


def load_examples(store: MemoryStore, profile: str | None = None) -> list[Example]:
    """Every example row in the store (optionally one profile), in key then id order."""
    where = {"profile": profile} if profile else None
    return [Example.from_row(r.row) for r in store.rows(kind=EXAMPLE_KIND, where=where)]


# --- reading the label sides --------------------------------------------------------------------------------------------


class SideReader:
    """File lines of a label's side, read-only: pairs from the corpus excerpts, populations and adjudications from
    their clones (``git show pin:path``), development recipes from their checkouts. ``None`` when unread."""

    def __init__(self, root: Path, cache: Path, sources: Sources, labels: Sequence[Mapping[str, Any]]) -> None:
        from .labels import Clone

        self.root, self.cache, self.sources = Path(root), Path(cache), sources
        self._pairs: dict[str, Any] | None = None
        self._clones: dict[str, Clone | None] = {}
        self._case_of: dict[str, str] = {}
        for label in labels:
            source = next((s for s in sources.sources if s.id == label.get("source")), None)
            if source is not None and source.kind == "population":
                self._case_of.setdefault(str(label.get("repo")), f"{source.options.get('cache', 'independent')}/{label.get('source_ref')}")

    def _pair_cases(self) -> dict[str, Any]:
        if self._pairs is None:
            from ..pairs import load_pair_catalog

            source = next(s for s in self.sources.sources if s.kind == "pairs")
            self._pairs = {case.name: case for case in load_pair_catalog(self.root / source.files[0])}
        return self._pairs

    def license(self, label: Mapping[str, Any]) -> str:
        if label.get("source") != "pairs":
            return ""
        case = self._pair_cases().get(str(label.get("source_ref")))
        return str(getattr(case, "license", "") or "")

    def __call__(self, label: Mapping[str, Any], pin_role: str) -> list[str] | None:
        from .labels import Clone, LabelSourceError

        source = str(label.get("source"))
        path = str(label.get("candidate", "")).partition("::")[0]
        if source == "pairs":
            case = self._pair_cases().get(str(label.get("source_ref")))
            if case is None:
                return None
            file = case.vuln_file if pin_role == "vulnerable" else case.fixed_file
            return Path(file).read_text(encoding="utf-8", errors="replace").splitlines() if Path(file).is_file() else None
        if source == "dev-php":
            name = str(label.get("source_ref", "")).partition(":")[0]
            file = self.cache / "repos" / name / str(label.get("pin"))[:12] / path
            return file.read_text(encoding="utf-8", errors="replace").splitlines() if file.is_file() else None
        case_dir = self._case_of.get(str(label.get("repo")))
        if case_dir is None:
            return None
        if case_dir not in self._clones:
            try:
                self._clones[case_dir] = Clone(self.cache / case_dir)
            except LabelSourceError:
                self._clones[case_dir] = None
        clone = self._clones[case_dir]
        return clone.lines(str(label.get("pin")), path) if clone is not None else None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def records_by_key(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
    """Feature records (``features`` rows of the store, or records with ``repo`` and ``pin`` beside them) by
    :func:`record_key`."""
    out: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = record_key(str(row["repo"]), str(row["pin"]), str(row["candidate"]), str(row["family"]), str(row.get("unit", "pin")))
        out[key] = dict(row)
    return out


__all__ = [
    "EXAMPLE_KIND", "NO_EXCERPT_LIMIT", "Example", "ExampleBuildError", "MemoryBuild", "SideReader", "build_examples",
    "label_pin", "label_set_digest", "load_examples", "pair_pins", "read_jsonl", "record_key", "records_by_key",
]  # fmt: skip
