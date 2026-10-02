"""A/B experiments over the decision engine and the plane (learned-decision-engine design section 6, Requirement 4).

Nothing is adopted on one run's number. An experiment is a **manifest** (``plane/experiments/<id>.yaml``) declared
before it runs: hypothesis, two or more **arms** (program variants: a compiled program id plus ``ProgramSpec``
overrides; or plane Run configurations as ``task_env``), the unit of randomisation, pairing, the resampling cluster,
the metrics, the minimum detectable effect, the sequential rule, the budget ceiling in USD, the families and the
folds, and a frozen **units file**. :func:`register` records the sha256 of the manifest and of the units file as an
``experiment`` row; :func:`run` and :func:`analyse` refuse a manifest that is not registered or whose digest differs
from the registered one, so a question cannot be changed after looking at an answer.

**Run.** Every unit runs in every arm (paired) in a seeded order of repositories; a seeded per-unit coin decides which
arm goes first, so provider drift over a run never aligns with arms. An arm is a :class:`.program.Program` over the
same memory and folds as the incumbent's evaluation; arm A replays the incumbent's cached responses at $0 when the
manifest says ``replay_only``, and a paid arm runs under its own ceiling. An arm with ``repeats: 2`` decides every
unit twice under different response-cache salts (the canary: do two runs agree?). Each decision is one
``arm_outcome`` row (unit, arm, replicate, score, verdict, usd); a stopped run resumes from the rows it has.

**Analyse.** Per-unit paired outcomes of arms A and B; the estimate is the paired difference B - A of a metric
(AUC, within-pair AUC, ADVISORY recall and precision, canary agreement, flag rate, usd per candidate) with a 95% CI
from a repository-cluster bootstrap (resampling repositories with the units inside them, since units of one
repository are correlated), an exact McNemar test on the discordant units beside it for binary outcomes, two looks
(half and all of the repositories, in the pre-shuffled order) with O'Brien-Fleming boundaries (|z| >= 2.797, then
1.977), and the adoption rule: **adopt B** when the final CI of the first primary excludes 0 in B's favour and no
other primary's CI excludes 0 against B; **reject B** when any primary's CI excludes 0 against B; for a cost-only
change (``test.cost_only``) **equivalent** when the TOST 90% CI of the detection difference lies within the margin
and the cost CI shows a saving; otherwise **inconclusive**, and the incumbent stays. The result is an
``experiment_result`` row and ``benchmarks/experiments/<id>/result.json`` (counts and intervals only).
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

import yaml

from ..plane.budget import BudgetExhausted
from ..plane.memory import MemoryStore, row_id
from .compile import load_program, spec_of
from .evaluate import candidate_from_example
from .examples import EXAMPLE_KIND, Example
from .folds import Fold, compile_split, folds_digest, outer_folds
from .program import Caller, Decision, Program, ProgramSpec

MANIFEST_DIR = Path("plane/experiments")
RESULT_DIR = Path("benchmarks/experiments")
EXPERIMENT_KIND = "experiment"
OUTCOME_KIND = "arm_outcome"
RESULT_KIND = "experiment_result"
REGISTER_TASK = "register"
POPULATION = "experiments"  # the envelope of every experiment row; `split` is the experiment id
RUN_TASK = "run"
ARM_KINDS = ("program", "plane")
UNITS = ("candidate", "file", "repository")
PAIRINGS = ("paired", "assigned")
# O'Brien-Fleming boundaries for two equally spaced looks at alpha 0.05, two-sided (design section 6).
OBF_TWO_LOOKS: Mapping[float, float] = {0.5: 2.797, 1.0: 1.977}
RESAMPLES = 10_000
ALPHA = 0.05
TOST_MARGIN = 0.05
ADVISORY_VERDICT = "vulnerable"
# metric name -> (direction: +1 higher is better, -1 lower is better; binary per unit: McNemar applies)
METRICS: Mapping[str, tuple[int, bool]] = {
    "auc": (1, False),
    "within_pair_auc": (1, False),
    "advisory_recall": (1, True),
    "advisory_precision": (1, False),
    "canary_agreement": (1, True),
    "flag_rate": (1, True),
    "usd_per_candidate": (-1, False),
}
VERDICTS = ("adopt", "reject", "equivalent", "inconclusive")


class ExperimentError(RuntimeError):
    """A manifest that cannot be run as declared: malformed, unregistered, modified, or not a program experiment."""


# --- the manifest ------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Arm:
    name: str
    label: str = ""
    programs: Mapping[str, str] = field(default_factory=dict)  # family -> compiled program id (program arms)
    spec: Mapping[str, Any] = field(default_factory=dict)  # ProgramSpec overrides, the declared difference
    task_env: Mapping[str, str] = field(default_factory=dict)  # plane arms: the Run's task environment
    replay_only: bool = False
    repeats: int = 1
    budget_usd: float = 0.0


@dataclass(frozen=True)
class Metric:
    name: str
    label: int | None = None  # restrict to units of this label (``flag_rate[label=1]``)
    target: float | None = None  # a level B must reach, reported beside the test

    @classmethod
    def parse(cls, text: str | Mapping[str, Any]) -> Metric:
        if isinstance(text, Mapping):
            return cls(str(text["name"]), text.get("label"), text.get("target"))
        name, _, rest = str(text).partition("[")
        label = None
        if rest:
            key, _, value = rest.rstrip("]").partition("=")
            if key != "label":
                raise ExperimentError(f"metric {text!r}: only a [label=0|1] selector is understood")
            label = int(value)
        return cls(name, label)

    @property
    def direction(self) -> int:
        return METRICS[self.name][0]

    @property
    def binary(self) -> bool:
        return METRICS[self.name][1]

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class Manifest:
    id: str
    hypothesis: str
    kind: str
    arms: Mapping[str, Arm]
    unit: str
    pairing: str
    cluster: str
    seed: int
    primary: tuple[Metric, ...]
    secondary: tuple[Metric, ...]
    alpha: float
    resamples: int
    cost_only: bool
    tost_margin: float
    mde: float
    looks: tuple[float, ...]
    boundaries: tuple[float, ...]
    budget_total_usd: float
    families: tuple[str, ...]
    folds: Mapping[str, Any]
    units_file: Path
    programs: Mapping[str, str]
    path: Path
    digest: str
    raw: Mapping[str, Any]

    @property
    def paid_arms(self) -> list[str]:
        return [a for a, arm in self.arms.items() if not arm.replay_only]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _boundaries(looks: Sequence[float], boundary: str, explicit: Sequence[float] | None) -> tuple[float, ...]:
    if explicit is not None:
        if len(explicit) != len(looks):
            raise ExperimentError("stopping.boundaries must give one z per look")
        return tuple(float(z) for z in explicit)
    if boundary != "obrien_fleming":
        raise ExperimentError(f"stopping.boundary {boundary!r}: only obrien_fleming, or explicit boundaries")
    if tuple(looks) != (0.5, 1.0):
        raise ExperimentError("obrien_fleming boundaries are tabulated for looks [0.5, 1.0] only; give stopping.boundaries")
    return tuple(OBF_TWO_LOOKS[look] for look in looks)


def load_manifest(path: Path) -> Manifest:
    """Parse and validate a manifest; its ``digest`` is the sha256 of the file bytes (register and run compare it)."""
    data = path.read_bytes()
    raw = yaml.safe_load(data)
    if not isinstance(raw, Mapping):
        raise ExperimentError(f"{path}: a manifest is a mapping")
    try:
        kind = str(raw.get("kind", "program"))
        if kind not in ARM_KINDS:
            raise ExperimentError(f"{path}: kind {kind!r} (one of {', '.join(ARM_KINDS)})")
        arms = {
            str(name): Arm(
                str(name),
                str(spec.get("label", "")),
                {str(k): str(v) for k, v in (spec.get("programs") or {}).items()},
                dict(spec.get("spec") or {}),
                {str(k): str(v) for k, v in (spec.get("task_env") or {}).items()},
                bool(spec.get("replay_only", False)),
                int(spec.get("repeats", 1)),
                float(spec.get("budget_usd", 0.0)),
            )  # fmt: skip
            for name, spec in dict(raw["arms"]).items()
        }
        if len(arms) < 2 or "A" not in arms or "B" not in arms:
            raise ExperimentError(f"{path}: arms A and B are required (A is the incumbent)")
        unknown = {k for arm in arms.values() for k in arm.spec} - {f.name for f in fields(ProgramSpec)}
        if unknown:
            raise ExperimentError(f"{path}: arm spec overrides {sorted(unknown)} are not ProgramSpec fields")
        metric = dict(raw["metric"])
        primary_raw = metric["primary"]
        primary = tuple(Metric.parse(m) for m in (primary_raw if isinstance(primary_raw, list) else [primary_raw]))
        secondary = tuple(Metric.parse(m) for m in metric.get("secondary", []))
        for m in (*primary, *secondary):
            if m.name not in METRICS:
                raise ExperimentError(f"{path}: metric {m.name!r} (one of {', '.join(METRICS)})")
        test = dict(raw.get("test") or {})
        stopping = dict(raw.get("stopping") or {"looks": [1.0], "boundaries": [1.959964]})
        looks = tuple(float(x) for x in stopping.get("looks", [0.5, 1.0]))
        if looks[-1] != 1.0 or any(b <= a for a, b in zip(looks, looks[1:], strict=False)) or looks[0] <= 0:
            raise ExperimentError(f"{path}: stopping.looks must increase to 1.0")
        budget = raw["budget_usd"]
        total = float(budget["total"] if isinstance(budget, Mapping) else budget)
        arm_total = sum(a.budget_usd for a in arms.values())
        if arm_total > total + 1e-9:
            raise ExperimentError(f"{path}: the arms' ceilings ({arm_total}) exceed budget_usd.total ({total})")
        unit = str(raw.get("unit", "candidate"))
        pairing = str(raw.get("pairing", "paired"))
        if unit not in UNITS or pairing not in PAIRINGS:
            raise ExperimentError(f"{path}: unit in {UNITS} and pairing in {PAIRINGS}")
        if "units_file" not in raw:
            raise ExperimentError(f"{path}: units_file is required (the frozen list of units)")
        manifest = Manifest(
            id=str(raw["id"]), hypothesis=str(raw["hypothesis"]), kind=kind, arms=arms, unit=unit, pairing=pairing,
            cluster=str(raw.get("cluster", "repository")), seed=int((raw.get("order") or {}).get("seed", 0)),
            primary=primary, secondary=secondary, alpha=float(test.get("alpha", ALPHA)), resamples=int(test.get("resamples", RESAMPLES)),
            cost_only=bool(test.get("cost_only", False)), tost_margin=float(test.get("tost_margin", TOST_MARGIN)),
            mde=float(raw.get("mde", 0.0)), looks=looks,
            boundaries=_boundaries(looks, str(stopping.get("boundary", "obrien_fleming")), stopping.get("boundaries")),
            budget_total_usd=total, families=tuple(str(f) for f in raw.get("families", [])), folds=dict(raw.get("folds") or {}),
            units_file=Path(str(raw["units_file"])), programs={str(k): str(v) for k, v in (raw.get("programs") or {}).items()},
            path=path, digest=_digest(data), raw=raw,
        )  # fmt: skip
    except KeyError as exc:
        raise ExperimentError(f"{path}: missing {exc}") from exc
    if manifest.id != path.stem:
        raise ExperimentError(f"{path}: id {manifest.id!r} must equal the file stem")
    if kind == "program" and not manifest.families:
        raise ExperimentError(f"{path}: a program experiment names its families")
    return manifest


# --- register ------------------------------------------------------------------------------------------------------------


def committed_at_head(path: Path, cwd: Path | None = None) -> str | None:
    """HEAD's commit when ``path`` is tracked and unchanged against HEAD, else ``None``."""
    try:
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(path)], cwd=cwd, capture_output=True, text=True)
        changed = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", str(path)], cwd=cwd, capture_output=True, text=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True)
    except OSError:
        return None
    if tracked.returncode or changed.returncode or head.returncode:
        return None
    return head.stdout.strip() or None


def experiment_repo(experiment_id: str) -> str:
    return f"experiments/{experiment_id}"


def registration_id(experiment_id: str) -> str:
    return row_id(EXPERIMENT_KIND, f"experiment-{experiment_id}", REGISTER_TASK, experiment_id)


def registered(store: MemoryStore, experiment_id: str) -> dict[str, Any] | None:
    rows = [r.row for r in store.rows(repo=experiment_repo(experiment_id), kind=EXPERIMENT_KIND) if r.row.get("task") == REGISTER_TASK]
    return rows[0] if rows else None


def register(
    store: MemoryStore,
    manifest: Manifest,
    *,
    commit_of: Callable[[Path], str | None] | None = None,
    created: str = "",
) -> dict[str, Any]:
    """Record the manifest's and the units file's digests as the ``experiment`` row. Refuses a manifest that is not
    committed at HEAD, a units file that exists but is not committed, and a second registration under a different
    digest (a changed question is a new experiment id). A units file that does not exist yet is recorded as
    ``pending``: the experiment cannot run until it is frozen and registered."""
    check = commit_of or committed_at_head
    commit = check(manifest.path)
    if commit is None:
        raise ExperimentError(f"{manifest.path} is not committed at HEAD: commit the manifest before registering it")
    units_digest = ""
    if manifest.units_file.exists():
        if check(manifest.units_file) is None:
            raise ExperimentError(f"{manifest.units_file} is not committed at HEAD: commit the frozen units before registering")
        units_digest = _digest(manifest.units_file.read_bytes())
    previous = registered(store, manifest.id)
    if previous is not None and previous.get("manifest_digest") != manifest.digest:
        raise ExperimentError(
            f"{manifest.id} is registered under digest {str(previous.get('manifest_digest'))[:12]}; the file now hashes to "
            f"{manifest.digest[:12]}. A changed manifest is a new experiment: give it a new id"
        )
    if previous is not None and previous.get("units_digest") and previous.get("units_digest") != units_digest:
        raise ExperimentError(f"{manifest.id}: the units file changed after registration; a new units list is a new experiment")
    row = {
        "id": registration_id(manifest.id), "kind": EXPERIMENT_KIND, "repo": experiment_repo(manifest.id), "pin": commit,
        "run": f"experiment-{manifest.id}", "task": REGISTER_TASK, "population": POPULATION, "split": manifest.id, "image": "host",
        "experiment": manifest.id, "hypothesis": manifest.hypothesis, "manifest_path": str(manifest.path),
        "manifest_digest": manifest.digest, "units_file": str(manifest.units_file), "units_digest": units_digest,
        "units_status": "frozen" if units_digest else "pending", "arms": sorted(manifest.arms), "experiment_kind": manifest.kind,
        "primary": [m.as_dict() for m in manifest.primary], "secondary": [m.as_dict() for m in manifest.secondary],
        "mde": manifest.mde, "looks": list(manifest.looks), "boundaries": list(manifest.boundaries),
        "budget_total_usd": manifest.budget_total_usd, "families": list(manifest.families), "created": created,
        "status": "registered",
    }  # fmt: skip
    store.put_row(row)
    return row


def check_registered(store: MemoryStore, manifest: Manifest, *, need_units: bool = True) -> dict[str, Any]:
    """The registration row, or a refusal: unregistered, modified manifest, missing or modified units."""
    row = registered(store, manifest.id)
    if row is None:
        raise ExperimentError(f"{manifest.id} is not registered: `ousast learn experiment register {manifest.path}` first")
    if row.get("manifest_digest") != manifest.digest:
        raise ExperimentError(f"{manifest.path} differs from the registered manifest ({str(row.get('manifest_digest'))[:12]}); refusing")
    if need_units:
        if not manifest.units_file.exists():
            raise ExperimentError(f"{manifest.units_file} does not exist: freeze the units, commit, register again")
        if not row.get("units_digest"):
            raise ExperimentError(f"{manifest.id}: the units file was not registered (pending); register again with it committed")
        if _digest(manifest.units_file.read_bytes()) != row["units_digest"]:
            raise ExperimentError(f"{manifest.units_file} differs from the registered units; refusing")
    return row


# --- units ---------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Unit:
    unit: str  # the example id (program experiments) or the plane's unit key
    group: str  # the repository: the resampling cluster
    family: str
    label: int
    fold: str = ""
    pair: str = ""  # the two sides of one candidate (vulnerable and fixed pin) share it; "" when unpaired

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_units(path: Path) -> list[Unit]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            out.append(
                Unit(str(d["unit"]), str(d["group"]), str(d["family"]), int(d["label"]), str(d.get("fold", "")), str(d.get("pair", "")))
            )
    return out


def write_units(path: Path, units: Sequence[Unit]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(u.as_dict(), sort_keys=True) + "\n" for u in units)
    path.write_text(text, encoding="utf-8")
    return _digest(text.encode("utf-8"))


def program_folds(memory: Sequence[Example], manifest: Manifest) -> tuple[list[Fold], str]:
    """The incumbent evaluation's outer folds (compile split excluded) and their digest, from the manifest's ``folds``."""
    seed = int(manifest.folds.get("seed", 0))
    split = compile_split(memory, fraction=float(manifest.folds.get("compile_fraction", 0.25)), seed=seed)
    folds = outer_folds(memory, k=int(manifest.folds.get("k", 5)), seed=seed, exclude=split.groups)
    return folds, folds_digest(split, folds)


def freeze_units(store: MemoryStore, manifest: Manifest, memory: Sequence[Example]) -> list[Unit]:
    """The evaluation candidates of the manifest's families under the incumbent's outer folds, paired by candidate
    across the two pins where both sides are in memory (no model; the list is then committed and registered)."""
    if manifest.kind != "program":
        raise ExperimentError(f"{manifest.id}: units of a plane experiment come from candidate generation, not the memory")
    folds, _ = program_folds(memory, manifest)
    sides: dict[str, tuple[str, str, str]] = {}
    for record in store.rows(kind=EXAMPLE_KIND):
        row = record.row
        sides[str(row["id"])] = (str(row.get("repo", "")), str(row.get("candidate", "")), str(row.get("family", "")))
    chosen = [(e, f) for f in folds if f.status == "ok" for e in memory if e.group in f.eval_groups and e.family in manifest.families]
    by_side: dict[tuple[str, str, str], set[int]] = {}
    for e, _ in chosen:
        by_side.setdefault(sides.get(e.id, ("", e.id, e.family)), set()).add(e.label)
    units = []
    for e, f in chosen:
        side = sides.get(e.id, ("", e.id, e.family))
        pair = _digest("\x00".join(side).encode())[:16] if by_side[side] == {0, 1} and side[1] else ""
        units.append(Unit(e.id, e.group, e.family, e.label, f.name, pair))
    return sorted(units, key=lambda u: (u.group, u.family, u.unit))


# --- outcomes ------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """One decision: a unit under an arm, replicate ``r`` (0 is the run; 1 the canary re-run)."""

    unit: str
    group: str
    family: str
    label: int
    pair: str
    arm: str
    replicate: int
    s: float | None
    verdict: str
    usd: float | None = None
    parse_failed: int = 0
    order: int = 0  # which position the arm had for this unit (0 ran first)

    @property
    def flag(self) -> bool:
        return self.verdict == ADVISORY_VERDICT


def outcome_id(experiment_id: str, arm: str, unit: str, replicate: int) -> str:
    return row_id(OUTCOME_KIND, f"experiment-{experiment_id}", f"arm-{arm}", f"{unit}:{replicate}")


def outcome_row(experiment_id: str, pin: str, outcome: Outcome) -> dict[str, Any]:
    return {
        "id": outcome_id(experiment_id, outcome.arm, outcome.unit, outcome.replicate), "kind": OUTCOME_KIND,
        "repo": experiment_repo(experiment_id), "pin": pin, "run": f"experiment-{experiment_id}", "task": f"arm-{outcome.arm}",
        "population": POPULATION, "split": experiment_id, "image": "host", "experiment": experiment_id, **asdict(outcome),
    }  # fmt: skip


def outcome_from_row(row: Mapping[str, Any]) -> Outcome:
    return Outcome(
        str(row["unit"]), str(row["group"]), str(row["family"]), int(row["label"]), str(row.get("pair") or ""), str(row["arm"]),
        int(row.get("replicate", 0)), None if row.get("s") is None else float(row["s"]), str(row.get("verdict") or ""),
        None if row.get("usd") is None else float(row["usd"]), int(row.get("parse_failed", 0)), int(row.get("order", 0)),
    )  # fmt: skip


def load_outcomes(store: MemoryStore, experiment_id: str) -> list[Outcome]:
    return [outcome_from_row(r.row) for r in store.rows(repo=experiment_repo(experiment_id), kind=OUTCOME_KIND)]


@dataclass(frozen=True)
class ArmUnit:
    """A unit under one arm with its replicates folded in: the run's score and verdict, the mean cost, and whether
    the canary replicate agreed with the run."""

    unit: str
    group: str
    family: str
    label: int
    pair: str
    s: float | None
    verdict: str
    usd: float | None
    agree: bool | None

    @property
    def flag(self) -> bool:
        return self.verdict == ADVISORY_VERDICT


def arm_units(outcomes: Iterable[Outcome], arm: str) -> dict[str, ArmUnit]:
    by_unit: dict[str, list[Outcome]] = {}
    for o in outcomes:
        if o.arm == arm:
            by_unit.setdefault(o.unit, []).append(o)
    out = {}
    for unit, rows in by_unit.items():
        rows.sort(key=lambda o: o.replicate)
        first = rows[0]
        costs = [o.usd for o in rows if o.usd is not None]
        agree = None if len(rows) < 2 else rows[0].verdict == rows[1].verdict
        out[unit] = ArmUnit(unit, first.group, first.family, first.label, first.pair, first.s, first.verdict,
                            sum(costs) / len(costs) if costs else None, agree)  # fmt: skip
    return out


def paired_units(outcomes: Iterable[Outcome], a: str = "A", b: str = "B") -> list[tuple[ArmUnit, ArmUnit]]:
    """Units decided in both arms (replicate 0), in unit order; a unit one arm skipped is not a pair."""
    rows = list(outcomes)
    left, right = arm_units(rows, a), arm_units(rows, b)
    return [(left[u], right[u]) for u in sorted(left) if u in right]


# --- metrics -------------------------------------------------------------------------------------------------------------


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def auc(rows: Sequence[ArmUnit]) -> float | None:
    """Mann-Whitney AUC of the score against the label; ties count one half; ``None`` without both labels."""
    pos = sorted(r.s for r in rows if r.label == 1 and r.s is not None)
    neg = sorted(r.s for r in rows if r.label == 0 and r.s is not None)
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def within_pair_auc(rows: Sequence[ArmUnit]) -> float | None:
    """Of the candidate pairs (vulnerable and fixed side both present), the share where the vulnerable side scores
    higher (ties one half)."""
    pairs: dict[str, dict[int, float]] = {}
    for r in rows:
        if r.pair and r.s is not None:
            pairs.setdefault(r.pair, {})[r.label] = r.s
    done = [(p[1], p[0]) for p in pairs.values() if 0 in p and 1 in p]
    if not done:
        return None
    return sum(1.0 if v > f else 0.5 if v == f else 0.0 for v, f in done) / len(done)


def metric_value(metric: Metric, rows: Sequence[ArmUnit]) -> float | None:
    if metric.label is not None:
        rows = [r for r in rows if r.label == metric.label]
    name = metric.name
    if name == "auc":
        return auc(rows)
    if name == "within_pair_auc":
        return within_pair_auc(rows)
    if name == "advisory_recall":
        return _mean([float(r.flag) for r in rows if r.label == 1])
    if name == "advisory_precision":
        return _mean([float(r.label == 1) for r in rows if r.flag])
    if name == "canary_agreement":
        return _mean([float(r.agree) for r in rows if r.agree is not None])
    if name == "flag_rate":
        return _mean([float(r.flag) for r in rows])
    if name == "usd_per_candidate":
        return _mean([r.usd for r in rows if r.usd is not None])
    raise ExperimentError(f"unknown metric {name!r}")


def binary_value(metric: Metric, row: ArmUnit) -> bool | None:
    """The per-unit binary outcome behind a binary metric (McNemar's cell), or ``None`` when it does not apply."""
    if metric.label is not None and row.label != metric.label:
        return None
    if metric.name == "advisory_recall":
        return row.flag if row.label == 1 else None
    if metric.name == "canary_agreement":
        return row.agree
    if metric.name == "flag_rate":
        return row.flag
    return None


# --- statistics ----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Estimate:
    metric: str
    a: float | None
    b: float | None
    diff: float | None
    ci: tuple[float, float] | None  # percentile bootstrap, two-sided at alpha
    se: float | None
    units: int
    groups: int
    resamples: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def paired_bootstrap(
    pairs: Sequence[tuple[ArmUnit, ArmUnit]], metric: Metric, *, resamples: int = RESAMPLES, seed: int = 0, alpha: float = ALPHA
) -> Estimate:
    """The paired difference B - A with a percentile CI from a cluster bootstrap over repositories: each resample draws
    repositories with replacement and takes every paired unit inside them, in both arms."""
    by_group: dict[str, list[tuple[ArmUnit, ArmUnit]]] = {}
    for pair in pairs:
        by_group.setdefault(pair[0].group, []).append(pair)
    names = sorted(by_group)
    a_all = metric_value(metric, [p[0] for p in pairs])
    b_all = metric_value(metric, [p[1] for p in pairs])
    diff = None if a_all is None or b_all is None else b_all - a_all
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(resamples if names else 0):
        sample = [p for g in (rng.choice(names) for _ in names) for p in by_group[g]]
        a = metric_value(metric, [p[0] for p in sample])
        b = metric_value(metric, [p[1] for p in sample])
        if a is not None and b is not None:
            values.append(b - a)
    ci = se = None
    if len(values) >= 2:
        values.sort()
        ci = (values[int(alpha / 2 * (len(values) - 1))], values[int((1 - alpha / 2) * (len(values) - 1))])
        mean = sum(values) / len(values)
        se = math.sqrt(sum((v - mean) ** 2 for v in values) / (len(values) - 1))
    return Estimate(metric.name, a_all, b_all, diff, ci, se, len(pairs), len(names), len(values))


@dataclass(frozen=True)
class McNemar:
    """Exact McNemar: of the discordant pairs, ``b`` where only A has the outcome and ``c`` where only B has it;
    the two-sided p-value of a binomial test with p = 0.5."""

    b: int
    c: int
    concordant: int
    p_value: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def exact_mcnemar(table: Sequence[tuple[bool, bool]]) -> McNemar:
    b = sum(1 for x, y in table if x and not y)
    c = sum(1 for x, y in table if y and not x)
    n = b + c
    if n == 0:
        return McNemar(b, c, len(table), 1.0)
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return McNemar(b, c, len(table) - n, min(1.0, 2 * tail))


def mcnemar_for(pairs: Sequence[tuple[ArmUnit, ArmUnit]], metric: Metric) -> McNemar | None:
    if not metric.binary:
        return None
    table = []
    for a, b in pairs:
        x, y = binary_value(metric, a), binary_value(metric, b)
        if x is not None and y is not None:
            table.append((x, y))
    return exact_mcnemar(table) if table else None


def look_order(groups: Iterable[str], seed: int) -> list[str]:
    """The pre-shuffled repository order the looks (and a run) follow."""
    names = sorted(set(groups))
    random.Random(seed).shuffle(names)
    return names


@dataclass(frozen=True)
class Look:
    fraction: float
    groups: int
    boundary: float
    estimate: Estimate
    z: float | None
    crossed: bool

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["estimate"] = self.estimate.as_dict()
        return d


def sequential_looks(
    pairs: Sequence[tuple[ArmUnit, ArmUnit]], metric: Metric, manifest: Manifest, *, resamples: int | None = None
) -> list[Look]:
    """The estimate at each look (the first ceil(fraction * groups) repositories in the pre-shuffled order) against its
    O'Brien-Fleming boundary. A crossed boundary stops the sequence: later looks are not taken."""
    order = look_order((p[0].group for p in pairs), manifest.seed)
    out: list[Look] = []
    n = resamples if resamples is not None else manifest.resamples
    for fraction, boundary in zip(manifest.looks, manifest.boundaries, strict=True):
        taken = set(order[: math.ceil(fraction * len(order))])
        subset = [p for p in pairs if p[0].group in taken]
        est = paired_bootstrap(subset, metric, resamples=n, seed=manifest.seed, alpha=manifest.alpha)
        z = None if est.diff is None or not est.se else est.diff / est.se
        # no bootstrap variance with a non-zero difference (every repository moved the same way) crosses any boundary
        crossed = (z is not None and abs(z) >= boundary) or (est.se == 0 and bool(est.diff))
        out.append(Look(fraction, len(taken), boundary, est, z, crossed))
        if crossed:
            break
    return out


def excludes_zero(ci: tuple[float, float] | None, direction: int) -> str:
    """``favour`` when the CI lies on B's good side, ``against`` on the bad side, else ``spans``."""
    if ci is None:
        return "spans"
    lo, hi = ci if direction > 0 else (-ci[1], -ci[0])
    return "favour" if lo > 0 else "against" if hi < 0 else "spans"


def decide(manifest: Manifest, finals: Mapping[str, Estimate], cost: Estimate | None, tost: Estimate | None) -> tuple[str, str]:
    """The adoption rule (module docstring): verdict and the reason in one line."""
    sides = {m.name: excludes_zero(finals[m.name].ci, m.direction) for m in manifest.primary}
    if any(side == "against" for side in sides.values()):
        bad = [n for n, side in sides.items() if side == "against"]
        return "reject", f"the CI of {', '.join(bad)} excludes 0 against B"
    first = manifest.primary[0].name
    if sides[first] == "favour":
        return "adopt", f"the CI of {first} excludes 0 in B's favour and no primary CI excludes 0 against B"
    if manifest.cost_only and cost is not None and tost is not None and tost.ci is not None and cost.ci is not None:
        within = -manifest.tost_margin <= tost.ci[0] and tost.ci[1] <= manifest.tost_margin
        saving = cost.ci[1] < 0
        if within and saving:
            return "equivalent", f"the TOST 90% CI of {tost.metric} lies within +-{manifest.tost_margin} and the cost CI shows a saving"
    return "inconclusive", f"the CI of {first} spans 0; the incumbent stays"


def analyse(
    manifest: Manifest, outcomes: Sequence[Outcome], *, resamples: int | None = None, provenance: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Counts and intervals only: per-metric final estimates, McNemar where the outcome is binary, the looks of the
    first primary, the adoption verdict."""
    pairs = paired_units(outcomes)
    n = resamples if resamples is not None else manifest.resamples
    finals: dict[str, Estimate] = {}
    tests: dict[str, Any] = {}
    for metric in (*manifest.primary, *manifest.secondary):
        est = paired_bootstrap(pairs, metric, resamples=n, seed=manifest.seed, alpha=manifest.alpha)
        finals[metric.name] = est
        mc = mcnemar_for(pairs, metric)
        tests[metric.name] = {
            "estimate": est.as_dict(), "mcnemar": mc.as_dict() if mc else None, "direction": metric.direction,
            "ci_vs_zero": excludes_zero(est.ci, metric.direction),
            "target": None if metric.target is None else {"level": metric.target, "b_meets": est.b is not None and est.b >= metric.target},
        }  # fmt: skip
    looks = sequential_looks(pairs, manifest.primary[0], manifest, resamples=n) if pairs else []
    cost = finals.get("usd_per_candidate")
    tost = None
    if manifest.cost_only:
        detection = next((m for m in (*manifest.primary, *manifest.secondary) if m.name != "usd_per_candidate"), None)
        if detection is not None:
            tost = paired_bootstrap(pairs, detection, resamples=n, seed=manifest.seed, alpha=0.10)
    verdict, reason = decide(manifest, finals, cost, tost) if pairs else ("inconclusive", "no paired units")
    arms = sorted({o.arm for o in outcomes})
    spend = {arm: round(sum(o.usd or 0.0 for o in outcomes if o.arm == arm), 6) for arm in arms}
    return {
        "experiment": manifest.id, "manifest_digest": manifest.digest, "hypothesis": manifest.hypothesis,
        "arms": {a: {"label": arm.label, "replay_only": arm.replay_only, "repeats": arm.repeats, "budget_usd": arm.budget_usd}
                 for a, arm in manifest.arms.items()},
        "units": {"paired": len(pairs), "groups": len({p[0].group for p in pairs}), "outcomes": len(outcomes),
                  "by_label": {str(lab): sum(p[0].label == lab for p in pairs) for lab in (0, 1)}},
        "primary": [m.as_dict() for m in manifest.primary], "secondary": [m.as_dict() for m in manifest.secondary],
        "tests": tests, "looks": [look.as_dict() for look in looks],
        "tost": None if tost is None else tost.as_dict(), "mde": manifest.mde, "alpha": manifest.alpha, "resamples": n,
        "decision": verdict, "reason": reason, "spend_usd": spend, **dict(provenance or {}),
    }  # fmt: skip


def result_row(manifest: Manifest, pin: str, result: Mapping[str, Any]) -> dict[str, Any]:
    tests = result["tests"]
    return {
        "id": row_id(RESULT_KIND, f"experiment-{manifest.id}", "analyse", manifest.id), "kind": RESULT_KIND,
        "repo": experiment_repo(manifest.id), "pin": pin, "run": f"experiment-{manifest.id}", "task": "analyse", "population": POPULATION,
        "split": manifest.id, "image": "host", "experiment": manifest.id, "manifest_digest": manifest.digest,
        "decision": result["decision"], "reason": result["reason"], "units": result["units"], "spend_usd": result["spend_usd"],
        "tests": {n: {"diff": t["estimate"]["diff"], "ci": t["estimate"]["ci"], "ci_vs_zero": t["ci_vs_zero"]} for n, t in tests.items()},
        "looks": [{"fraction": look["fraction"], "z": look["z"], "crossed": look["crossed"]} for look in result["looks"]],
    }  # fmt: skip


# --- run -----------------------------------------------------------------------------------------------------------------


def arm_spec(manifest: Manifest, arm: Arm, family: str, store: MemoryStore) -> ProgramSpec:
    """The arm's program: the family's compiled incumbent, with the arm's declared overrides and nothing else."""
    pid = arm.programs.get(family) or manifest.programs.get(family)
    if pid is None:
        raise ExperimentError(f"{manifest.id}: arm {arm.name} names no program for family {family!r}")
    return replace(spec_of(load_program(store, pid)), **dict(arm.spec))


@dataclass
class RunSummary:
    experiment: str
    status: str  # done | unfinished | stopped
    units: int
    decided: dict[str, int]
    skipped: dict[str, int]
    spend: dict[str, dict[str, Any]]
    folds_digest: str
    stopped_at_look: int | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def run(
    store: MemoryStore,
    manifest: Manifest,
    memory: Sequence[Example],
    callers: Mapping[str, Caller],
    excerpt_text: Callable[[str], str | None],
    vectors: Mapping[str, Sequence[float]] | None = None,
    *,
    stop_early: bool = True,
    resamples: int | None = None,
    on_decision: Callable[[Outcome, Decision], None] | None = None,
) -> RunSummary:
    """Every unit in every arm, paired, repositories in the pre-shuffled look order, a seeded coin per unit for which
    arm goes first; outcomes already in the store are not decided again. After the first look's repositories the
    primary is tested against its boundary and, when crossed, the run stops. A ceiling ends the run ``unfinished``."""
    if manifest.kind != "program":
        raise ExperimentError(f"{manifest.id}: plane arms run as plane Runs; their outcomes arrive as arm_outcome rows")
    row = check_registered(store, manifest)
    units = read_units(manifest.units_file)
    folds, fdigest = program_folds(memory, manifest)
    by_name = {f.name: f for f in folds}
    index = {e.id: e for e in memory}
    for unit in units:
        fold = by_name.get(unit.fold)
        if fold is None or unit.group not in fold.eval_groups or unit.unit not in index:
            raise ExperimentError(
                f"{manifest.id}: unit {unit.unit[:12]} is not under fold {unit.fold!r} of this memory; the memory changed"
            )
    programs: dict[tuple[str, str], Program] = {}
    for arm in manifest.arms.values():
        for family in manifest.families:
            programs[arm.name, family] = Program(arm_spec(manifest, arm, family, store), memory, excerpt_text, vectors)
    candidate_of = candidate_from_example(excerpt_text, vectors)
    have = {outcome_id(manifest.id, o.arm, o.unit, o.replicate) for o in load_outcomes(store, manifest.id)}
    order = look_order((u.group for u in units), manifest.seed)
    first_look = set(order[: math.ceil(manifest.looks[0] * len(order))]) if len(manifest.looks) > 1 else set()
    rank = {g: i for i, g in enumerate(order)}
    decided = {a: 0 for a in manifest.arms}
    skipped = {a: 0 for a in manifest.arms}
    status, stopped_at, reason = "done", None, ""
    rng = random.Random(manifest.seed)
    arm_names = sorted(manifest.arms)
    fold_seed = int(manifest.folds.get("seed", 0))
    try:
        for unit in sorted(units, key=lambda u: (rank[u.group], u.family, u.unit)):
            if stop_early and first_look and unit.group not in first_look:  # the walk has passed every first-look repository
                looks = sequential_looks(
                    paired_units(load_outcomes(store, manifest.id)), manifest.primary[0], manifest, resamples=resamples
                )
                if looks and looks[0].crossed:
                    status, stopped_at, reason = "stopped", 1, f"the first look crossed its boundary (z = {looks[0].z:.3f})"
                    break
                first_look = set()  # tested once
            first = rng.random() < 0.5
            ordered = arm_names if first else list(reversed(arm_names))
            for position, name in enumerate(ordered):
                arm = manifest.arms[name]
                for r in range(arm.repeats):
                    if outcome_id(manifest.id, name, unit.unit, r) in have:
                        skipped[name] += 1
                        continue
                    candidate = candidate_of(index[unit.unit])
                    if candidate is None:
                        raise ExperimentError(f"{manifest.id}: unit {unit.unit[:12]} has no excerpt in the store")
                    caller = callers[name]
                    caller.salt = f"r{r}:" if r else ""
                    before = caller.usd() or 0.0
                    try:
                        decision = programs[name, unit.family].decide(candidate, by_name[unit.fold], caller, seed=fold_seed)
                    finally:
                        caller.salt = ""
                    usd = round((caller.usd() or 0.0) - before, 6) if caller.usd() is not None else None
                    outcome = Outcome(unit.unit, unit.group, unit.family, unit.label, unit.pair, name, r, decision.s, decision.verdict, usd,
                                      decision.parse_failed, position)  # fmt: skip
                    store.put_row(outcome_row(manifest.id, str(row["pin"]), outcome))
                    have.add(outcome_id(manifest.id, name, unit.unit, r))
                    decided[name] += 1
                    if on_decision is not None:
                        on_decision(outcome, decision)
    except BudgetExhausted as exc:
        status, reason = "unfinished", str(exc)
    spend = {
        name: {"usd": c.usd(), "client_calls": c.calls, "replayed": c.replayed, "cache_digest": c.cache_digest()}
        for name, c in callers.items()
    }
    summary = RunSummary(manifest.id, status, len(units), decided, skipped, spend, fdigest, stopped_at, reason)
    store.put_row({
        "id": row_id(EXPERIMENT_KIND, f"experiment-{manifest.id}", RUN_TASK, manifest.id), "kind": EXPERIMENT_KIND,
        "repo": experiment_repo(manifest.id), "pin": str(row["pin"]), "run": f"experiment-{manifest.id}", "task": RUN_TASK,
        "population": POPULATION, "split": manifest.id, "image": "host", "experiment": manifest.id,
        "manifest_digest": manifest.digest, **summary.as_dict(),
    })  # fmt: skip
    return summary


__all__ = [
    "ALPHA", "ARM_KINDS", "EXPERIMENT_KIND", "MANIFEST_DIR", "METRICS", "OBF_TWO_LOOKS", "OUTCOME_KIND", "RESAMPLES", "RESULT_DIR",
    "RESULT_KIND", "TOST_MARGIN", "VERDICTS", "Arm", "ArmUnit", "Estimate", "ExperimentError", "Look", "Manifest", "McNemar", "Metric",
    "Outcome", "RunSummary", "Unit", "analyse", "arm_spec", "arm_units", "auc", "check_registered", "committed_at_head", "decide",
    "exact_mcnemar", "excludes_zero", "freeze_units", "load_manifest", "load_outcomes", "look_order", "mcnemar_for", "metric_value",
    "outcome_row", "paired_bootstrap", "paired_units", "program_folds", "read_units", "register", "registered", "result_row", "run",
    "sequential_looks", "within_pair_auc", "write_units",
]  # fmt: skip
