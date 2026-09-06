"""Vuln-vs-fixed pair corpus: TP on the vuln tree, silent on the fix tree.

Isolated trees keep the two sides from contaminating each other (a `safe.py`
sitting next to `app.py` cannot measure false positives). Pair outcomes feed
the improvement loop as miss (vuln) and fp (fix) signals.

pair-corpus-honesty: the overlay scorer counts ``coverage`` records with a
source as detections and as leaks, matches by function when a label names one,
flags CWE-only rows as weak labels, reports parser/adjudication loss, and
slices metrics by provenance profile and by mechanism. Known-limit pairs are
evaluated but excluded from the achievable numbers.
"""

from __future__ import annotations

import hashlib
import importlib.util
import math
import os
import shutil
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from functools import lru_cache
from pathlib import Path

from .benchmark import (
    BenchmarkManifest,
    BenchmarkRun,
    BenchmarkSource,
    ExpectedFinding,
    evaluate_benchmark,
    load_benchmark_manifest,
)
from .findings import StaticFinding, quick_scan_findings
from .mapping import analyze_entry_points, attach_reachability_hints
from .preprocess import FileTarget, preprocess_repository
from .rank import rank_targets
from .ruleset import PatternRule
from .semantic import OverlayRecord, adjudicate
from .semantic.facts import FactLoadError, load_facts
from .semantic.functions import RESERVED_FUNCTION_LABELS, function_at, named_function_ranges, spans_named
from .semantic.obligations.facts import OPERATION_KINDS

DEFAULT_CATALOG = Path("benchmarks/pairs/catalog.toml")
DEFAULT_SAST_CATALOG = Path("benchmarks/pairs/sast/catalog.toml")
DEFAULT_VFC_CATALOG = Path("benchmarks/pairs/vfc/catalog.toml")
DEFAULT_VIBE_PY_CATALOG = Path("benchmarks/pairs/vibe-py/catalog.toml")
DEFAULT_VFC_JS_CATALOG = Path("benchmarks/pairs/vfc-js/catalog.toml")
DEFAULT_AGENT_VFC_CATALOG = Path("benchmarks/pairs/agent-vfc/catalog.toml")
DEFAULT_DATASETS = Path("benchmarks/pairs/datasets.toml")
DEFAULT_MECHANISMS = Path("benchmarks/pairs/mechanisms.toml")

# Slices scored on overlay dispositions (inventory fallback when nothing adjudicates).
OVERLAY_SLICES = frozenset({"sast", "vfc", "vibe-py", "vfc-js", "agent-vfc"})
# Harvested function slices: every label must name the function (design §LabelSchema); "<anon>" does not scope.
FUNCTION_REQUIRED_SLICES = OVERLAY_SLICES - {"sast"}
FunctionRanges = dict[str, tuple[tuple[str, int, int], ...]]
SLICE_NAMES = ("all", "local", "github", "sast", "vfc", "vibe-py", "vfc-js", "agent-vfc")
PROVENANCES = frozenset({"human", "agent", "mixed", "synthetic"})
SPLITS = frozenset({"train", "holdout"})
# Req 9: how a label was established. Only seeded and reviewed pairs steer the improve loop.
REVIEW_TIERS = frozenset({"seeded", "advisory", "title", "reviewed"})
GATING_TIERS = frozenset({"seeded", "reviewed"})
# Req 10: pointer pairs are harvested into a cache outside the repository, never vendored.
PAIR_CACHE_ENV = "OPENULTRASAST_PAIR_CACHE"
PAIRS_NETWORK_ENV = "OPENULTRASAST_PAIRS_NETWORK"
DEFAULT_PAIR_CACHE = Path.home() / ".cache" / "openultrasast" / "pairs"
POINTER_REQUIRED = ("repo", "parent", "commit", "path", "mode")
POINTER_FIELDS = POINTER_REQUIRED + (
    "host",
    "fix_repo",
    "fix_path",
    "line",
    "fix_line",
    "line_start",
    "line_end",
    "function",
    "language",
    "license",
    "relpath",
    "provenance",
    "mechanism",
    "cve",
    "commit_url",
)
HARVEST_LIBRARY = Path("benchmarks/pairs/harvest.py")
_DEFAULT_TIER = {
    "local": "reviewed",
    "github": "advisory",
    "sast": "advisory",
    "vfc": "advisory",
    "vibe-py": "seeded",
    "vfc-js": "advisory",
    "agent-vfc": "title",
}
_DEFAULT_PROVENANCE = {"sast": "synthetic", "local": "human", "github": "human", "vfc": "human"}
_MANIFEST_MECHANISM = "source_reaches_sink"  # cheat-sheet fixtures referenced via expected_from

HunterScan = Callable[[Path], list[StaticFinding]]


class CatalogError(ValueError):
    """Raised when a pair catalog violates the label schema."""


@dataclass(frozen=True)
class PairCase:
    name: str
    slice: str
    language: str
    origin: str
    vuln_file: Path
    fixed_file: Path
    relpath: str
    expected: tuple[ExpectedFinding, ...]
    min_recall: float
    fix_policy: str
    repo: str = ""
    commit: str = ""
    commit_url: str = ""
    cve: str = ""
    license: str = ""
    provenance: str = "human"
    split: str = "train"
    known_limit: str | None = None
    review_tier: str = "advisory"
    reviewer: str = ""
    vendored: bool = True
    unscorable: str | None = None  # computed: identical_twin, known_limit:<reason> (learning-harness Req 4.1)
    split_declared: bool = True  # False when the catalog row named no split, so the split helper may assign one
    fix_date: str = ""  # ISO date of the fixing commit; the catalog generator fills it, the split helper orders by it
    recipe: tuple[tuple[str, object], ...] = ()  # pointer pairs carry their harvest recipe instead of excerpts


@dataclass(frozen=True)
class PairOutcome:
    name: str
    slice: str
    language: str
    origin: str
    detected_vuln: bool
    silent_fix: bool
    pair_correct: bool
    vuln_matched: int
    vuln_expected: int
    vuln_findings: int
    fix_findings: int
    fix_leaks: int
    recall: float
    misses: tuple[str, ...]
    leaks: tuple[str, ...]
    commit_url: str = ""
    cve: str = ""
    provenance: str = "human"
    mechanisms: tuple[str, ...] = ()
    known_limit: str | None = None
    split: str = "train"
    weak_labels: int = 0
    parse_failed_vuln: int = 0
    parse_failed_fixed: int = 0
    unadjudicated_vuln: int = 0
    unadjudicated_fixed: int = 0
    detection_kinds: tuple[str, ...] = ()
    unresolved_labels: int = 0  # expected rows whose function names no range on the vulnerable side
    review_tier: str = "advisory"


@dataclass(frozen=True)
class PairCorpusMetrics:
    pairs: int
    detected_vuln: int
    silent_fix: int
    pair_correct: int
    labeled_expected: int
    labeled_matched: int
    labeled_fix_leaks: int
    pair_pass_rate: float
    vuln_recall: float
    specificity: float
    labeled_recall: float
    youden: float


@dataclass(frozen=True)
class PairEvalResult:
    outcomes: tuple[PairOutcome, ...]
    overall: PairCorpusMetrics
    per_slice: dict[str, PairCorpusMetrics]
    signals: tuple[dict[str, object], ...]
    scorers: dict[str, dict[str, PairCorpusMetrics]] = field(default_factory=dict)
    per_profile: dict[str, PairCorpusMetrics] = field(default_factory=dict)
    per_tier: dict[str, PairCorpusMetrics] = field(default_factory=dict)
    per_mechanism: dict[str, PairCorpusMetrics] = field(default_factory=dict)
    achievable: dict[str, PairCorpusMetrics] = field(default_factory=dict)
    known_limit: tuple[str, ...] = ()
    loss: dict[str, dict[str, int]] = field(default_factory=dict)
    degradations: tuple[dict[str, object], ...] = ()


def load_datasets(path: Path = DEFAULT_DATASETS) -> tuple[dict[str, object], ...]:
    payload = tomllib.loads(path.read_text())
    return tuple(dict(item) for item in payload.get("dataset", []))


@lru_cache(maxsize=4)
def load_mechanisms(path: Path = DEFAULT_MECHANISMS) -> tuple[str, frozenset[str]]:
    """Closed mechanism vocabulary: (version, ids). Missing file is a catalog error."""
    if not path.is_file():
        raise CatalogError(f"mechanism vocabulary missing: {path}")
    payload = tomllib.loads(path.read_text())
    ids = frozenset(str(item["id"]) for item in payload.get("mechanism", []) if isinstance(item, dict) and item.get("id"))
    if not ids:
        raise CatalogError(f"mechanism vocabulary is empty: {path}")
    return str(payload.get("version", "1")), ids


def load_pair_catalog(path: Path = DEFAULT_CATALOG) -> tuple[PairCase, ...]:
    cases = _load_catalog_file(path)
    if path.resolve() == DEFAULT_CATALOG.resolve():
        for extra in (
            DEFAULT_SAST_CATALOG,
            DEFAULT_VFC_CATALOG,
            DEFAULT_VIBE_PY_CATALOG,
            DEFAULT_VFC_JS_CATALOG,
            DEFAULT_AGENT_VFC_CATALOG,
        ):
            if extra.exists():
                cases = cases + _load_catalog_file(extra)
    return cases


def _load_catalog_file(path: Path) -> tuple[PairCase, ...]:
    catalog_path = path.resolve()
    payload = tomllib.loads(catalog_path.read_text())
    root = catalog_path.parent
    _, mechanisms = load_mechanisms()
    cases: list[PairCase] = []
    for item in payload.get("pair", []):
        name = str(item["name"])
        slice_name = str(item.get("slice", "github"))
        expected = _expected_for(item, root, name, mechanisms)
        if slice_name in FUNCTION_REQUIRED_SLICES:
            for row in expected:
                if not row.function or row.function in RESERVED_FUNCTION_LABELS:
                    raise CatalogError(
                        f"pair {name}: slice {slice_name} requires a named function on every expected row (got {row.function!r})"
                    )
        provenance = str(item.get("provenance") or _DEFAULT_PROVENANCE.get(slice_name, "human"))
        if provenance not in PROVENANCES:
            raise CatalogError(f"pair {name}: unknown provenance {provenance!r}; expected one of {sorted(PROVENANCES)}")
        split = str(item.get("split", "train"))
        if split not in SPLITS:
            raise CatalogError(f"pair {name}: unknown split {split!r}; expected train or holdout")
        known_limit = item.get("known_limit")
        review_tier, reviewer = _review_tier(item, slice_name, name)
        vendored = item.get("vendored", True) is not False
        recipe: tuple[tuple[str, object], ...] = ()
        if vendored:
            vuln_file, fixed_file = _resolve(root, str(item["vuln"])), _resolve(root, str(item["fixed"]))
        else:
            vuln_file, fixed_file, recipe = _pointer_files(item, slice_name, name)
        cases.append(
            PairCase(
                name=name,
                slice=slice_name,
                language=str(item.get("language", "")),
                origin=str(item.get("origin", "")),
                vuln_file=vuln_file,
                fixed_file=fixed_file,
                relpath=str(item["relpath"]),
                expected=expected,
                min_recall=float(item.get("min_recall", 1.0)),
                fix_policy=str(item.get("fix_policy", "silent")),
                repo=str(item.get("repo", "")),
                commit=str(item.get("commit", "")),
                commit_url=str(item.get("commit_url", "")),
                cve=str(item.get("cve", "")),
                license=str(item.get("license", "")),
                provenance=provenance,
                split=split,
                known_limit=str(known_limit) if known_limit else None,
                unscorable=_unscorable_reason(known_limit, vuln_file, fixed_file, vendored=vendored),
                split_declared="split" in item,
                fix_date=str(item.get("fix_date", "")),
                review_tier=review_tier,
                reviewer=reviewer,
                vendored=vendored,
                recipe=recipe,
            )
        )
    return tuple(cases)


def pair_cache_dir() -> Path:
    """Cache root for pointer pairs (Req 10.2); outside the repository unless the operator points it elsewhere."""
    return Path(os.environ.get(PAIR_CACHE_ENV) or DEFAULT_PAIR_CACHE).expanduser()


def network_allowed(pointers: bool | None = None) -> bool:
    """``pairs --pointers`` for one run, or OPENULTRASAST_PAIRS_NETWORK=1; CI never sets either (Req 10.3, 10.4)."""
    if pointers is not None:
        return pointers
    return os.environ.get(PAIRS_NETWORK_ENV, "") == "1"


def pointer_recipe(case: PairCase) -> dict[str, object]:
    return dict(case.recipe)


def select_vendored(cases: Sequence[PairCase]) -> tuple[PairCase, ...]:
    """Tests and gates score vendored pairs only (Req 10.4)."""
    return tuple(case for case in cases if case.vendored)


def _pointer_files(item: dict[str, object], slice_name: str, name: str) -> tuple[Path, Path, tuple[tuple[str, object], ...]]:
    missing = [key for key in POINTER_REQUIRED if not item.get(key)]
    if missing:
        raise CatalogError(f"pair {name}: vendored = false requires {', '.join(POINTER_REQUIRED)} (missing {', '.join(missing)})")
    recipe = {key: item[key] for key in POINTER_FIELDS if key in item}
    recipe["name"] = name
    recipe["slice"] = slice_name
    expected = item.get("expected")
    if isinstance(expected, list) and expected and isinstance(expected[0], dict):  # header fields live on the expected row
        for key in ("function", "mechanism"):
            recipe.setdefault(key, expected[0].get(key, ""))
    ext = Path(str(item["path"])).suffix or ".c"
    folder = (pair_cache_dir() / slice_name / name).resolve()
    return folder / f"vuln{ext}", folder / f"fixed{ext}", tuple(sorted(recipe.items()))


@lru_cache(maxsize=1)
def _harvest_library() -> object:
    spec = importlib.util.spec_from_file_location("openultrasast_pair_harvest", HARVEST_LIBRARY.resolve())
    if spec is None or spec.loader is None:
        raise OSError(f"harvest library not found: {HARVEST_LIBRARY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _materialize_pointer(recipe: dict[str, object], cache_root: Path) -> tuple[Path, Path]:
    """Harvest both sides of a pointer pair into ``cache_root`` through the shared harvest library (network)."""
    module = _harvest_library()
    vuln, fixed = module.materialize_pointer(  # type: ignore[attr-defined]
        recipe, cache_root, slice_name=str(recipe["slice"])
    )
    return Path(vuln), Path(fixed)


def _pointer_ready(case: PairCase, *, pointers: bool | None) -> dict[str, object] | None:
    """None when the pair can be scored; otherwise the degradation entry (skipped or fetch failed).

    The network switch is consulted first: a warm cache only spares the fetch under ``--pointers``/env, it never turns a
    default run into a pointer run (Req 10.3).
    """
    if case.vendored:
        return None
    if not network_allowed(pointers):
        return {"stage": "pairs", "reason": "pointer_pair_skipped", "pair": case.name}
    if case.vuln_file.is_file() and case.fixed_file.is_file():
        return None
    try:
        _materialize_pointer(pointer_recipe(case), pair_cache_dir())
    except Exception as exc:  # noqa: BLE001 - a failed fetch is a recorded loss, never a crash of the whole run
        return {"stage": "pairs", "reason": "pointer_pair_fetch_failed", "pair": case.name, "detail": f"{type(exc).__name__}: {exc}"[:200]}
    if case.vuln_file.is_file() and case.fixed_file.is_file():
        return None
    return {"stage": "pairs", "reason": "pointer_pair_fetch_failed", "pair": case.name, "detail": "harvest wrote no excerpts"}


def _review_tier(item: dict[str, object], slice_name: str, name: str) -> tuple[str, str]:
    """Tier from the row, else from ``reviewer`` (pending -> title, a name -> reviewed), else the slice default."""
    reviewer = str(item.get("reviewer", "") or "")
    pending = reviewer.lower() == "pending"
    explicit = item.get("review_tier")
    if explicit is not None:
        tier = str(explicit)
    elif pending:
        tier = "title"
    elif reviewer:
        tier = "reviewed"
    else:
        tier = _DEFAULT_TIER.get(slice_name, "advisory")
    if tier not in REVIEW_TIERS:
        raise CatalogError(f"pair {name}: unknown review_tier {tier!r}; expected one of {sorted(REVIEW_TIERS)}")
    if tier == "reviewed" and (not reviewer or pending):
        raise CatalogError(f"pair {name}: review_tier reviewed requires a named reviewer")
    return tier, "" if pending else reviewer


def evaluate_pair(case: PairCase, *, hunter: HunterScan | None = None, ruleset: tuple[PatternRule, ...] | None = None) -> PairOutcome:
    with tempfile.TemporaryDirectory(prefix="ousast-pair-") as scratch:
        vuln_root = _materialize(Path(scratch) / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(Path(scratch) / "fixed", case.fixed_file, case.relpath)
        if hunter is not None:
            return _evaluate_hunter_pair(case, vuln_root, fix_root, hunter)
        if case.slice in OVERLAY_SLICES:
            return _evaluate_overlay_pair(case, vuln_root, fix_root, ruleset)
        return _evaluate_inventory_pair(case, vuln_root, fix_root, ruleset=ruleset)


def evaluate_catalog(
    cases: Sequence[PairCase],
    *,
    hunter: HunterScan | None = None,
    ruleset: tuple[PatternRule, ...] | None = None,
    inventory_sidecar: bool = True,
    pointers: bool | None = None,
) -> PairEvalResult:
    """Score every case. ``ruleset`` lets the improve loop score a candidate ledger; ``inventory_sidecar=False`` skips the second scan.

    Pointer pairs (``vendored = false``) are harvested into the cache when ``pointers`` (or OPENULTRASAST_PAIRS_NETWORK=1) allows the
    network, otherwise skipped with a ``pointer_pair_skipped`` degradation (Req 10.2, 10.3).
    """
    degradations: list[dict[str, object]] = []
    ready: list[PairCase] = []
    for case in cases:
        degradation = _pointer_ready(case, pointers=pointers)
        if degradation is None:
            ready.append(case)
        else:
            degradations.append(degradation)
    cases = tuple(ready)
    outcomes = tuple(evaluate_pair(case, ruleset=ruleset) for case in cases)
    scorers: dict[str, dict[str, PairCorpusMetrics]] = {}
    for slice_name in sorted({case.slice for case in cases if case.slice in OVERLAY_SLICES}):
        slice_cases = tuple(case for case in cases if case.slice == slice_name)
        scorers[slice_name] = {"overlay": _metrics(tuple(item for item in outcomes if item.slice == slice_name))}
        if inventory_sidecar:
            scorers[slice_name]["inventory"] = _metrics(tuple(_inventory_only(case, ruleset) for case in slice_cases))
        if hunter is not None:
            scorers[slice_name]["hunter"] = _metrics(tuple(evaluate_pair(case, hunter=hunter) for case in slice_cases))
    if hunter is None and scorers:
        degradations.append({"stage": "pairs", "reason": "hunter_model_unavailable"})
    achievable_outcomes = tuple(item for item in outcomes if item.known_limit is None)
    per_mechanism: dict[str, list[PairOutcome]] = {}
    for item in outcomes:
        for mechanism in item.mechanisms:
            per_mechanism.setdefault(mechanism, []).append(item)
    return PairEvalResult(
        outcomes=outcomes,
        overall=_metrics(outcomes),
        per_slice={
            slice_name: _metrics(tuple(item for item in outcomes if item.slice == slice_name))
            for slice_name in sorted({item.slice for item in outcomes})
        },
        signals=tuple(build_pair_signals(outcomes)),
        scorers=scorers,
        per_profile={
            profile: _metrics(tuple(item for item in outcomes if item.provenance == profile))
            for profile in sorted({item.provenance for item in outcomes})
        },
        per_tier={
            tier: _metrics(tuple(item for item in outcomes if item.review_tier == tier))
            for tier in sorted({item.review_tier for item in outcomes})
        },
        per_mechanism={mechanism: _metrics(tuple(items)) for mechanism, items in sorted(per_mechanism.items())},
        achievable={
            slice_name: _metrics(tuple(item for item in achievable_outcomes if item.slice == slice_name))
            for slice_name in sorted({item.slice for item in achievable_outcomes})
        },
        known_limit=tuple(item.name for item in outcomes if item.known_limit is not None),
        loss=_loss(outcomes),
        degradations=tuple(degradations),
    )


def build_pair_signals(outcomes: Sequence[PairOutcome], *, split: str | None = None) -> list[dict[str, object]]:
    """Same miss/fp vocabulary as ``build_rule_signals``, tagged with the pair name, profile, and mechanisms.

    ``split`` restricts the signals to one split, so a learning path teaches from the train rows only (Req 5.1).
    """
    signals: list[dict[str, object]] = []
    for outcome in outcomes:
        if outcome.known_limit is not None:
            continue  # unachievable by construction; the loop must not chase it
        if split is not None and outcome.split != split:
            continue
        common: dict[str, object] = {
            "pair": outcome.name,
            "profile": outcome.provenance,
            "mechanisms": list(outcome.mechanisms),
            "split": outcome.split,
        }
        for miss in outcome.misses:
            rule_id, path, cwe = (miss.split(":", 2) + ["", ""])[:3]
            signals.append({"rule_id": rule_id if rule_id != "-" else "", "signal": "miss", "cwe": cwe, "path": path, **common})
        for leak in outcome.leaks:
            rule_id = leak.split(":", 1)[0]
            signals.append({"rule_id": rule_id, "signal": "fp", "path": leak, "side": "fixed", **common})
    return sorted(signals, key=lambda item: (str(item.get("signal")), str(item.get("rule_id")), str(item.get("pair"))))


@dataclass(frozen=True)
class SplitReport:
    """What ``split_by_repository`` had to do and what it found (learning-harness Req 4.4)."""

    assigned: tuple[tuple[str, str], ...] = ()  # (pair, split) for rows whose catalog row named none
    straddling: tuple[tuple[str, tuple[str, ...]], ...] = ()  # repository -> pairs, when one repository sits in both splits
    undated: int = 0  # assigned rows with no fix date, ordered by name instead


# The keys the harvester writes into an excerpt's provenance header (benchmarks/pairs/harvest.py).
# Only a leading comment line carrying one of these keys is metadata; anything else is code. A C
# preprocessor directive and an ordinary leading comment are code, and stripping them would let two
# different files hash equal and vanish from every denominator.
_PROVENANCE_KEYS = frozenset(
    {"provenance", "repo", "commit", "parent", "commit_url", "cve", "license", "function", "relpath", "mechanism", "upstream_start"}
)
_COMMENT_MARKERS = ("#", "//", "*/", "/*", "*")


def _is_header_line(line: str) -> bool:
    body = line.strip()
    if not body:
        return True
    for marker in _COMMENT_MARKERS:
        if body.startswith(marker):
            body = body[len(marker) :].strip()
            break
    else:
        return False
    if not body:
        return True  # the framing line of a block comment
    key, separator, _rest = body.partition(":")
    return bool(separator) and key.strip().lower() in _PROVENANCE_KEYS


def _header_lines(lines: Sequence[str]) -> int:
    """How many leading lines are the provenance header. Stops at the first line that is code."""
    index = 0
    while index < len(lines) and _is_header_line(lines[index]):
        index += 1
    return index


@lru_cache(maxsize=4096)
def _body_digest(path: Path) -> str | None:
    """Hash of an excerpt with its provenance header and trailing whitespace removed; None when unreadable or empty."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    lines = text.splitlines()
    body = "\n".join(line.rstrip() for line in lines[_header_lines(lines) :]).strip()
    return hashlib.sha256(body.encode()).hexdigest() if body else None


def _unscorable_reason(known_limit: object, vuln_file: Path, fixed_file: Path, *, vendored: bool) -> str | None:
    """Why this pair cannot be scored, or None. A declared known limit wins over anything computed."""
    if known_limit:
        return f"known_limit:{known_limit}"
    if not vendored:
        return None
    digest = _body_digest(vuln_file)
    return "identical_twin" if digest is not None and digest == _body_digest(fixed_file) else None


def duplicate_groups(cases: Sequence[PairCase]) -> tuple[tuple[str, ...], ...]:
    """Pairs whose vulnerable excerpts are the same code, reported before any split is applied (Req 4.3)."""
    by_digest: dict[str, list[str]] = {}
    for case in cases:
        digest = _body_digest(case.vuln_file) if case.vendored else None
        if digest is not None:
            by_digest.setdefault(digest, []).append(case.name)
    return tuple(tuple(sorted(names)) for _, names in sorted(by_digest.items()) if len(names) > 1)


def split_by_repository(cases: Sequence[PairCase], *, holdout_fraction: float = 0.5) -> tuple[tuple[PairCase, ...], SplitReport]:
    """Keep every declared split, assign the rest by repository in date order, and report repositories that straddle.

    A repository never straddles by our doing: rows that named no split inherit their repository's declared split when
    there is one, and otherwise the whole repository lands on one side, oldest first (Req 4.4).
    """
    groups: dict[str, list[PairCase]] = {}
    for case in cases:
        groups.setdefault(case.repo or f"{case.slice}:{case.name}", []).append(case)
    straddling = tuple(
        (repo, tuple(sorted(case.name for case in members)))
        for repo, members in sorted(groups.items())
        if len({case.split for case in members if case.split_declared}) > 1
    )
    open_repos = [repo for repo, members in groups.items() if any(not case.split_declared for case in members)]
    inherited = {repo: next((case.split for case in groups[repo] if case.split_declared), None) for repo in open_repos}
    orderable = sorted(
        (repo for repo in open_repos if inherited[repo] is None),
        key=lambda repo: (min((case.fix_date for case in groups[repo] if case.fix_date), default="9999-99-99"), repo),
    )
    holdout_count = math.ceil(len(orderable) * holdout_fraction) if orderable else 0
    holdout = set(orderable[len(orderable) - holdout_count :]) if holdout_count else set()
    assigned: list[tuple[str, str]] = []
    undated = 0
    out: list[PairCase] = []
    for case in cases:
        repo = case.repo or f"{case.slice}:{case.name}"
        if case.split_declared:
            out.append(case)
            continue
        split = inherited.get(repo) or ("holdout" if repo in holdout else "train")
        undated += 0 if case.fix_date else 1
        assigned.append((case.name, split))
        out.append(replace(case, split=split, split_declared=True))
    return tuple(out), SplitReport(assigned=tuple(assigned), straddling=straddling, undated=undated)


def select_slice(cases: Sequence[PairCase], slice_name: str | None) -> tuple[PairCase, ...]:
    if not slice_name or slice_name == "all":
        return tuple(cases)
    return tuple(case for case in cases if case.slice == slice_name)


def select_tier(cases: Sequence[PairCase], tiers: Iterable[str]) -> tuple[PairCase, ...]:
    """Pairs whose review tier is in ``tiers`` (the improve loop passes GATING_TIERS)."""
    wanted = frozenset(tiers)
    return tuple(case for case in cases if case.review_tier in wanted)


def select_profile(cases: Sequence[PairCase], profile: str | None) -> tuple[PairCase, ...]:
    if not profile or profile == "all":
        return tuple(cases)
    return tuple(case for case in cases if case.provenance == profile)


def select_split(cases: Sequence[PairCase], split: str | None) -> tuple[PairCase, ...]:
    if not split or split == "all":
        return tuple(cases)
    return tuple(case for case in cases if case.split == split)


def result_payload(result: PairEvalResult) -> dict[str, object]:
    return {
        "overall": asdict(result.overall),
        "per_slice": {name: asdict(metrics) for name, metrics in result.per_slice.items()},
        "outcomes": [asdict(outcome) for outcome in result.outcomes],
        "signals": list(result.signals),
        "scorers": {
            slice_name: {scorer: asdict(metrics) for scorer, metrics in inner.items()} for slice_name, inner in result.scorers.items()
        },
        "per_profile": {name: asdict(metrics) for name, metrics in result.per_profile.items()},
        "per_tier": {name: asdict(metrics) for name, metrics in result.per_tier.items()},
        "per_mechanism": {name: asdict(metrics) for name, metrics in result.per_mechanism.items()},
        "achievable": {name: asdict(metrics) for name, metrics in result.achievable.items()},
        "known_limit": list(result.known_limit),
        "loss": {name: dict(counts) for name, counts in result.loss.items()},
        "degradations": list(result.degradations),
    }


# --- catalog helpers -------------------------------------------------------


def _expected_for(item: dict[str, object], root: Path, name: str, mechanisms: frozenset[str]) -> tuple[ExpectedFinding, ...]:
    inline = item.get("expected")
    if isinstance(inline, list) and inline:
        rows = tuple(_parse_expected(entry, name, mechanisms) for entry in inline if isinstance(entry, dict))
        for row in rows:
            _validate_expected(row, name)
        return rows
    expected_from = item.get("expected_from")
    if not expected_from:
        return ()
    manifest = load_benchmark_manifest(_resolve(root, str(expected_from)))
    relpath = str(item["relpath"])
    # Pair eval measures ruled sinks. Unruled planted misses (split-sink, CWE-190)
    # stay on the stage-1/2 fixtures and must not drag local pair_correct below 1.0.
    derived: list[ExpectedFinding] = []
    for entry in manifest.expected:
        if not (entry.rule_id and (relpath in entry.path or entry.path in relpath)):
            continue
        mechanism = entry.mechanism or _MANIFEST_MECHANISM
        if mechanism not in mechanisms:
            raise CatalogError(f"pair {name}: unknown mechanism {mechanism!r} in {expected_from}")
        derived.append(ExpectedFinding(**{**asdict(entry), "mechanism": mechanism}))
    return tuple(derived)


def _parse_expected(item: dict[str, object], name: str, mechanisms: frozenset[str]) -> ExpectedFinding:
    line_value = item.get("line")
    mechanism = item.get("mechanism")
    if not isinstance(mechanism, str) or not mechanism:
        raise CatalogError(f"pair {name}: expected row is missing mechanism")
    if mechanism not in mechanisms:
        raise CatalogError(f"pair {name}: unknown mechanism {mechanism!r}; see benchmarks/pairs/mechanisms.toml")
    family = item.get("family")
    obligation = item.get("obligation")
    if obligation is not None and obligation not in OPERATION_KINDS:
        raise CatalogError(f"pair {name}: unknown obligation {obligation!r}; expected one of {sorted(OPERATION_KINDS)}")
    return ExpectedFinding(
        cwe=str(item["cwe"]),
        vulnerability_class=str(item.get("class", item.get("vulnerability_class", "unknown"))),
        path=str(item["path"]),
        evidence=str(item.get("evidence", "")),
        rule_id=str(item["rule_id"]) if "rule_id" in item else None,
        line=line_value if isinstance(line_value, int) else None,
        function=str(item["function"]) if "function" in item else None,
        sink=str(item["sink"]) if "sink" in item else None,
        mechanism=mechanism,
        obligation=str(obligation) if obligation is not None else None,
        family=str(family) if family is not None else None,
    )


def _validate_expected(row: ExpectedFinding, name: str) -> None:
    if (row.sink or "").lower() == "unknown" and not row.function and not row.rule_id:
        raise CatalogError(f"pair {name}: expected row has sink=unknown and neither function nor rule_id; label it or drop it")


def is_weak_label(row: ExpectedFinding) -> bool:
    """A row that can only match by CWE string. Never counts as a detection."""
    return not row.function and not row.rule_id and (not row.sink or row.sink.lower() == "unknown")


def _manifest(case: PairCase, expected: Sequence[ExpectedFinding] | None = None) -> BenchmarkManifest:
    return BenchmarkManifest(
        name=case.name,
        language=case.language,
        frameworks=[],
        setup=[],
        source=BenchmarkSource(type="local", path=str(case.vuln_file)),
        modes=["quick"],
        expected=list(case.expected if expected is None else expected),
        known_noise=[],
        baselines=[],
    )


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _materialize(dest: Path, source: Path, relpath: str) -> Path:
    target = dest / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return dest


# --- scans -----------------------------------------------------------------


def _targets(root: Path) -> list[FileTarget]:
    _, targets = preprocess_repository(root)
    return attach_reachability_hints(targets, analyze_entry_points(root, targets))


def _quick_scan(target: Path, ruleset: tuple[PatternRule, ...] | None = None) -> list[StaticFinding]:
    targets = _targets(target)
    findings = quick_scan_findings(target, targets, rank_targets(targets), ruleset)
    return [finding for finding in findings if finding.status != "shadow"]


@dataclass(frozen=True)
class _Side:
    findings: list[StaticFinding]
    records: list[OverlayRecord]
    parse_failed: int
    ranges: dict[str, tuple[tuple[str, int, int], ...]]
    obligations: list[StaticFinding] = field(default_factory=list)  # obligation statics, computed for obligation-labeled rows only


def _overlay_scan(target: Path, ruleset: tuple[PatternRule, ...] | None = None, *, obligations: bool = False) -> _Side:
    targets = _targets(target)
    findings = [f for f in quick_scan_findings(target, targets, rank_targets(targets), ruleset) if f.status != "shadow"]
    records = adjudicate(root=target, targets=targets, findings=findings)
    parse_failed = 0
    ranges: dict[str, tuple[tuple[str, int, int], ...]] = {}
    for item in targets:
        try:
            text = (target / item.path).read_text(errors="ignore")
        except OSError:
            parse_failed += 1
            continue
        named = named_function_ranges(item.path, text, item.language)
        if named is None:
            parse_failed += 1
        else:
            ranges[item.path] = named
    statics = _obligation_scan(target, targets) if obligations else []
    return _Side(findings=findings, records=records, parse_failed=parse_failed, ranges=ranges, obligations=statics)


def _obligation_scan(root: Path, targets: Sequence[FileTarget]) -> list[StaticFinding]:
    """Obligation findings for one side in function-local mode (no path records, no declared policy, no store): the
    scorer's additive rule for obligation-labeled rows (Req 7.2). Never runs for rows without the label."""
    from .config import ObligationsConfig
    from .semantic.ir import parse_file
    from .semantic.obligations import check_obligations, findings_to_static, load_obligation_facts
    from .semantic.obligations.dominance import OrderDominance

    try:
        flow_facts = load_facts()
    except FactLoadError:
        return []
    irs: dict[str, tuple[object, str]] = {}
    texts: dict[str, str] = {}
    for target in targets:
        try:
            text = (root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        texts[target.path] = text
        irs[target.path] = (parse_file(target.path, text, target.language), text)
    result = check_obligations(
        irs=irs,  # type: ignore[arg-type]
        entries=analyze_entry_points(root, list(targets)),
        facts=load_obligation_facts(),
        flow_facts=flow_facts,
        policy=None,
        paths=(),
        dominance=OrderDominance(texts=texts),
        store_shapes=(),
        min_siblings=ObligationsConfig().min_siblings,
    )
    return findings_to_static(result)


def _inventory_only(case: PairCase, ruleset: tuple[PatternRule, ...] | None = None) -> PairOutcome:
    with tempfile.TemporaryDirectory(prefix="ousast-pair-inv-") as scratch:
        vuln_root = _materialize(Path(scratch) / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(Path(scratch) / "fixed", case.fixed_file, case.relpath)
        return _evaluate_inventory_pair(case, vuln_root, fix_root, ruleset=ruleset)


def _evaluate_inventory_pair(
    case: PairCase,
    vuln_root: Path,
    fix_root: Path,
    *,
    extra: Mapping[str, int] | None = None,
    ruleset: tuple[PatternRule, ...] | None = None,
) -> PairOutcome:
    vuln_findings = _with_functions(vuln_root, _quick_scan(vuln_root, ruleset))
    fix_findings = _with_functions(fix_root, _quick_scan(fix_root, ruleset))
    return _inventory_outcome(case, vuln_findings, fix_findings, extra=extra)


def _with_functions(root: Path, findings: list[StaticFinding]) -> list[StaticFinding]:
    """Give regex findings an enclosing function from a parse so function-labeled rows can match (Req 1.2)."""
    if not any(finding.function_name is None for finding in findings):
        return findings
    ranges: dict[str, tuple[tuple[str, int, int], ...]] = {}
    for target in _targets(root):
        try:
            named = named_function_ranges(target.path, (root / target.path).read_text(errors="ignore"), target.language)
        except OSError:
            continue
        if named is not None:
            ranges[target.path] = named
    out: list[StaticFinding] = []
    for finding in findings:
        if finding.function_name is None:
            function = function_at(ranges.get(finding.path, ()), finding.line)
            if function is not None:
                finding = replace(finding, function_name=function)
        out.append(finding)
    return out


def make_hunter_scan(client: object, model: str, *, max_steps: int | None = None) -> HunterScan:
    """Run the tool hunter over every file of an isolated pair tree (Req 1.7)."""
    from .complexity.map import Hotspot
    from .tool_hunter import DEFAULT_MAX_STEPS, run_tool_hunter

    def scan(root: Path) -> list[StaticFinding]:
        hotspots = [
            Hotspot(
                path=target.path,
                function_name=None,
                score=1.0,
                band="high",
                signals={},
                rationale="pair corpus function",
                test_hint=None,
                inventory_finding_ids=(),
            )
            for target in _targets(root)
        ]
        return _with_functions(root, run_tool_hunter(root, hotspots, client=client, model=model, max_steps=max_steps or DEFAULT_MAX_STEPS))  # type: ignore[arg-type]

    return scan


def _inventory_outcome(
    case: PairCase,
    vuln_findings: list[StaticFinding],
    fix_findings: list[StaticFinding],
    *,
    extra: Mapping[str, int] | None = None,
) -> PairOutcome:
    # Weak (CWE-only) rows never match, on this path either (Req 1.3): score the strong rows
    # with the benchmark matcher and count the weak rows as misses.
    strong = tuple(row for row in case.expected if not is_weak_label(row))
    weak = tuple(row for row in case.expected if is_weak_label(row))
    vuln_result = evaluate_benchmark(
        run=BenchmarkRun(benchmark_run_id="pair", root=Path("/tmp/pair"), manifest=_manifest(case, strong)),
        mode="quick",
        findings=vuln_findings,
        scan_id=None,
        scan_run_dir=None,
    )
    expected_total = len(case.expected)
    matched = vuln_result.metrics.matched_findings_total
    recall = matched / expected_total if expected_total else 1.0
    leaks = _fix_leaks(case, fix_findings)
    detected = recall + 1e-12 >= case.min_recall
    silent = not leaks
    misses = tuple(f"{miss.rule_id or '-'}:{miss.path}:{miss.cwe}" for miss in vuln_result.misses) + tuple(
        f"{row.rule_id or '-'}:{row.path}:{row.cwe}" for row in weak
    )
    leak_ids = tuple(finding.finding_id for finding in leaks)
    counters = dict(extra or {})
    return PairOutcome(
        name=case.name,
        slice=case.slice,
        language=case.language,
        origin=case.origin,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=detected and silent,
        vuln_matched=matched,
        vuln_expected=expected_total,
        vuln_findings=len(vuln_findings),
        fix_findings=len(fix_findings),
        fix_leaks=len(leaks),
        recall=recall,
        misses=misses,
        leaks=leak_ids,
        commit_url=case.commit_url,
        cve=case.cve,
        provenance=case.provenance,
        review_tier=case.review_tier,
        mechanisms=_mechanisms(case),
        known_limit=case.known_limit,
        split=case.split,
        weak_labels=len(weak),
        parse_failed_vuln=int(counters.get("parse_failed_vuln", 0)),
        parse_failed_fixed=int(counters.get("parse_failed_fixed", 0)),
        unadjudicated_vuln=int(counters.get("unadjudicated_vuln", 0)),
        unadjudicated_fixed=int(counters.get("unadjudicated_fixed", 0)),
        unresolved_labels=int(counters.get("unresolved_labels", 0)),
        detection_kinds=("inventory",) if vuln_findings else (),
    )


def _evaluate_overlay_pair(case: PairCase, vuln_root: Path, fix_root: Path, ruleset: tuple[PatternRule, ...] | None = None) -> PairOutcome:
    obligations = any(row.obligation for row in case.expected)
    vuln = _overlay_scan(vuln_root, ruleset, obligations=obligations)
    fixed = _overlay_scan(fix_root, ruleset, obligations=obligations)
    loss: dict[str, int] = {
        "parse_failed_vuln": vuln.parse_failed,
        "parse_failed_fixed": fixed.parse_failed,
        "unadjudicated_vuln": sum(1 for record in vuln.records if record.disposition == "unadjudicated"),
        "unadjudicated_fixed": sum(1 for record in fixed.records if record.disposition == "unadjudicated"),
    }
    if not _adjudicated(vuln.records) and not _adjudicated(fixed.records) and not (vuln.obligations or fixed.obligations):
        # Parser/facts could not adjudicate this language; score inventory so
        # labeled calibration does not collapse when tree-sitter grammars are absent.
        loss["unresolved_labels"] = sum(1 for row in case.expected if _label_unresolved(row, vuln.ranges))
        return _inventory_outcome(case, _with_functions(vuln_root, vuln.findings), _with_functions(fix_root, fixed.findings), extra=loss)
    detected_vuln = _detections(vuln.records)
    detected_fix = _detections(fixed.records)
    expected_total = len(case.expected)
    matched = sum(
        1
        for row in case.expected
        if _overlay_matches_expected(row, detected_vuln, case.language, vuln.ranges)
        or _obligation_matches_expected(row, vuln.obligations, vuln.ranges)
    )
    recall = matched / expected_total if expected_total else 1.0
    detected = recall + 1e-12 >= case.min_recall
    overlay_leaks = _overlay_leaks(case, detected_fix, fixed.ranges) + _obligation_leaks(case, fixed.obligations, fixed.ranges)
    silent = not overlay_leaks
    unresolved = sum(1 for row in case.expected if _label_unresolved(row, vuln.ranges))
    misses = tuple(
        f"{row.rule_id or '-'}:{row.path}:{row.cwe}" + ("!unresolved" if _label_unresolved(row, vuln.ranges) else "")
        for row in case.expected
        if not (
            _overlay_matches_expected(row, detected_vuln, case.language, vuln.ranges)
            or _obligation_matches_expected(row, vuln.obligations, vuln.ranges)
        )
    )
    obligation_kinds = (
        ("obligation",) if any(_obligation_matches_expected(row, vuln.obligations, vuln.ranges) for row in case.expected) else ()
    )
    return PairOutcome(
        name=case.name,
        slice=case.slice,
        language=case.language,
        origin=case.origin,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=detected and silent,
        vuln_matched=matched,
        vuln_expected=expected_total,
        vuln_findings=len(detected_vuln),
        fix_findings=len(detected_fix),
        fix_leaks=len(overlay_leaks),
        recall=recall,
        misses=misses,
        leaks=overlay_leaks,
        commit_url=case.commit_url,
        cve=case.cve,
        provenance=case.provenance,
        review_tier=case.review_tier,
        mechanisms=_mechanisms(case),
        known_limit=case.known_limit,
        split=case.split,
        weak_labels=sum(1 for row in case.expected if is_weak_label(row)),
        detection_kinds=tuple(sorted({record.disposition for record in detected_vuln} | set(obligation_kinds))),
        parse_failed_vuln=loss["parse_failed_vuln"],
        parse_failed_fixed=loss["parse_failed_fixed"],
        unadjudicated_vuln=loss["unadjudicated_vuln"],
        unadjudicated_fixed=loss["unadjudicated_fixed"],
        unresolved_labels=unresolved,
    )


def _evaluate_hunter_pair(case: PairCase, vuln_root: Path, fix_root: Path, hunter: HunterScan) -> PairOutcome:
    """Score the LLM hunter with the same detection and leak rules (Req 1.7)."""
    vuln_findings = hunter(vuln_root)
    fix_findings = hunter(fix_root)
    vuln_ranges = _overlay_scan(vuln_root).ranges
    fix_ranges = _overlay_scan(fix_root).ranges
    expected_total = len(case.expected)
    matched = sum(1 for row in case.expected if any(_hunter_matches_expected(row, finding, vuln_ranges) for finding in vuln_findings))
    recall = matched / expected_total if expected_total else 1.0
    detected = recall + 1e-12 >= case.min_recall
    if case.fix_policy == "silent":
        leaks = tuple(finding.finding_id for finding in fix_findings)
    else:
        leaks = tuple(
            finding.finding_id
            for finding in fix_findings
            if any(_hunter_matches_expected(row, finding, fix_ranges) for row in case.expected)
        )
    misses = tuple(
        f"{row.rule_id or '-'}:{row.path}:{row.cwe}"
        for row in case.expected
        if not any(_hunter_matches_expected(row, finding, vuln_ranges) for finding in vuln_findings)
    )
    return PairOutcome(
        name=case.name,
        slice=case.slice,
        language=case.language,
        origin=case.origin,
        detected_vuln=detected,
        silent_fix=not leaks,
        pair_correct=detected and not leaks,
        vuln_matched=matched,
        vuln_expected=expected_total,
        vuln_findings=len(vuln_findings),
        fix_findings=len(fix_findings),
        fix_leaks=len(leaks),
        recall=recall,
        misses=misses,
        leaks=leaks,
        commit_url=case.commit_url,
        cve=case.cve,
        provenance=case.provenance,
        review_tier=case.review_tier,
        mechanisms=_mechanisms(case),
        known_limit=case.known_limit,
        split=case.split,
        weak_labels=sum(1 for row in case.expected if is_weak_label(row)),
        detection_kinds=("hunter",) if vuln_findings else (),
    )


# --- matching ---------------------------------------------------------------


def _adjudicated(records: Sequence[OverlayRecord]) -> bool:
    return any(record.disposition in {"promote", "demote", "coverage"} for record in records)


def _detections(records: Sequence[OverlayRecord]) -> list[OverlayRecord]:
    """Promotions plus coverage records that carry a source-to-sink flow (Req 1.1)."""
    return [
        record
        for record in records
        if record.disposition == "promote" or (record.disposition == "coverage" and record.sources and record.sinks)
    ]


@lru_cache(maxsize=1)
def _sink_ids_by_rule() -> dict[tuple[str, str], frozenset[str]]:
    """(language, rule_id) -> fact sink ids that declare that rule (facts are the alias table)."""
    try:
        facts = load_facts()
    except FactLoadError:
        return {}
    table: dict[tuple[str, str], set[str]] = {}
    for sink in facts.sinks:
        for rule_id in sink.rule_ids:
            table.setdefault((sink.language, rule_id), set()).add(sink.id)
    return {key: frozenset(value) for key, value in table.items()}


def _fact_language(language: str) -> str:
    return {"c_cpp": "c", "cpp": "c", "typescript": "javascript"}.get(language, language)


def _in_named_function(record: OverlayRecord, function: str, ranges: FunctionRanges | None) -> bool:
    """Design §Scorer rule (1): the record lies inside the labeled function's line range. No range, no match (never name equality)."""
    spans = spans_named((ranges or {}).get(record.path, ()), function)
    return record.line is not None and any(start <= record.line <= end for start, end in spans)


def _label_unresolved(expected: ExpectedFinding, ranges: FunctionRanges | None) -> bool:
    """A labeled function that no parsed range of the vulnerable side names cannot be matched; count it as loss."""
    if not expected.function:
        return False
    return not any(spans_named(spans, expected.function) for spans in (ranges or {}).values())


def _overlay_matches_expected(
    expected: ExpectedFinding, detected: Sequence[OverlayRecord], language: str, ranges: FunctionRanges | None = None
) -> bool:
    if is_weak_label(expected):
        return False
    alias_sinks = _sink_ids_by_rule().get((_fact_language(language), expected.rule_id or ""), frozenset())
    for record in detected:
        function_ok = True
        if expected.function:
            function_ok = _in_named_function(record, expected.function, ranges)
            if not function_ok:
                continue
        if expected.rule_id and expected.rule_id in record.proposal_id:
            return True
        if alias_sinks and any(sink in alias_sinks for sink in record.sinks):
            return True
        if expected.sink and expected.sink.lower() != "unknown" and expected.sink in record.sinks:
            return True
        # CWE equality only counts inside a named function (Req 1.2, 1.3).
        if expected.function and function_ok and expected.cwe and expected.cwe == record.cwe:
            return True
    return False


def _hunter_matches_expected(
    expected: ExpectedFinding, finding: StaticFinding, ranges: dict[str, tuple[tuple[str, int, int], ...]]
) -> bool:
    if is_weak_label(expected):
        return False
    text = f"{finding.title} {finding.rationale} {' '.join(finding.tags)}".lower()
    if expected.function:
        spans = spans_named(ranges.get(finding.path, ()), expected.function)
        if finding.line is None or not any(start <= finding.line <= end for start, end in spans):
            return False
        if expected.cwe and expected.cwe.lower() in text:
            return True
    if expected.sink and expected.sink.lower() != "unknown" and expected.sink.lower() in text:
        return True
    return bool(expected.rule_id and expected.rule_id in finding.finding_id)


def _obligation_matches_expected(expected: ExpectedFinding, statics: Sequence[StaticFinding], ranges: FunctionRanges | None) -> bool:
    """The one additive rule (Req 7.2): a row with `obligation` is detected by a finding tagged `obligation:<kind>` whose line
    lies inside the labeled function. Nothing else about the scorer changes; rows without the label never reach here."""
    if not expected.obligation or not expected.function:
        return False
    tag = f"obligation:{expected.obligation}"
    for finding in statics:
        if tag not in finding.tags or finding.line is None:
            continue
        spans = spans_named((ranges or {}).get(finding.path, ()), expected.function)
        if any(start <= finding.line <= end for start, end in spans):
            return True
    return False


def _obligation_leaks(case: PairCase, statics: Sequence[StaticFinding], ranges: FunctionRanges | None) -> tuple[str, ...]:
    if not statics:
        return ()
    if case.fix_policy == "silent":
        return tuple(finding.finding_id for finding in statics if any(row.obligation for row in case.expected))
    return tuple(
        finding.finding_id for finding in statics if any(_obligation_matches_expected(row, [finding], ranges) for row in case.expected)
    )


def _overlay_leaks(case: PairCase, detected_fix: Sequence[OverlayRecord], ranges: FunctionRanges | None = None) -> tuple[str, ...]:
    if case.fix_policy == "silent":
        return tuple(record.proposal_id for record in detected_fix)
    return tuple(
        record.proposal_id
        for record in detected_fix
        if any(_overlay_matches_expected(row, [record], case.language, ranges) for row in case.expected)
    )


def _fix_leaks(case: PairCase, findings: list[StaticFinding]) -> tuple[StaticFinding, ...]:
    if case.fix_policy == "silent":
        return tuple(findings)
    leaked: list[StaticFinding] = []
    for finding in findings:
        for expected in case.expected:
            if expected.rule_id and finding.finding_id.startswith(f"{expected.rule_id}:"):
                leaked.append(finding)
                break
            if expected.cwe.lower() in (finding.rationale + " " + finding.finding_id).lower():
                leaked.append(finding)
                break
    return tuple(leaked)


def _mechanisms(case: PairCase) -> tuple[str, ...]:
    return tuple(sorted({row.mechanism for row in case.expected if row.mechanism}))


# --- metrics ---------------------------------------------------------------


def _metrics(outcomes: Sequence[PairOutcome]) -> PairCorpusMetrics:
    pairs = len(outcomes)
    detected = sum(1 for item in outcomes if item.detected_vuln)
    silent = sum(1 for item in outcomes if item.silent_fix)
    correct = sum(1 for item in outcomes if item.pair_correct)
    labeled_expected = sum(item.vuln_expected for item in outcomes)
    labeled_matched = sum(item.vuln_matched for item in outcomes)
    labeled_leaks = sum(item.fix_leaks for item in outcomes)
    return PairCorpusMetrics(
        pairs=pairs,
        detected_vuln=detected,
        silent_fix=silent,
        pair_correct=correct,
        labeled_expected=labeled_expected,
        labeled_matched=labeled_matched,
        labeled_fix_leaks=labeled_leaks,
        pair_pass_rate=correct / pairs if pairs else 1.0,
        vuln_recall=detected / pairs if pairs else 1.0,
        specificity=silent / pairs if pairs else 1.0,
        labeled_recall=labeled_matched / labeled_expected if labeled_expected else 1.0,
        youden=(detected / pairs if pairs else 1.0) - (1.0 - (silent / pairs if pairs else 1.0)),
    )


def _loss(outcomes: Sequence[PairOutcome]) -> dict[str, dict[str, int]]:
    loss: dict[str, dict[str, int]] = {}
    for item in outcomes:
        bucket = loss.setdefault(
            item.slice,
            {"parse_failed_files": 0, "unadjudicated_proposals": 0, "weak_labels": 0, "known_limit": 0, "unresolved_function_labels": 0},
        )
        bucket["parse_failed_files"] += item.parse_failed_vuln + item.parse_failed_fixed
        bucket["unadjudicated_proposals"] += item.unadjudicated_vuln + item.unadjudicated_fixed
        bucket["weak_labels"] += item.weak_labels
        bucket["unresolved_function_labels"] += item.unresolved_labels
        bucket["known_limit"] += 1 if item.known_limit else 0
    return loss
