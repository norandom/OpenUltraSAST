"""The harvest Runs of the learned decision engine (design, commit sequence item 5; Req 1.1).

``ousast plane harvest --labels labels-<sha>.jsonl --plane DIR`` writes two Runs over the labelled units of a label
snapshot (``ousast learn labels --out``), with the Workspaces and Tasks they need, under ``DIR`` (a scratch plane
root: the excerpts and candidates are inputs, never committed):

- ``runs/<name>-verify.yaml``: verify passes a and b and ``agree`` (no tie-break) on every verify-family unit
  (:data:`.tasks.verify.OPERATIONS`): both sides of each labelled pair, and the development pins -- population v1's
  vulnerable and fixed pins, the dev-php recipes -- with ``repo-facts`` first for their callers;
- ``runs/<name>-roles.yaml``: ``roles`` (model roles) on the candidate files of every labelled pin unit: the pair
  sides, grouped many to a Workspace (a roles prompt sees one chunk of one file, so grouping changes nothing it
  reads), and one Task per population or recipe pin.

Units carry no label. A pair side is a files-only Workspace holding the excerpt (and the documents that register
it) under ``repo/`` and the candidates under ``inputs/`` -- outside the hunt's root, so the tools cannot read them;
its name is opaque (``h-<sha>``): the pair's name says its CWE and its side. ``agree`` gets no declared sites, so
no ``site_match`` is computed. ``units.json`` maps each unit name to its source, reference, side, repository, pin
and candidates for the host-side feature build; it names functions and stays local.

Every Run entry has a budget; the sum over each Run is held under ``ceiling`` (USD) by construction: verify gets
:data:`USD_PER_HUNT` per hunt of an excerpt or a repository (scaled down when the hunts would exceed the ceiling),
roles a per-chunk estimate times a headroom, scaled down to the ceiling.
A pair side's pin is the git blob sha1 of its excerpt (the store keys rows by
a 40-hex pin; an excerpt has no commit of its own).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..preprocess import detect_language
from .generate import ATESPACE, CALLS_PER_HUNT, CASE_PATH, INPUTS_PATH, _dump, _json, _task
from .manifests import GIT_COMMITS_ANNOTATION, RUN_API_VERSION, Task
from .reconciler import _ax_name, _doc
from .tasks.repo_facts import DECLARATION, GLOBAL, _declared_name
from .tasks.roles import CHUNK_LINES
from .tasks.verify import OPERATIONS, units_of

__all__ = ["Unit", "declaration_line", "pair_units", "population_units", "render_harvest", "write_harvest"]

Candidate = tuple[str, str, int]
REPO = "repo"
# Per verify hunt (pilot 2026-10-01: an excerpt hunt cost $0.003-0.004, a repository hunt $0.019-0.022): ~3x and ~2.5x.
USD_PER_HUNT = {"excerpt": 0.012, "repository": 0.05}
ROLES_GROUP_FILES = 40
# A Workspace's files travel inline: ax hands them to the actor in one environment variable (AX_WORKSPACES_YAML), which
# Linux caps at 128 KiB (MAX_ARG_STRLEN) after YAML escaping. An 86 KB excerpt failed with "actor template not found"
# (2026-10-01), so did a 31 KB one; 7 KB ran. A unit whose own files exceed the limit is skipped, listed in `units.json`.
MAX_INLINE_BYTES = 20_000
ROLES_OUTPUT_TOKENS = 700  # per chunk, generous: a role list with evidence quotes
ROLES_HEADROOM = 2.5
UNKNOWN_SIZE = (80_000, 2_000)  # (characters, lines) assumed for a candidate file the host could not read
PRICES = {"input_per_m": 0.44, "output_per_m": 1.32}  # plane/models/deepseek-flash.yaml
POPULATION_SOURCES = ("population-v1", "population-v2", "dev-php", "adjudications")
VERIFY_SOURCES = ("population-v1", "dev-php")  # the development cases (design section 3); v2 has its recorded Run


@dataclass(frozen=True)
class Unit:
    """One pin of the harvest: a repository at a commit (``files`` empty) or one side of a pair (``files`` holds the
    excerpt). ``family`` is the verify family, ``""`` when the unit is classified by ``roles`` only."""

    name: str
    source: str
    ref: str
    side: str
    repo: str
    pin: str
    family: str
    candidates: tuple[Candidate, ...]
    files: tuple[tuple[str, str], ...] = field(default=())
    verify: tuple[Candidate, ...] = field(default=())  # the candidates of ``family`` (all of them when empty)
    sizes: tuple[tuple[str, int, int], ...] = field(default=())  # (path, characters, lines) of a pin's candidate files

    @property
    def paths(self) -> list[str]:
        return sorted({c[0] for c in self.candidates})

    def index_row(self) -> dict[str, Any]:
        return {"source": self.source, "ref": self.ref, "side": self.side, "repo": self.repo, "pin": self.pin,
                "family": self.family, "candidates": [list(c) for c in self.candidates]}  # fmt: skip


def _opaque(*parts: str) -> str:
    return "h-" + hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:12]


def blob_sha1(text: str) -> str:
    data = text.encode("utf-8")
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def declaration_line(lines: Sequence[str] | None, path: str, function: str) -> int:
    """1-based line of the first declaration of ``function`` in ``lines``; 1 for ``<global>`` or when not declared."""
    pattern = DECLARATION.get(detect_language(Path(path)) or "")
    if not lines or pattern is None or function == GLOBAL:
        return 1
    return next((i + 1 for i, line in enumerate(lines) if _declared_name(pattern, line) == function), 1)


def _read_labels(labels: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in labels.read_text(encoding="utf-8").splitlines() if line.strip()]


def pair_units(labels: Path, catalog: Path) -> list[Unit]:
    """Both sides of every labelled pair (pin units), each with its labelled candidates of every family; ``family`` is
    the pair's verify family when it has one."""
    from ..pairs import load_pair_catalog

    wanted: dict[str, dict[str, set[str]]] = {}
    for row in _read_labels(labels):
        if row["source"] == "pairs" and row["unit"] == "pin":
            wanted.setdefault(row["source_ref"], {}).setdefault(row["family"], set()).add(row["candidate"])
    cases = {case.name: case for case in load_pair_catalog(catalog)}
    out: list[Unit] = []
    for name in sorted(wanted):
        case = cases[name]
        families = wanted[name]
        verify = sorted(f for f in families if f in OPERATIONS)
        for side in ("vuln", "fixed"):
            excerpt = case.vuln_file if side == "vuln" else case.fixed_file
            if not excerpt.is_file():
                raise ValueError(f"{name}: the {side} excerpt is not materialised ({excerpt}); fetch pointer pairs first")
            texts = {case.relpath: excerpt.read_text(encoding="utf-8", errors="replace")}
            for relpath, vuln_doc, fixed_doc in case.context_files:
                texts[relpath] = (vuln_doc if side == "vuln" else fixed_doc).read_text(encoding="utf-8", errors="replace")
            lines = {path: text.splitlines() for path, text in texts.items()}

            def located(names: Iterable[str], lines: Mapping[str, list[str]] = lines) -> tuple[Candidate, ...]:
                return tuple(sorted({(p, fn, declaration_line(lines.get(p), p, fn)) for c in names for p, _, fn in [c.partition("::")]}))

            role = "vulnerable" if side == "vuln" else "fixed"
            out.append(Unit(
                _opaque("pairs", name, side), "pairs", name, role, case.repo or f"pairs/{case.slice}/{name}",
                blob_sha1(texts[case.relpath]), verify[0] if verify else "", located(set().union(*families.values())),
                tuple(sorted(texts.items())), located(families[verify[0]]) if verify else (),
            ))  # fmt: skip
    return out


def population_units(labels: Path, cache: Path) -> list[Unit]:
    """One unit per (repository, pin, family) of the population, recipe and adjudication pin labels, candidates with
    their declaration line at that pin (read from the case clone or the recipe checkout). ``family`` is set for the
    development cases' verify families (:data:`VERIFY_SOURCES`, and v1 adjudications), else ``""``."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in _read_labels(labels):
        if row["unit"] != "pin" or row["source"] not in POPULATION_SOURCES:
            continue
        key = (row["repo"], row["pin"], row["family"])
        group = groups.setdefault(key, {"sources": set(), "refs": set(), "side": row["pin_role"], "candidates": set()})
        group["sources"].add(row["split"] if row["source"] == "adjudications" else row["source"])
        group["refs"].add(row["source_ref"])
        group["candidates"].add(row["candidate"])
    case_ids = {r: ref for (r, _, _), g in groups.items() for ref in g["refs"] if ":" not in ref and "#" not in ref}
    out: list[Unit] = []
    for (repo, pin, family), group in sorted(groups.items()):
        source = sorted(group["sources"])[0]
        ref = case_ids[repo] if source.startswith("population") and repo in case_ids else str(sorted(group["refs"])[0])
        reader = _reader(cache, source, ref, pin)
        texts = {p: reader(p) for p in {c.partition("::")[0] for c in group["candidates"]}}
        candidates = sorted({(p, fn, declaration_line(texts[p], p, fn)) for c in group["candidates"] for p, _, fn in [c.partition("::")]})
        sizes = tuple((p, sum(len(x) + 1 for x in t), len(t)) for p, t in sorted(texts.items()) if t is not None)
        verify = family if family in OPERATIONS and source in VERIFY_SOURCES else ""
        out.append(Unit(_opaque(repo, pin, family), source, ref, group["side"], repo, pin, verify, tuple(candidates), sizes=sizes))
    return out


def _reader(cache: Path, source: str, ref: str, pin: str) -> Any:
    """Lines of a path at the pin: the case clone (populations), else the recipe checkout (dev-php)."""
    from ..learn.labels import Clone, LabelSourceError

    if source == "dev-php":
        root = cache / "repos" / ref.split(":")[0] / pin[:12]
        return lambda path: (root / path).read_text(encoding="utf-8", errors="replace").splitlines() if (root / path).is_file() else None
    try:
        clone = Clone(cache / "independent" / ref)
    except LabelSourceError:
        return lambda path: None
    return lambda path: clone.lines(pin, path)


# --- manifests -------------------------------------------------------------------------------------------------------


def _git_workspace(unit: Unit) -> dict[str, Any]:
    doc = _doc("Workspace", _ax_name(unit.name, "pin"), {"git": [{"name": REPO, "repo": unit.repo, "dir": REPO, "depth": 1}]}, ATESPACE)
    doc["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"{REPO}={unit.pin}"}
    return doc


def _files_workspace(name: str, files: Mapping[str, str]) -> dict[str, Any]:
    return _doc("Workspace", name, {"files": [{"path": k, "content": v} for k, v in sorted(files.items())]}, ATESPACE)


def _verify_docs(unit: Unit, templates: Mapping[str, Task], usd_per_hunt: float) -> tuple[list[dict], list[dict], list[dict]]:
    """(Workspaces, Tasks, Run entries) of one verify unit."""
    asked = list(unit.verify or unit.candidates)
    candidates = {"family": unit.family, "candidates": [list(c) for c in asked]}
    hunts = max(len(units_of(asked)), 1)
    budget = {"usd": math.floor(hunts * usd_per_hunt * 1000) / 1000, "calls": hunts * CALLS_PER_HUNT}
    on_repo = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/{REPO}"}
    workspaces: list[dict] = []
    tasks: list[dict] = []
    entries: list[dict] = []
    if unit.files:
        files = {f"{REPO}/{path}": text for path, text in unit.files} | {"inputs/candidates.json": _json(candidates)}
        workspace = _files_workspace(_ax_name(unit.name, "side"), files)
        workspaces.append(workspace)
        bindings = [(workspace["metadata"]["name"], CASE_PATH)]
        inputs = f"{CASE_PATH}/inputs/candidates.json"
    else:
        pinned = _git_workspace(unit)
        functions = [{"path": p, "function": fn, "line": ln} for p, fn, ln in asked]
        files_doc = _files_workspace(
            _ax_name(unit.name, "inputs"), {"candidates.json": _json(candidates), "functions.json": _json(functions)}
        )
        workspaces += [pinned, files_doc]
        bindings = [(pinned["metadata"]["name"], CASE_PATH), (files_doc["metadata"]["name"], INPUTS_PATH)]
        inputs = f"{INPUTS_PATH}/candidates.json"
        facts_env = {**on_repo, "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/functions.json"}
        tasks.append(_task(templates["repo-facts"], f"repo-facts-{unit.name}", facts_env, bindings))
        entries.append({"name": f"{unit.name}-facts", "task": f"repo-facts-{unit.name}", "outputs": ["facts.json", "summary.json"],
                        "budget": {"usd": 0, "calls": 0}, "serialize": "repo-facts"})  # fmt: skip
    for label in ("a", "b"):
        env = {**on_repo, "OUSAST_INPUT_CANDIDATES": inputs, "OUSAST_PASS": label}
        tasks.append(_task(templates["verify"], f"verify-{label}-{unit.name}", env, bindings))
        entry: dict[str, Any] = {"name": f"{unit.name}-v{label}", "task": f"verify-{label}-{unit.name}",
                                 "outputs": ["units.jsonl", "summary.json"], "budget": dict(budget)}  # fmt: skip
        if not unit.files:
            entry["inputs"] = {"facts": f"{unit.name}-facts/facts.json"}
        entries.append(entry)
    tasks.append(
        _task(templates["agree"], f"agree-{unit.name}", {"OUSAST_INPUT_CANDIDATES": inputs}, bindings[-1:] if not unit.files else bindings)
    )
    entries.append({
        "name": f"{unit.name}-agree", "task": f"agree-{unit.name}",
        "inputs": {"pass_a": f"{unit.name}-va/units.jsonl", "pass_b": f"{unit.name}-vb/units.jsonl"},
        "outputs": ["agreed.json", "disputed.json", "summary.json"], "budget": {"usd": 0, "calls": 0},
    })  # fmt: skip
    return workspaces, tasks, entries


def _roles_estimate(sizes: Iterable[tuple[int, int]]) -> tuple[float, int]:
    """(usd, chunks) of classifying files of ``(characters, lines)``: input at ~3.5 characters a token plus the
    prompt, a generous output."""
    usd, chunks = 0.0, 0
    for characters, count in sizes:
        lines = max(count, 1)
        n = math.ceil(lines / CHUNK_LINES)
        tokens_in = (characters + 8 * lines) / 3.5 + 400 * n
        usd += tokens_in * PRICES["input_per_m"] / 1e6 + n * ROLES_OUTPUT_TOKENS * PRICES["output_per_m"] / 1e6
        chunks += n
    return usd, chunks


def _kind(unit: Unit) -> str:
    return "excerpt" if unit.files else "repository"


def _inline(unit: Unit, *, roles: bool = False) -> int:
    """Bytes of the unit's files a Workspace would carry inline (roles: its candidate files only)."""
    return sum(len(text.encode("utf-8")) for path, text in unit.files if not roles or path in unit.paths)


def oversized(unit: Unit) -> str | None:
    """Why a unit cannot run on ax, or None: its files exceed :data:`MAX_INLINE_BYTES`."""
    return f"excerpt {_inline(unit)} bytes over the {MAX_INLINE_BYTES}-byte inline limit" if _inline(unit) > MAX_INLINE_BYTES else None


def _roles_groups(units: Sequence[Unit]) -> list[list[Unit]]:
    groups: list[list[Unit]] = [[]]
    size = 0
    for unit in units:
        weight = _inline(unit, roles=True)
        if groups[-1] and (len(groups[-1]) >= ROLES_GROUP_FILES or size + weight > MAX_INLINE_BYTES):
            groups.append([])
            size = 0
        groups[-1].append(unit)
        size += weight
    return [g for g in groups if g]


def render_harvest(
    units: Sequence[Unit], templates: Mapping[str, Task], name: str, command: str, *, ceiling: float = 10.0
) -> dict[str, str]:
    """Relative path under the plane root -> file text: both Runs, their Workspaces and Tasks, and ``units.json``.
    A population file whose size is unknown is estimated at :data:`UNKNOWN_SIZE`."""
    header = f"# generated by `{command}`; do not edit, regenerate.\n"
    out: dict[str, str] = {}
    verify_units = [u for u in units if u.family and oversized(u) is None]
    hunts = sum(max(len(units_of(list(u.verify or u.candidates))), 1) for u in verify_units)
    wanted = 2 * sum(max(len(units_of(list(u.verify or u.candidates))), 1) * USD_PER_HUNT[_kind(u)] for u in verify_units)  # passes a, b
    scale = min(1.0, ceiling * 0.98 / wanted) if wanted else 1.0
    workspaces: list[dict] = []
    tasks: list[dict] = []
    entries: list[dict] = []
    for unit in verify_units:
        w, t, e = _verify_docs(unit, templates, USD_PER_HUNT[_kind(unit)] * scale)
        workspaces += w
        tasks += t
        entries += e
    out.update(_run_files(header, f"{name}-verify", workspaces, tasks, entries, f"{len(verify_units)} units, {hunts} hunts per pass"))
    emitted = {w["metadata"]["name"] for w in workspaces}  # a pin Workspace both Runs bind is written once
    workspaces, tasks, entries, estimates = [], [], [], []
    for group in _roles_groups([u for u in units if u.files and _inline(u, roles=True) <= MAX_INLINE_BYTES]):
        files = {f"{REPO}/{u.name}/{p}": t for u in group for p, t in u.files if p in u.paths}
        listing = sorted(f.removeprefix(f"{REPO}/") for f in files)
        workspace = _files_workspace(_ax_name(name, "roles", group[0].name), files | {"inputs/files.json": _json(listing)})
        workspaces.append(workspace)
        estimates.append(_roles_estimate((len(text), len(text.splitlines())) for text in files.values()))
        bound = [(workspace["metadata"]["name"], CASE_PATH)]
        env = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/{REPO}", "OUSAST_INPUT_FILES": f"{CASE_PATH}/inputs/files.json"}
        tasks.append(_task(templates["roles"], f"roles-{group[0].name}", env, bound))
        entries.append(
            {"name": f"{group[0].name}-roles", "task": f"roles-{group[0].name}", "outputs": ["roles.json", "units.jsonl", "summary.json"]}
        )
    seen: set[tuple[str, str]] = set()
    for unit in (u for u in units if not u.files):
        if (unit.repo, unit.pin) in seen:
            continue
        seen.add((unit.repo, unit.pin))
        same = [u for u in units if not u.files and (u.repo, u.pin) == (unit.repo, unit.pin)]
        paths = sorted({p for u in same for p in u.paths})
        known = {p: (chars, lines) for u in same for p, chars, lines in u.sizes}
        pinned = _git_workspace(unit)
        files_doc = _files_workspace(_ax_name(unit.name, "roles-in"), {"files.json": _json(paths)})
        workspaces += [w for w in (pinned, files_doc) if w["metadata"]["name"] not in emitted]
        estimates.append(_roles_estimate(known.get(p, UNKNOWN_SIZE) for p in paths))
        bound = [(pinned["metadata"]["name"], CASE_PATH), (files_doc["metadata"]["name"], INPUTS_PATH)]
        env = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/{REPO}", "OUSAST_INPUT_FILES": f"{INPUTS_PATH}/files.json"}
        tasks.append(_task(templates["roles"], f"roles-{unit.name}", env, bound))
        entries.append(
            {"name": f"{unit.name}-roles", "task": f"roles-{unit.name}", "outputs": ["roles.json", "units.jsonl", "summary.json"]}
        )
    wanted = sum(usd for usd, _ in estimates) * ROLES_HEADROOM
    scale = min(1.0, ceiling * 0.98 / wanted) if wanted else 1.0
    for entry, (usd, chunks) in zip(entries, estimates, strict=True):
        entry["budget"] = {"usd": max(math.floor(usd * ROLES_HEADROOM * scale * 1000) / 1000, 0.001), "calls": chunks * 2 + 2}
    out.update(_run_files(header, f"{name}-roles", workspaces, tasks, entries, f"{len(entries)} roles tasks"))
    index = {u.name: u.index_row() | ({"skipped": oversized(u)} if oversized(u) else {}) for u in units}
    out["units.json"] = json.dumps(index, indent=1, sort_keys=True) + "\n"
    return out


def _run_files(header: str, run: str, workspaces: list[dict], tasks: list[dict], entries: list[dict], note: str) -> dict[str, str]:
    total = sum(float(e["budget"]["usd"]) for e in entries)
    metadata = {"name": run, "annotations": {"openultrasast.io/population": "harvest", "openultrasast.io/split": "learn"}}
    doc = {"apiVersion": RUN_API_VERSION, "kind": "Run", "metadata": metadata, "spec": {"tasks": entries}}
    files = {f"workspaces/{run}.yaml": _dump(header, workspaces), f"tasks/{run}.yaml": _dump(header, tasks)}
    files[f"runs/{run}.yaml"] = _dump(header + f"# {note}; usd ceiling {total:.3f}.\n", [doc])
    return files


def write_harvest(
    labels: Path, plane: Path, *, name: str, command: str, catalog: Path, cache: Path, templates: Path, ceiling: float = 10.0
) -> dict[str, str]:
    """Build the units, render, write under ``plane`` (with the Model manifests copied beside); returns the rendered
    files."""
    from .manifests import load_manifests

    units = pair_units(labels, catalog) + population_units(labels, cache)
    loaded = load_manifests([templates / "tasks" / f"{n}.yaml" for n in ("repo-facts", "verify", "agree", "roles")]).tasks
    files = render_harvest(units, loaded, name, command, ceiling=ceiling)
    for path in sorted((templates / "models").glob("*.yaml")):
        files[f"models/{path.name}"] = path.read_text(encoding="utf-8")
    for relative, text in files.items():
        target = plane / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    yaml.safe_load_all(files[f"runs/{name}-verify.yaml"])  # parse check
    return files
