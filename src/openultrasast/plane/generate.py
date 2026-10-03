"""Manifests of a recorded measurement as a Run (ai-service-plane task 7).

``ousast plane workspaces <population.toml> --validation-set <set.json> --candidates <dir> --triage <dir>`` writes,
under ``--plane`` (default ``plane/``), everything a Run over the set needs beside the hand-written templates
(``tasks/repo-facts.yaml``, ``tasks/verify.yaml``, ``tasks/agree.yaml``, ``models/*.yaml``):

- ``workspaces/<case>-vulnerable.yaml``: the case's repository at its vulnerable pin (commit in the
  ``openultrasast.io/git-commits`` annotation, as :mod:`.workspaces` writes it);
- ``workspaces/<case>-inputs.yaml``: a files-only Workspace with the inputs no task produces -- the recorded
  candidates (``candidates.json`` in the ``independent-v2-modelsinks`` shape for ``verify`` and ``agree``,
  ``functions.json`` as ``{path, function, line}`` rows for ``repo-facts``), everything ``agree`` scores by
  (``case.json``: the declared sites, the old-side fix ranges exactly as ``evaluate.hunks(case, "old")`` computes
  them from ``--repos``, the declared sites among the set's candidates -- the reference's "of 20" -- and the
  reference's cost: candidates before triage, recorded usd, and the triage share of it) and the recorded triage
  (``triage.json``, for the measurement);
- ``tasks/<run>.yaml``: per case, one Task per template (two for ``verify``: ``OUSAST_PASS=a|b``) binding the two
  Workspaces and naming the files as env;
- ``runs/<run>.yaml``: the Run, per case ``facts -> verify a, verify b -> agree -> verify c -> final -> features ->
  remember`` (``features``: one allow-listed feature record per candidate, learned-decision-engine task 1),
  with budgets, annotated with the population and split (``openultrasast.io/population``/``split``: the files'
  stems) the memory rows carry.

``--loop`` (harnessx-removal design section 6) appends the improvement loop: per case ``alerts`` (quick-mode rules
on the vulnerable and the fixed pin, which gets its Workspace ``<case>-fixed``; ``case.json`` then also carries the
fix's new-side ranges) feeding ``remember``, and once ``memory-snapshot`` (the store's rows after the train-on-test
guard, written on the host by ``memory.seed``) -> ``loop-measure`` -> ``loop-propose`` -> ``loop-improve``, the last
two bound to this repository at the commit under test. All of them model-free with budget ``{usd: 0, calls: 0}``;
the gate's verdict is ``<run>/loop-improve/gate.json``, and adopting an accepted ledger stays a maintainer commit.

Each ``repo-facts`` Task carries ``openultrasast.io/memory-key`` (repository, pin, candidates digest, runner image
digest): the key under which stored facts are reused instead of recomputed (``plane/memory.py``, ``seed``).

Why per-case Tasks rather than one Task per step: an ax Task binds its Workspaces by name and a Run entry adds
neither a binding nor env (it names a Task, artifacts and a budget), and ``Run.inputs`` accepts only
``<task>/<artifact>``. So an input that no task produces is a Workspace ``files`` entry, and the case a step works
on is fixed by the Task it runs. One Run covers every case so the measurement has one state and one attribution
table.

Candidates are the set's ``(path, function)`` pairs with the line of the case record, deduplicated the way
``benchmarks/independent/verify_batched.py`` does (sorted, the last line of a repeated pair wins), and filtered
by the recorded triage (the ``kept`` lists of the batched-check scans): ``verify`` has no triage stage, so the
hunts see exactly the candidates the reference hunts saw. Output is a pure function of the inputs.

The recorded triage cost is derived per file: a batched-check record's ``usd`` paid for the triage call and the
hunts, and its ``usage`` counts only the hunts (``verify_sinks._Recording`` slices the client's usage from the
first hunt on), so the triage share is ``usd`` minus that usage priced at the reference model's list price.

``--runner-image FILE`` (the profile's images file, ``ops/k8s/profiles/kind-images.json``, written by ``ops/ax/up.sh``;
the older one-line pin file still reads) re-pins the templates' ``image:`` to the runner digest in that file before
generating, so a rebuilt image is one command.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..model.endpoint import price_of
from .budget import cost_of
from .manifests import GIT_COMMITS_ANNOTATION, RUN_API_VERSION, Task, load_manifests
from .memory import MEMORY_KEY_ANNOTATION, POPULATION_ANNOTATION, SNAPSHOT_ANNOTATION, SPLIT_ANNOTATION, memory_key
from .reconciler import _ax_name, _doc
from .tasks.repo_facts import _digest
from .tasks.verify import MAX_STEPS, units_of

__all__ = ["CaseInputs", "Loop", "fix_ranges", "increment", "read_cases", "render", "repin_templates"]

REFERENCE_USD_PER_CANDIDATE = 0.022  # two passes: verifier-batched-check-2026-09-29.json cost.usd_per_candidate_two_passes
REFERENCE_MODEL = "deepseek-flash"  # verify_batched.py's default (DEFAULT_DETECTOR_MODEL) in the batched check
TRIAGE_BASIS = (
    "derived per file from the batched-check scans: recorded usd (triage + hunts) minus the recorded hunt usage "
    f"priced at {REFERENCE_MODEL} list prices; the triage call's own usage was not recorded"
)
RANGES_BASIS = "git diff -U0 <vulnerable> <fixed>, old side: benchmarks/independent/evaluate.hunks(case, 'old')"
HEADROOM = 1.5
CALLS_PER_HUNT = MAX_STEPS + 2  # every tool step, the answer, one empty-content retry
ATESPACE = "default"  # the default when no profile is given; ``increment`` takes ``profile.atespace``
CASE_PATH = "/workspace/case"
INPUTS_PATH = "/workspace/inputs"
FIXED_PATH = "/workspace/fixed"
PROJECT_PATH = "/workspace/project"
TEMPLATES = ("repo-facts", "verify", "agree", "remember", "alerts", "loop", "features", "roles")
FIXED_RANGES_BASIS = "git diff -U0 <vulnerable> <fixed>, new side: the fix's lines at the fixed pin"
LOOP_MANIFEST = "benchmarks/manifests/java-spring-boot-vulnerable.toml"  # the equality baseline's `improve` manifest
LOOP_CATALOG = "benchmarks/pairs/catalog.toml"

Candidate = tuple[str, str, int]


@dataclass(frozen=True)
class CaseInputs:
    case: Mapping[str, Any]
    candidates: tuple[Candidate, ...]
    kept: tuple[Candidate, ...]
    triage: Mapping[str, str]
    recorded_usd: float
    triage_usd: float = 0.0
    ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None
    fixed_ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None


@dataclass(frozen=True)
class Loop:
    """The improvement loop appended to a Run (``--loop``, design section 6): ``repo`` at ``commit`` is this
    repository at the commit under test, where ``manifest`` and ``catalog`` (paths inside it) gate the proposals;
    rows of ``populations`` never propose (the train-on-test guard)."""

    repo: str
    commit: str
    manifest: str = LOOP_MANIFEST
    catalog: str = LOOP_CATALOG
    populations: tuple[str, ...] = ()


def fix_ranges(repo: Path, vulnerable: str, fixed: str, side: str = "old") -> dict[str, list[tuple[int, int]]]:
    """Changed line ranges per file on the vulnerable side of the fix: `evaluate.hunks(case, "old")`, line for
    line (including its attribution of a hunk under ``--- /dev/null`` to the file before it). ``side="new"`` is
    the same on the fixed side (``+++ b/`` paths, the ``+`` spans): where a fixed-pin alert sits inside the fix."""
    if not (repo / ".git").exists() and not (repo / "HEAD").is_file():
        raise ValueError(f"no repository at {repo}: the fix ranges cannot be computed")
    diff = subprocess.run(["git", "-C", str(repo), "diff", "-U0", vulnerable, fixed], capture_output=True, text=True, check=True).stdout
    ranges: dict[str, list[tuple[int, int]]] = {}
    current = ""
    header, group = ("--- a/", 1) if side == "old" else ("+++ b/", 3)
    for line in diff.splitlines():
        if line.startswith(header):
            current = line[6:]
        elif line.startswith("@@") and current:
            match = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?", line)
            if match:
                span = match.group(group + 1)
                first, length = int(match.group(group)), int(span) if span is not None else 1
                ranges.setdefault(current, []).append((first, first + max(length, 1) - 1))
    if not ranges:
        raise ValueError(f"{repo}: the diff {vulnerable[:12]}..{fixed[:12]} changed no line on the vulnerable side")
    return ranges


def _triage_usd(rows: Sequence[Mapping[str, Any]]) -> float:
    """The triage share of the recorded spend: per file, usd minus the recorded hunt usage at list price."""
    prices = price_of(REFERENCE_MODEL)
    if prices is None:
        raise ValueError(f"no recorded price for {REFERENCE_MODEL}")
    return round(sum(max(float(r.get("usd") or 0.0) - cost_of(r.get("usage") or {}, prices), 0.0) for r in rows), 6)


def _scan_rows(triage_dir: Path, case_id: str) -> list[dict[str, Any]]:
    path = triage_dir / f"{case_id}--vulnerable_a.jsonl"
    if not path.is_file():
        raise ValueError(f"{case_id}: no recorded triage at {path}")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = [r for r in rows if "unverified" not in r]
    if not rows:
        raise ValueError(f"{path}: no completed file record")
    return rows


def read_cases(
    validation_set: Path, candidates_dir: Path, triage_dir: Path, population: Path, repos: Path | None = None, *, fixed_side: bool = False
) -> list[CaseInputs]:
    """The set's cases in id order, each with its candidates, the triage-kept subset, the recorded cost and its
    triage share, and -- with ``repos`` (one clone per case id) -- the fix's old-side ranges (and, with
    ``fixed_side``, its new-side ranges, which the loop's `alerts` task marks fixed-pin alerts by)."""
    subset: dict[str, list[list[str]]] = json.loads(validation_set.read_text(encoding="utf-8"))
    records = {c["id"]: c for c in tomllib.loads(population.read_text(encoding="utf-8"))["case"]}
    cases: list[CaseInputs] = []
    for case_id in sorted(subset):
        if case_id not in records:
            raise ValueError(f"{validation_set}: case {case_id!r} is not in {population}")
        record = json.loads((candidates_dir / f"{case_id}.json").read_text(encoding="utf-8"))
        unique = {(str(p), str(fn)): (str(p), str(fn), int(ln)) for p, fn, ln in sorted(record["candidates"])}
        wanted = [(str(p), str(fn)) for p, fn, *_ in subset[case_id]]
        missing = [f"{p}::{fn}" for p, fn in wanted if (p, fn) not in unique]
        if missing:
            raise ValueError(f"{case_id}: set candidates absent from {candidates_dir / case_id}.json: {missing[:5]}")
        wanted_keys = set(wanted)
        chosen = [c for key, c in unique.items() if key in wanted_keys]
        rows = _scan_rows(triage_dir, case_id)
        asked = {(str(c[0]), str(c[1])): (str(c[0]), str(c[1]), int(c[2])) for r in rows for c in r["candidates"]}
        if sorted(asked.values()) != sorted(chosen):
            raise ValueError(f"{case_id}: the recorded scans asked {sorted(asked.values())[:3]}..., the set gives {chosen[:3]}...")
        kept_keys = {(str(r["path"]), str(fn)) for r in rows for fn in r.get("kept", [c[1] for c in r["candidates"]])}
        triage = {f"{r['path']}::{fn}": str(label) for r in rows for fn, label in sorted((r.get("triage") or {}).items())}
        cases.append(
            CaseInputs(
                case=records[case_id],
                candidates=tuple(chosen),
                kept=tuple(c for c in chosen if (c[0], c[1]) in kept_keys),
                triage=dict(sorted(triage.items())),
                recorded_usd=round(sum(float(r.get("usd") or 0.0) for r in rows), 6),
                triage_usd=_triage_usd(rows),
                ranges=None if repos is None else fix_ranges(repos / case_id, records[case_id]["vulnerable"], records[case_id]["fixed"]),
                fixed_ranges=(
                    fix_ranges(repos / case_id, records[case_id]["vulnerable"], records[case_id]["fixed"], side="new")
                    if repos is not None and fixed_side
                    else None
                ),
            )
        )
    return cases


def _dump(header: str, docs: Sequence[Mapping[str, Any]]) -> str:
    return header + str(yaml.safe_dump_all(list(docs), sort_keys=False, width=1000))


def _json(payload: object) -> str:
    return json.dumps(payload, indent=1, sort_keys=True) + "\n"


def _case_record(item: CaseInputs) -> dict[str, Any]:
    """What `agree` scores by: sites, fix ranges (absent without ``--repos``), sites in the set, reference cost."""
    case = item.case
    sites = [str(s) for s in case.get("sites", [])]
    in_set = {f"{p}::{fn}" for p, fn, _ in item.candidates}
    record: dict[str, Any] = {"id": case["id"], "family": case["family"], "sites": sites}
    if item.ranges is not None:
        record["ranges"] = {path: [list(span) for span in spans] for path, spans in item.ranges.items()}
        record["ranges_basis"] = RANGES_BASIS
    if item.fixed_ranges is not None:
        record["fixed_ranges"] = {path: [list(span) for span in spans] for path, spans in item.fixed_ranges.items()}
        record["fixed_ranges_basis"] = FIXED_RANGES_BASIS
    record["sites_in_set"] = [s for s in sites if s in in_set]
    record["cost"] = {
        "candidates_before_triage": len(item.candidates), "recorded_usd": item.recorded_usd,
        "recorded_triage_usd": item.triage_usd, "recorded_triage_basis": TRIAGE_BASIS,
    }  # fmt: skip
    return record


def _workspaces(item: CaseInputs, atespace: str = ATESPACE) -> tuple[dict[str, Any], dict[str, Any]]:
    case = item.case
    git = [{"name": "repo", "repo": case["repo"], "dir": "repo", "depth": 1}]
    pinned = _doc("Workspace", _ax_name(case["id"], "vulnerable"), {"git": git}, atespace)
    pinned["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"repo={case['vulnerable']}"}
    files = {
        "candidates.json": _json({"id": case["id"], "family": case["family"], "candidates": [list(c) for c in item.kept]}),
        "functions.json": _json([{"path": p, "function": fn, "line": ln} for p, fn, ln in item.kept]),
        "case.json": _json(_case_record(item)),
        "triage.json": _json(
            {"candidates": [list(c) for c in item.candidates], "kept": [list(c) for c in item.kept], "triage": dict(item.triage)}
        ),
    }
    inputs = _doc("Workspace", _ax_name(case["id"], "inputs"), {"files": [{"path": k, "content": v} for k, v in files.items()]}, atespace)
    return pinned, inputs


def _task(
    template: Task, name: str, env: Mapping[str, str], bindings: Sequence[tuple[str, str]], command: Sequence[str] = ()
) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if template.image:
        spec["image"] = template.image
    spec["command"] = [*template.command, *command]
    spec["env"] = [{"name": e.name, "value": e.value} for e in template.env] + [{"name": k, "value": v} for k, v in env.items()]
    if template.resources:
        kinds = {kind: values for kind, values in vars(template.resources).items() if values is not None}
        spec["resources"] = {kind: {k: v for k, v in vars(values).items() if v is not None} for kind, values in kinds.items()}
    spec["workspaces"] = [{"name": n, "path": p} for n, p in bindings]
    if template.debug:
        spec["debug"] = True
    doc = _doc("Task", name, spec, template.metadata.atespace)
    if template.metadata.annotations:
        doc["metadata"]["annotations"] = dict(template.metadata.annotations)
    return doc


def verify_budget(item: CaseInputs) -> dict[str, float | int]:
    """One verify pass: 1.5x its share of the case's recorded two-pass cost (at least the set's per-candidate
    average times the case's candidates), rounded up to a cent; calls: every hunt at its step ceiling."""
    share = max(item.recorded_usd, REFERENCE_USD_PER_CANDIDATE * len(item.candidates)) / 2
    hunts = len(units_of(list(item.kept)))
    return {"usd": math.ceil(HEADROOM * share * 100 - 1e-9) / 100, "calls": max(hunts, 1) * CALLS_PER_HUNT}


def _tiebreak_entries(item: CaseInputs) -> list[dict[str, Any]]:
    """The tie-break (Requirement 6.4): verify pass c on the candidates a and b disputed, then agree 2-of-3. Fresh
    budget dicts, so YAML adds no anchor to the entries before them."""
    case_id = item.case["id"]
    return [
        {
            "name": f"{case_id}-vc", "task": f"verify-c-{case_id}", "dependsOn": [f"{case_id}-agree"],
            "inputs": {"facts": f"{case_id}-facts/facts.json", "only": f"{case_id}-agree/disputed.json"},
            "outputs": ["units.jsonl", "summary.json"], "budget": verify_budget(item),
        },
        {
            "name": f"{case_id}-final", "task": f"agree-{case_id}",
            "inputs": {pass_: f"{case_id}-v{pass_[-1]}/units.jsonl" for pass_ in ("pass_a", "pass_b", "pass_c")},
            "outputs": ["agreed.json", "disputed.json"], "budget": {"usd": 0, "calls": 0},
        },
    ]  # fmt: skip


def _free() -> dict[str, int]:
    return {"usd": 0, "calls": 0}  # model-free: budget.py refuses any call, so a stray one fails loudly


def _chain_inputs(case_id: str, alerts: bool) -> dict[str, str]:
    """Every artifact of a case's chain -- facts, the three passes with their summaries, the final agree -- and, in a
    loop, its alerts with their coverage."""
    inputs = {"facts": f"{case_id}-facts/facts.json", "facts_summary": f"{case_id}-facts/summary.json"}
    for label in ("a", "b", "c"):
        inputs.update({f"pass_{label}": f"{case_id}-v{label}/units.jsonl", f"summary_{label}": f"{case_id}-v{label}/summary.json"})
    inputs["agreed"] = f"{case_id}-final/agreed.json"
    if alerts:
        inputs["alerts"] = f"{case_id}-alerts/alerts.jsonl"
        inputs["alerts_summary"] = f"{case_id}-alerts/summary.json"  # the coverage: whether a zero could mean clean
    return inputs


def _features(item: CaseInputs, templates: Mapping[str, Task], alerts: bool) -> tuple[dict, dict]:
    """(Task, Run entry) of the case's `features` (learned-decision-engine design section 1): model-free, bound to the
    vulnerable Workspace for the functions' spans and entry-point distance; the chain's artifacts as input."""
    case_id = item.case["id"]
    env = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/repo"}
    task = _task(templates["features"], f"features-{case_id}", env, [(_ax_name(case_id, "vulnerable"), CASE_PATH)])
    inputs = _chain_inputs(case_id, alerts)
    entry = {"name": f"{case_id}-features", "task": f"features-{case_id}", "inputs": inputs, "outputs": ["features.jsonl", "summary.json"]}
    return task, {**entry, "budget": _free()}


def _remember(item: CaseInputs, templates: Mapping[str, Task], population: str, split: str, alerts: bool) -> tuple[dict, dict]:
    """(Task, Run entry) of the case's `remember` (design section 4): bound to the vulnerable Workspace for the
    repository and pin its rows carry; every artifact of the case's chain (and, in a loop, its alerts) and the case's
    feature records as input."""
    case_id = item.case["id"]
    env = {"OUSAST_POPULATION": population or "unknown", "OUSAST_SPLIT": split or "unknown"}
    task = _task(templates["remember"], f"remember-{case_id}", env, [(_ax_name(case_id, "vulnerable"), CASE_PATH)])
    inputs = {**_chain_inputs(case_id, alerts), "features": f"{case_id}-features/features.jsonl"}
    entry = {"name": f"{case_id}-remember", "task": f"remember-{case_id}", "inputs": inputs, "outputs": ["memory.jsonl"], "budget": _free()}
    return task, entry


def _alerts(item: CaseInputs, templates: Mapping[str, Task], atespace: str = ATESPACE) -> tuple[dict, dict, dict]:
    """(fixed-pin Workspace, Task, Run entry) of the case's `alerts`: quick-mode rules on both pins."""
    case = item.case
    git = [{"name": "repo", "repo": case["repo"], "dir": "repo", "depth": 1}]
    fixed = _doc("Workspace", _ax_name(case["id"], "fixed"), {"git": git}, atespace)
    fixed["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"repo={case['fixed']}"}
    bindings = [(_ax_name(case["id"], "vulnerable"), CASE_PATH), (fixed["metadata"]["name"], FIXED_PATH)]
    bindings.append((_ax_name(case["id"], "inputs"), INPUTS_PATH))
    env = {
        "OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/repo", "OUSAST_FIXED_DIR": f"{FIXED_PATH}/repo",
        "OUSAST_INPUT_CASE": f"{INPUTS_PATH}/case.json", "OUSAST_VULNERABLE_PIN": str(case["vulnerable"]),
        "OUSAST_FIXED_PIN": str(case["fixed"]),
    }  # fmt: skip
    task = _task(templates["alerts"], f"alerts-{case['id']}", env, bindings)
    entry = {"name": f"{case['id']}-alerts", "task": f"alerts-{case['id']}", "outputs": ["alerts.jsonl", "summary.json"], "budget": _free()}
    entry["serialize"] = "engine"
    return fixed, task, entry


def _loop(
    cases: Sequence[CaseInputs], templates: Mapping[str, Task], loop: Loop, atespace: str = ATESPACE
) -> tuple[dict, list[dict], list[dict]]:
    """(project Workspace, Tasks, Run entries) of the loop's singletons: snapshot -> measure -> propose -> improve."""
    git = [{"name": "repo", "repo": loop.repo, "dir": "repo", "depth": 1}]
    project = _doc("Workspace", _ax_name("openultrasast", loop.commit[:12]), {"git": git}, atespace)
    project["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"repo={loop.commit}"}
    bound = [(project["metadata"]["name"], PROJECT_PATH)]
    env = {
        "OUSAST_PROJECT_DIR": f"{PROJECT_PATH}/repo", "OUSAST_LOOP_MANIFEST": loop.manifest, "OUSAST_LOOP_CATALOG": loop.catalog,
        "OUSAST_QUALIFY_POPULATIONS": json.dumps(sorted(loop.populations)),
    }  # fmt: skip
    snapshot = _task(templates["loop"], "memory-snapshot", {}, [], ["snapshot"])
    guard = {"catalog": loop.catalog, "manifest": loop.manifest, "populations": sorted(loop.populations)}
    snapshot["metadata"].setdefault("annotations", {})[SNAPSHOT_ANNOTATION] = json.dumps(guard, sort_keys=True, separators=(",", ":"))
    tasks = [
        snapshot, _task(templates["loop"], "loop-measure", {}, [], ["measure"]),
        _task(templates["loop"], "loop-propose", env, bound, ["propose"]),
        _task(templates["loop"], "loop-improve", env, bound, ["improve"]),
    ]  # fmt: skip
    remembered = {f"remember_{c.case['id']}": f"{c.case['id']}-remember/memory.jsonl" for c in cases}
    entries = [
        {"name": "memory-snapshot", "task": "memory-snapshot", "outputs": ["rows.jsonl", "index.json"], "budget": _free()},
        {"name": "loop-measure", "task": "loop-measure", "inputs": {**remembered, "snapshot": "memory-snapshot/rows.jsonl"},
         "outputs": ["measure.json", "rows.jsonl"], "budget": _free()},
        {"name": "loop-propose", "task": "loop-propose",
         "inputs": {"measure": "loop-measure/measure.json", "rows": "loop-measure/rows.jsonl", "index": "memory-snapshot/index.json"},
         "outputs": ["proposals.jsonl", "memory_proposals.jsonl", "signals.json"], "budget": _free()},
        {"name": "loop-improve", "task": "loop-improve", "inputs": {"proposals": "loop-propose/proposals.jsonl"},
         "outputs": ["gate.json", "journal.json"], "budget": _free(), "serialize": "engine"},
    ]  # fmt: skip
    return project, tasks, entries


def render(
    cases: Sequence[CaseInputs],
    templates: Mapping[str, Task],
    run_name: str,
    command: str,
    *,
    population: str = "",
    split: str = "",
    loop: Loop | None = None,
    atespace: str = ATESPACE,
) -> dict[str, str]:
    """Relative path under the plane root -> file text, for every generated manifest. ``population`` and ``split``
    (the population file's and the set's stems) become the Run's annotations, which the memory rows carry. Each
    case ends in `features` -> `remember`; ``loop`` adds per case `alerts` (and the fixed-pin Workspace), and once the
    snapshot, `loop-measure`, `loop-propose` and `loop-improve` (design section 6), all model-free."""
    header = f"# generated by `{command}`; do not edit, regenerate.\n"
    out: dict[str, str] = {}
    tasks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    tiebreak: list[dict[str, Any]] = []
    for item in cases:
        case_id = item.case["id"]
        pinned, inputs = _workspaces(item, atespace)
        for doc in (pinned, inputs):
            out[f"workspaces/{doc['metadata']['name']}.yaml"] = _dump(header, [doc])
        repo = [(pinned["metadata"]["name"], CASE_PATH), (inputs["metadata"]["name"], INPUTS_PATH)]
        on_repo = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/repo"}
        facts_env = {**on_repo, "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/functions.json"}
        facts_task = _task(templates["repo-facts"], f"repo-facts-{case_id}", facts_env, repo)
        digest = _digest(sorted({fn for _, fn, _ in item.kept}))
        key = memory_key(str(item.case["repo"]), str(item.case["vulnerable"]), digest, templates["repo-facts"].image or "")
        facts_task["metadata"].setdefault("annotations", {})[MEMORY_KEY_ANNOTATION] = key
        tasks.append(facts_task)
        for label in ("a", "b"):
            env = {**on_repo, "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/candidates.json", "OUSAST_PASS": label}
            tasks.append(_task(templates["verify"], f"verify-{label}-{case_id}", env, repo))
        agree_env = {
            "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/candidates.json",
            "OUSAST_INPUT_SITES": f"{INPUTS_PATH}/case.json",
            "OUSAST_CASE_ID": case_id,
        }
        tasks.append(_task(templates["agree"], f"agree-{case_id}", agree_env, repo[1:]))
        free = {"usd": 0, "calls": 0}
        facts = {"name": f"{case_id}-facts", "task": f"repo-facts-{case_id}", "outputs": ["facts.json"], "budget": free}
        entries.append({**facts, "serialize": "repo-facts"})
        for label in ("a", "b"):
            entries.append({
                "name": f"{case_id}-v{label}", "task": f"verify-{label}-{case_id}", "inputs": {"facts": f"{case_id}-facts/facts.json"},
                "outputs": ["units.jsonl", "summary.json"], "budget": verify_budget(item),
            })  # fmt: skip
        entries.append({
            "name": f"{case_id}-agree", "task": f"agree-{case_id}",
            "inputs": {"pass_a": f"{case_id}-va/units.jsonl", "pass_b": f"{case_id}-vb/units.jsonl"},
            "outputs": ["agreed.json", "disputed.json"], "budget": free,
        })  # fmt: skip
        env = {**on_repo, "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/candidates.json", "OUSAST_PASS": "c"}
        tasks.append(_task(templates["verify"], f"verify-c-{case_id}", env, repo))
        tiebreak.extend(_tiebreak_entries(item))
    tasks.sort(key=lambda doc: 1 if doc["metadata"]["name"].startswith("verify-c-") else 0)  # stable: the old Tasks first
    entries.extend(tiebreak)  # appended: the first Run's entries stay byte-identical, so a rerun keeps their state
    for item in cases:  # appended after the tie-break for the same reason
        if loop is not None:
            fixed, alerts_task, alerts_entry = _alerts(item, templates, atespace)
            out[f"workspaces/{fixed['metadata']['name']}.yaml"] = _dump(header, [fixed])
            tasks.append(alerts_task)
            entries.append(alerts_entry)
        features_task, features_entry = _features(item, templates, loop is not None)
        tasks.append(features_task)
        entries.append(features_entry)
        remember_task, remember_entry = _remember(item, templates, population, split, loop is not None)
        tasks.append(remember_task)
        entries.append(remember_entry)
    if loop is not None:
        project, loop_tasks, loop_entries = _loop(cases, templates, loop, atespace)
        out[f"workspaces/{project['metadata']['name']}.yaml"] = _dump(header, [project])
        tasks.extend(loop_tasks)
        entries.extend(loop_entries)
    out[f"tasks/{run_name}.yaml"] = _dump(header, tasks)
    annotations = {k: v for k, v in ((POPULATION_ANNOTATION, population), (SPLIT_ANNOTATION, split)) if v}
    metadata: dict[str, Any] = {"name": run_name, **({"annotations": annotations} if annotations else {})}
    run = {"apiVersion": RUN_API_VERSION, "kind": "Run", "metadata": metadata, "spec": {"tasks": entries}}
    total = sum(float(e["budget"]["usd"]) for e in entries)
    candidates = sum(len(c.candidates) for c in cases)
    kept = sum(len(c.kept) for c in cases)
    note = f"# {len(cases)} cases, {candidates} candidates ({kept} kept by the recorded triage); usd ceiling {total:.2f}.\n"
    out[f"runs/{run_name}.yaml"] = _dump(header + note, [run])
    return out


_IMAGE_LINE = re.compile(r'^(\s*image:\s*)"?[^"\s]+"?\s*$', re.MULTILINE)


def repin_templates(plane: Path, image_file: Path) -> str:
    """Set every template's ``image:`` to the runner reference of ``image_file``: a profile images file
    (``{"runner": "<registry>/<name>@sha256:..."}``, as ``ops/ax/up.sh`` writes it) or the older one-line pin; a
    reference without a digest is refused. Comments and layout are kept. Returns the reference. (Task 4.3 gives
    the engine template ``images["engine"]``; until then only the runner key is read.)"""
    from .profile import ProfileError, load_images

    try:
        image = load_images(image_file)["runner"]
    except ProfileError as exc:
        raise ValueError(str(exc)) from None
    except KeyError:
        raise ValueError(f"{image_file}: no runner image in the images file") from None
    for name in TEMPLATES:
        path = plane / "tasks" / f"{name}.yaml"
        text = path.read_text(encoding="utf-8")
        pinned, count = _IMAGE_LINE.subn(lambda m: f'{m.group(1)}"{image}"', text)
        if count != 1:
            raise ValueError(f"{path}: {count} image lines, expected one")
        path.write_text(pinned, encoding="utf-8")
    return image


def increment(
    population: Path,
    validation_set: Path,
    candidates_dir: Path,
    triage_dir: Path,
    *,
    plane: Path,
    run_name: str,
    command: str,
    repos: Path | None = None,
    runner_image: Path | None = None,
    loop: Loop | None = None,
    atespace: str | None = None,
) -> list[Path]:
    """Write the generated manifests under ``plane`` from the templates in ``plane/tasks`` (re-pinned first when
    ``runner_image`` is given), with the improvement loop when ``loop`` is given; returns the paths. Workspaces go
    to ``atespace`` (default: the profile's)."""
    if atespace is None:
        from .profile import load_profile

        atespace = load_profile().atespace
    if loop is not None and repos is None:
        raise ValueError("--loop needs --repos: the alerts task marks fixed-pin alerts by the fix's new-side ranges")
    if runner_image is not None:
        repin_templates(plane, runner_image)
    loaded = load_manifests([plane / "tasks" / f"{name}.yaml" for name in TEMPLATES])
    cases = read_cases(validation_set, candidates_dir, triage_dir, population, repos, fixed_side=loop is not None)
    files = render(
        cases, loaded.tasks, run_name, command, population=population.stem, split=validation_set.stem, loop=loop, atespace=atespace
    )
    written: list[Path] = []
    for relative, text in files.items():
        path = plane / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written
