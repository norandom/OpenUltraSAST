"""Manifests of a recorded measurement as a Run (ai-service-plane task 7).

``ousast plane workspaces <population.toml> --validation-set <set.json> --candidates <dir> --triage <dir>`` writes,
under ``--plane`` (default ``plane/``), everything a Run over the set needs beside the hand-written templates
(``tasks/repo-facts.yaml``, ``tasks/verify.yaml``, ``tasks/agree.yaml``, ``models/*.yaml``):

- ``workspaces/<case>-vulnerable.yaml``: the case's repository at its vulnerable pin (commit in the
  ``openultrasast.io/git-commits`` annotation, as :mod:`.workspaces` writes it);
- ``workspaces/<case>-inputs.yaml``: a files-only Workspace with the inputs no task produces -- the recorded
  candidates (``candidates.json`` in the ``independent-v2-modelsinks`` shape for ``verify`` and ``agree``,
  ``functions.json`` as ``{path, function, line}`` rows for ``repo-facts``), the case's declared sites
  (``case.json`` for ``agree``) and the recorded triage (``triage.json``, for the measurement);
- ``tasks/<run>.yaml``: per case, one Task per template (two for ``verify``: ``OUSAST_PASS=a|b``) binding the two
  Workspaces and naming the files as env;
- ``runs/<run>.yaml``: the Run, per case ``facts -> verify a, verify b -> agree``, with budgets.

Why per-case Tasks rather than one Task per step: an ax Task binds its Workspaces by name and a Run entry adds
neither a binding nor env (it names a Task, artifacts and a budget), and ``Run.inputs`` accepts only
``<task>/<artifact>``. So an input that no task produces is a Workspace ``files`` entry, and the case a step works
on is fixed by the Task it runs. One Run covers every case so the measurement has one state and one attribution
table.

Candidates are the set's ``(path, function)`` pairs with the line of the case record, deduplicated the way
``benchmarks/independent/verify_batched.py`` does (sorted, the last line of a repeated pair wins), and filtered
by the recorded triage (the ``kept`` lists of the batched-check scans): ``verify`` has no triage stage, so the
hunts see exactly the candidates the reference hunts saw. Output is a pure function of the inputs.
"""

from __future__ import annotations

import json
import math
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .manifests import GIT_COMMITS_ANNOTATION, RUN_API_VERSION, Task, load_manifests
from .reconciler import _ax_name, _doc
from .tasks.verify import MAX_STEPS, units_of

__all__ = ["CaseInputs", "increment", "read_cases", "render"]

REFERENCE_USD_PER_CANDIDATE = 0.022  # two passes: verifier-batched-check-2026-09-29.json cost.usd_per_candidate_two_passes
HEADROOM = 1.5
CALLS_PER_HUNT = MAX_STEPS + 2  # every tool step, the answer, one empty-content retry
ATESPACE = "default"
CASE_PATH = "/workspace/case"
INPUTS_PATH = "/workspace/inputs"
TEMPLATES = ("repo-facts", "verify", "agree")

Candidate = tuple[str, str, int]


@dataclass(frozen=True)
class CaseInputs:
    case: Mapping[str, Any]
    candidates: tuple[Candidate, ...]
    kept: tuple[Candidate, ...]
    triage: Mapping[str, str]
    recorded_usd: float


def _scan_rows(triage_dir: Path, case_id: str) -> list[dict[str, Any]]:
    path = triage_dir / f"{case_id}--vulnerable_a.jsonl"
    if not path.is_file():
        raise ValueError(f"{case_id}: no recorded triage at {path}")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = [r for r in rows if "unverified" not in r]
    if not rows:
        raise ValueError(f"{path}: no completed file record")
    return rows


def read_cases(validation_set: Path, candidates_dir: Path, triage_dir: Path, population: Path) -> list[CaseInputs]:
    """The set's cases in id order, each with its candidates, the triage-kept subset and the recorded cost."""
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
            )
        )
    return cases


def _dump(header: str, docs: Sequence[Mapping[str, Any]]) -> str:
    return header + str(yaml.safe_dump_all(list(docs), sort_keys=False, width=1000))


def _json(payload: object) -> str:
    return json.dumps(payload, indent=1, sort_keys=True) + "\n"


def _workspaces(item: CaseInputs) -> tuple[dict[str, Any], dict[str, Any]]:
    case = item.case
    git = [{"name": "repo", "repo": case["repo"], "dir": "repo", "depth": 1}]
    pinned = _doc("Workspace", _ax_name(case["id"], "vulnerable"), {"git": git}, ATESPACE)
    pinned["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"repo={case['vulnerable']}"}
    files = {
        "candidates.json": _json({"id": case["id"], "family": case["family"], "candidates": [list(c) for c in item.kept]}),
        "functions.json": _json([{"path": p, "function": fn, "line": ln} for p, fn, ln in item.kept]),
        "case.json": _json({"id": case["id"], "family": case["family"], "sites": list(case.get("sites", []))}),
        "triage.json": _json(
            {"candidates": [list(c) for c in item.candidates], "kept": [list(c) for c in item.kept], "triage": dict(item.triage)}
        ),
    }
    inputs = _doc("Workspace", _ax_name(case["id"], "inputs"), {"files": [{"path": k, "content": v} for k, v in files.items()]}, ATESPACE)
    return pinned, inputs


def _task(template: Task, name: str, env: Mapping[str, str], bindings: Sequence[tuple[str, str]]) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if template.image:
        spec["image"] = template.image
    spec["command"] = list(template.command)
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


def render(cases: Sequence[CaseInputs], templates: Mapping[str, Task], run_name: str, command: str) -> dict[str, str]:
    """Relative path under the plane root -> file text, for every generated manifest."""
    header = f"# generated by `{command}`; do not edit, regenerate.\n"
    out: dict[str, str] = {}
    tasks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    for item in cases:
        case_id = item.case["id"]
        pinned, inputs = _workspaces(item)
        for doc in (pinned, inputs):
            out[f"workspaces/{doc['metadata']['name']}.yaml"] = _dump(header, [doc])
        repo = [(pinned["metadata"]["name"], CASE_PATH), (inputs["metadata"]["name"], INPUTS_PATH)]
        on_repo = {"OUSAST_WORKSPACE_DIR": f"{CASE_PATH}/repo"}
        facts_env = {**on_repo, "OUSAST_INPUT_CANDIDATES": f"{INPUTS_PATH}/functions.json"}
        tasks.append(_task(templates["repo-facts"], f"repo-facts-{case_id}", facts_env, repo))
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
    out[f"tasks/{run_name}.yaml"] = _dump(header, tasks)
    run = {"apiVersion": RUN_API_VERSION, "kind": "Run", "metadata": {"name": run_name}, "spec": {"tasks": entries}}
    total = sum(float(e["budget"]["usd"]) for e in entries)
    candidates = sum(len(c.candidates) for c in cases)
    kept = sum(len(c.kept) for c in cases)
    note = f"# {len(cases)} cases, {candidates} candidates ({kept} kept by the recorded triage); usd ceiling {total:.2f}.\n"
    out[f"runs/{run_name}.yaml"] = _dump(header + note, [run])
    return out


def increment(
    population: Path, validation_set: Path, candidates_dir: Path, triage_dir: Path, *, plane: Path, run_name: str, command: str
) -> list[Path]:
    """Write the generated manifests under ``plane`` from the templates in ``plane/tasks``; returns the paths."""
    loaded = load_manifests([plane / "tasks" / f"{name}.yaml" for name in TEMPLATES])
    files = render(read_cases(validation_set, candidates_dir, triage_dir, population), loaded.tasks, run_name, command)
    written: list[Path] = []
    for relative, text in files.items():
        path = plane / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written
