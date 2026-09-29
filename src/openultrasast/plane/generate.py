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

The recorded triage cost is derived per file: a batched-check record's ``usd`` paid for the triage call and the
hunts, and its ``usage`` counts only the hunts (``verify_sinks._Recording`` slices the client's usage from the
first hunt on), so the triage share is ``usd`` minus that usage priced at the reference model's list price.

``--runner-image FILE`` (``~/.cache/ousast/ax-src/runner-image``, written by ``ops/ax/up.sh``) re-pins the
templates' ``image:`` to the digest in that file before generating, so a rebuilt image is one command.
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
from .reconciler import _ax_name, _doc
from .tasks.verify import MAX_STEPS, units_of

__all__ = ["CaseInputs", "fix_ranges", "increment", "read_cases", "render", "repin_templates"]

REFERENCE_USD_PER_CANDIDATE = 0.022  # two passes: verifier-batched-check-2026-09-29.json cost.usd_per_candidate_two_passes
REFERENCE_MODEL = "deepseek-flash"  # verify_batched.py's default (DEFAULT_DETECTOR_MODEL) in the batched check
TRIAGE_BASIS = (
    "derived per file from the batched-check scans: recorded usd (triage + hunts) minus the recorded hunt usage "
    f"priced at {REFERENCE_MODEL} list prices; the triage call's own usage was not recorded"
)
RANGES_BASIS = "git diff -U0 <vulnerable> <fixed>, old side: benchmarks/independent/evaluate.hunks(case, 'old')"
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
    triage_usd: float = 0.0
    ranges: Mapping[str, Sequence[tuple[int, int]]] | None = None


def fix_ranges(repo: Path, vulnerable: str, fixed: str) -> dict[str, list[tuple[int, int]]]:
    """Changed line ranges per file on the vulnerable side of the fix: `evaluate.hunks(case, "old")`, line for
    line (including its attribution of a hunk under ``--- /dev/null`` to the file before it)."""
    if not (repo / ".git").exists() and not (repo / "HEAD").is_file():
        raise ValueError(f"no repository at {repo}: the fix ranges cannot be computed")
    diff = subprocess.run(["git", "-C", str(repo), "diff", "-U0", vulnerable, fixed], capture_output=True, text=True, check=True).stdout
    ranges: dict[str, list[tuple[int, int]]] = {}
    current = ""
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            current = line[6:]
        elif line.startswith("@@") and current:
            match = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?", line)
            if match:
                first, length = int(match.group(1)), int(match.group(2)) if match.group(2) is not None else 1
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
    validation_set: Path, candidates_dir: Path, triage_dir: Path, population: Path, repos: Path | None = None
) -> list[CaseInputs]:
    """The set's cases in id order, each with its candidates, the triage-kept subset, the recorded cost and its
    triage share, and -- with ``repos`` (one clone per case id) -- the fix's old-side ranges."""
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
    record["sites_in_set"] = [s for s in sites if s in in_set]
    record["cost"] = {
        "candidates_before_triage": len(item.candidates), "recorded_usd": item.recorded_usd,
        "recorded_triage_usd": item.triage_usd, "recorded_triage_basis": TRIAGE_BASIS,
    }  # fmt: skip
    return record


def _workspaces(item: CaseInputs) -> tuple[dict[str, Any], dict[str, Any]]:
    case = item.case
    git = [{"name": "repo", "repo": case["repo"], "dir": "repo", "depth": 1}]
    pinned = _doc("Workspace", _ax_name(case["id"], "vulnerable"), {"git": git}, ATESPACE)
    pinned["metadata"]["annotations"] = {GIT_COMMITS_ANNOTATION: f"repo={case['vulnerable']}"}
    files = {
        "candidates.json": _json({"id": case["id"], "family": case["family"], "candidates": [list(c) for c in item.kept]}),
        "functions.json": _json([{"path": p, "function": fn, "line": ln} for p, fn, ln in item.kept]),
        "case.json": _json(_case_record(item)),
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


_IMAGE_LINE = re.compile(r'^(\s*image:\s*)"?[^"\s]+"?\s*$', re.MULTILINE)


def repin_templates(plane: Path, image_file: Path) -> str:
    """Set every template's ``image:`` to the digest-pinned reference in ``image_file`` (as ``ops/ax/up.sh``
    writes it); comments and layout are kept. Returns the reference."""
    image = image_file.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", image):
        raise ValueError(f"{image_file}: expected a digest-pinned image reference, got {image!r}")
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
) -> list[Path]:
    """Write the generated manifests under ``plane`` from the templates in ``plane/tasks`` (re-pinned first when
    ``runner_image`` is given); returns the paths."""
    if runner_image is not None:
        repin_templates(plane, runner_image)
    loaded = load_manifests([plane / "tasks" / f"{name}.yaml" for name in TEMPLATES])
    files = render(read_cases(validation_set, candidates_dir, triage_dir, population, repos), loaded.tasks, run_name, command)
    written: list[Path] = []
    for relative, text in files.items():
        path = plane / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written
