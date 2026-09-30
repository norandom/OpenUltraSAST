"""`remember` (harnessx-removal Requirement 6.1, design section 4): a case's delivered artifacts as memory rows.

No model, budget ``{usd: 0, calls: 0}``, one per case. It reads the case's `facts.json`, the `units.jsonl` of the
verify passes a, b and c, the final `agreed.json` (its per-candidate rows and `disputed` list) and, when present,
`alerts.jsonl`, and writes `memory.jsonl` -- rows of the kinds `facts`, `verdict`, `unit_cost` and `alert` (the
fifth kind, `proposal_outcome`, comes from the loop) -- and passes `facts.json` through. Task code interprets the
artifacts, so the reconciler and the runner stay content-blind (ai-service-plane Req 3.4).

Every row carries `id` (deterministic: :func:`..memory.row_id`), `kind`, `repo`, `pin`, `run`, `task`,
`population`, `split` and `image` (the runner image digest the case's tasks ran on).

Env contract in a Run: `OUSAST_OUTPUT_DIR`, `OUSAST_RUN`, `OUSAST_TASK`, `OUSAST_INPUT_FACTS`,
`OUSAST_INPUT_PASS_A`/`_B`, optional `OUSAST_INPUT_PASS_C`, `OUSAST_INPUT_SUMMARY_A`/`_B`/`_C` (the passes'
`summary.json`, for the model), `OUSAST_INPUT_AGREED`, `OUSAST_INPUT_ALERTS`; the repository and pin from the bound
Workspace (`AX_WORKSPACES_YAML`, `OUSAST_GIT_PINS`), the image from `AX_TASK_YAML`, the population and split from
`OUSAST_POPULATION`/`OUSAST_SPLIT` (the generator copies the Run's `openultrasast.io/population` and
`openultrasast.io/split` annotations). Exit 0 done, 2 failed.

On the host, :func:`remember_run` does the same over a recorded run directory (``ousast plane remember <run>``):
per case without a delivered `memory.jsonl` it reads the artifacts and the rendered `task.yaml` beside them and
ingests the rows directly, writing nothing into the run directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..memory import REMEMBER_OUTPUT, IngestResult, MemoryStore, image_digest, ingest, repo_key, row_id, validate_row
from .repo_facts import _digest

PASSES = ("a", "b", "c")
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Context:
    run: str
    task: str
    repo: str
    pin: str
    image: str
    population: str = UNKNOWN
    split: str = UNKNOWN

    def row(self, kind: str, subject: str, **fields: Any) -> dict[str, Any]:
        base = {
            "id": row_id(kind, self.run, self.task, subject), "kind": kind, "repo": repo_key(self.repo), "pin": self.pin,
            "run": self.run, "task": self.task, "population": self.population, "split": self.split, "image": self.image,
        }  # fmt: skip
        return {**base, **fields}


def candidates_digest(facts: Mapping[str, Any]) -> str:
    """`repo_facts._digest` of the candidate names `facts.json` was computed for (its `callers` keys)."""
    names = sorted({str(key).partition("::")[2] for key in (facts.get("callers") or {})})
    return _digest(names)


def _final(row: Mapping[str, Any], disputed: set[str]) -> str:
    if row.get("agreed"):
        return "agreed"
    return "disputed" if str(row["candidate"]) in disputed else "rejected"


def rows_for(
    ctx: Context,
    *,
    facts: bytes | None,
    passes: Mapping[str, Sequence[Mapping[str, Any]]],
    models: Mapping[str, str | None],
    agreed: Mapping[str, Any] | None,
    alerts: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """The memory rows of one case: facts, verdicts, unit costs, alerts."""
    rows: list[dict[str, Any]] = []
    if facts is not None:
        loaded = json.loads(facts)
        sha = hashlib.sha256(facts).hexdigest()
        counts = loaded.get("counts") or {}
        files = int(counts.get("files", len(loaded.get("files") or {})))
        rows.append(ctx.row("facts", sha, sha256=sha, candidates_digest=candidates_digest(loaded), files=files))
    if agreed is not None:
        disputed = {str(d["candidate"]) for d in agreed.get("disputed") or []}
        for cand in agreed.get("candidates") or []:
            finding = cand.get("finding") or {}
            fields = {
                "candidate": cand["candidate"], "family": finding.get("family") or agreed.get("family"), "site": cand.get("site"),
                "passes": {p: cand.get(p) for p in PASSES}, "final": _final(cand, disputed), "tiebreak": cand.get("c") is not None,
                "site_match": cand.get("site_match"), "usd": cand.get("usd"), "turns": cand.get("turns"),
            }  # fmt: skip
            rows.append(ctx.row("verdict", str(cand["candidate"]), **fields))
    for label in PASSES:
        for unit in passes.get(label) or []:
            usage = dict(unit.get("usage") or {})
            fields = {
                "pass": label, "path": unit.get("path"), "usd": unit.get("usd"), "calls": usage.get("calls"), "usage": usage,
                "turns": unit.get("turns"), "model": models.get(label),
            }  # fmt: skip
            rows.append(ctx.row("unit_cost", f"{label}:{unit.get('path')}", **fields))
    for alert in alerts:
        fields = {k: alert.get(k) for k in ("rule_id", "rule_status", "path", "line", "function", "pin_role")}
        rows.append(ctx.row("alert", f"{fields['rule_id']}:{fields['path']}:{fields['line']}", **fields))
    return [validate_row(r, f"{ctx.task} {r['kind']}") for r in rows]


def _jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _json(path: Path | None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path is not None and path.is_file() else None


def _model(summary: object) -> str | None:
    return str(summary["model"]) if isinstance(summary, dict) and summary.get("model") else None


def context_from(
    task_doc: Mapping[str, Any], workspaces: Sequence[Mapping[str, Any]], *, run: str, task: str, population: str, split: str
) -> Context:
    """Repository, pin and image from a rendered Task and its Workspaces: the pin named in `OUSAST_GIT_PINS`, the
    repository of that Workspace's git entry, the Task's image."""
    spec = task_doc.get("spec") or {}
    env = {str(e.get("name")): str(e.get("value")) for e in spec.get("env") or []}
    pins: dict[str, str] = json.loads(env.get("OUSAST_GIT_PINS") or "{}")
    if len(pins) != 1:
        raise ValueError(f"{task}: expected one pinned repository in OUSAST_GIT_PINS, got {sorted(pins)}")
    ((ref, pin),) = pins.items()
    ws_name, _, git_name = ref.partition("/")
    repos = [
        str(g["repo"])
        for w in workspaces if (w.get("metadata") or {}).get("name") == ws_name
        for g in (w.get("spec") or {}).get("git") or [] if g.get("name") == git_name
    ]  # fmt: skip
    if not repos:
        raise ValueError(f"{task}: no bound Workspace git entry {ref}")
    image = str(spec.get("image") or "")
    if not image:
        raise ValueError(f"{task}: the Task names no image")
    return Context(run, task, repos[0], pin, image_digest(image), population or UNKNOWN, split or UNKNOWN)


def _rendered(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
    tasks = [d for d in docs if d.get("kind") == "Task"]
    if not tasks:
        raise ValueError(f"{path}: no rendered Task")
    return tasks[-1], [d for d in docs if d.get("kind") == "Workspace"]


def case_rows(base: Path, case: str, *, population: str, split: str) -> tuple[list[dict[str, Any]], bytes | None]:
    """The rows of one case of a recorded run directory, from its artifacts and the rendered `task.yaml`."""
    facts_dir = base / f"{case}-facts"
    candidates = [base / f"{case}-{step}" / "task.yaml" for step in ("facts", "va", "vb", "agree")]
    rendered = next((path for path in candidates if path.is_file()), None)
    if rendered is None:
        raise ValueError(f"{base}: case {case} has no rendered task.yaml")
    task_doc, workspaces = _rendered(rendered)
    ctx = context_from(task_doc, workspaces, run=base.name, task=f"{case}-remember", population=population, split=split)
    reused = (_json(facts_dir / "summary.json") or {}).get("reused")
    if isinstance(reused, dict) and reused.get("image"):
        ctx = Context(ctx.run, ctx.task, ctx.repo, ctx.pin, image_digest(str(reused["image"])), ctx.population, ctx.split)
    facts = (facts_dir / "facts.json").read_bytes() if (facts_dir / "facts.json").is_file() else None
    final = base / f"{case}-final" / "agreed.json"
    agreed = _json(final if final.is_file() else base / f"{case}-agree" / "agreed.json")
    passes = {p: _jsonl(base / f"{case}-v{p}" / "units.jsonl") for p in PASSES}
    models = {p: _model(_json(base / f"{case}-v{p}" / "summary.json")) for p in PASSES}
    alerts = _jsonl(base / f"{case}-alerts" / "alerts.jsonl")
    return rows_for(ctx, facts=facts, passes=passes, models=models, agreed=agreed, alerts=alerts), facts


def remember_run(run_dir: Path, store: MemoryStore, *, population: str = UNKNOWN, split: str = UNKNOWN) -> list[IngestResult]:
    """Ingest a run: delivered `memory.jsonl` files as they are, and every other case (a `<case>-facts` task)
    computed here from its artifacts."""
    base = Path(run_dir)
    if not base.is_dir():
        raise ValueError(f"no run directory at {base}")
    results = ingest(base, store)
    delivered = {r.task for r in results}
    for facts_dir in sorted(base.glob("*-facts")):
        case = facts_dir.name.removesuffix("-facts")
        if f"{case}-remember" in delivered or (base / f"{case}-remember" / REMEMBER_OUTPUT).is_file():
            continue
        rows, facts = case_rows(base, case, population=population, split=split)
        results.append(store.ingest_rows(base.name, f"{case}-remember", rows, facts))
    return results


def _path(env: Mapping[str, str], name: str) -> Path | None:
    return Path(env[name]) if env.get(name) else None


def _units(path: Path | None) -> list[dict[str, Any]]:
    return _jsonl(path / "units.jsonl" if path is not None and path.is_dir() else path)


def main(environ: Mapping[str, str] | None = None) -> int:
    env = environ if environ is not None else os.environ
    output_dir = _path(env, "OUSAST_OUTPUT_DIR")
    summary: dict[str, Any] = {"status": "failed", "units_done": 0, "units_total": 1, "usd": 0, "calls": 0, "usage": {}, "model": None}
    try:
        if output_dir is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        output_dir.mkdir(parents=True, exist_ok=True)
        task_doc = yaml.safe_load(env.get("AX_TASK_YAML") or "{}") or {}
        task_doc.setdefault("spec", {})["env"] = [{"name": "OUSAST_GIT_PINS", "value": env.get("OUSAST_GIT_PINS") or "{}"}]
        workspaces = [d for d in yaml.safe_load_all(env.get("AX_WORKSPACES_YAML") or "") if isinstance(d, dict)]
        ctx = context_from(
            task_doc, workspaces, run=env.get("OUSAST_RUN") or UNKNOWN, task=env.get("OUSAST_TASK") or "remember",
            population=env.get("OUSAST_POPULATION") or UNKNOWN, split=env.get("OUSAST_SPLIT") or UNKNOWN,
        )  # fmt: skip
        facts_path = _path(env, "OUSAST_INPUT_FACTS")
        facts = facts_path.read_bytes() if facts_path is not None and facts_path.is_file() else None
        passes = {p: _units(_path(env, f"OUSAST_INPUT_PASS_{p.upper()}")) for p in PASSES}
        models = {p: _model(_json(_path(env, f"OUSAST_INPUT_SUMMARY_{p.upper()}"))) for p in PASSES}
        agreed = _json(_path(env, "OUSAST_INPUT_AGREED"))
        rows = rows_for(ctx, facts=facts, passes=passes, models=models, agreed=agreed, alerts=_jsonl(_path(env, "OUSAST_INPUT_ALERTS")))
        (output_dir / REMEMBER_OUTPUT).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
        if facts is not None:
            (output_dir / "facts.json").write_bytes(facts)
        summary.update(status="done", units_done=1, rows=len(rows))
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback
        summary["reason"] = traceback.format_exc()[-2000:]
    if output_dir is not None:
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: summary.get(k) for k in ("status", "rows")}), file=sys.stderr)
    return 0 if summary["status"] == "done" else 2


__all__ = ["Context", "candidates_digest", "case_rows", "context_from", "main", "remember_run", "rows_for"]


if __name__ == "__main__":
    raise SystemExit(main())
