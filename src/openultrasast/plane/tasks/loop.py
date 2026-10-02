"""The improvement loop as plane tasks (harnessx-removal Requirement 6.3, design section 6).

``command: ["loop", <step>]``; every step is model-free with budget ``{usd: 0, calls: 0}`` (``budget.py`` refuses any
call, so a stray one fails loudly), and each writes ``summary.json`` under the task contract. Records travel as
``{"key", "version", "row"}`` lines: the store object a row came from and its version (the bucket's object version id, a file's
content hash), which a proposal's provenance cites (Req 6.4).

- ``snapshot``: never runs in the sandbox, which cannot read the host's store. ``ousast plane run`` seeds it before
  the Run (``memory.seed`` -> :func:`write_snapshot`): the store's rows after the train-on-test guard to
  ``rows.jsonl``, and ``index.json`` (store, index digest, row counts, what the guard excluded). Run in a sandbox it
  fails, naming the seed that did not happen.
- ``measure``: every case's ``remember`` rows (inputs ``remember_<case>``) plus the snapshot -> ``measure.json``,
  the increment's metrics for this run, the store and both (declared sites agreed, usd per candidate, dispute rates
  per family, alerts per rule and pin) -- and ``rows.jsonl``, the union by row id that ``propose`` reads.
- ``propose``: ``improve/memory.py``'s rules M1/M2 over those rows after the guard (``OUSAST_QUALIFY_POPULATIONS``, the
  gated manifest's cases, the pair catalog's holdout pairs), against the benchmark target's ledger and journal in
  this repository at the commit under test (``OUSAST_PROJECT_DIR``) -> ``proposals.jsonl`` (edit + provenance),
  ``memory_proposals.jsonl`` (the sidecar) and ``signals.json`` (M3, advisory).
- ``improve``: one ``evolve.run_round`` with those proposals -- the unchanged validator and gate, the pair catalog's
  holdout clause included -- on copies of the target's ledger and journal -> ``gate.json`` (the ``RoundOutcome``
  and which edits came from memory), ``journal.json``, the sidecar, and ``rule_policy.json`` only when the round
  was accepted; ``memory.jsonl`` holds the ``proposal_outcome`` rows the host ingests after the Run. Adopting an
  accepted ledger stays a maintainer commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import traceback
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..memory import REMEMBER_OUTPUT, MemoryStore, Record, validate_row

INPUT_PREFIX = "OUSAST_INPUT_REMEMBER_"
CALIBRATION = Path(".openultrasast") / "calibration"  # cli.CALIBRATION_DIR: where `improve` keeps a target's ledger
ADOPTION = "adoption is a maintainer commit: copy rule_policy.json to {ledger} (README, Rule-level loop)"


# --- records -------------------------------------------------------------------------------------------------------


def _record_line(record: Record) -> str:
    return json.dumps({"key": record.key, "version": record.version, "row": record.row}, sort_keys=True, separators=(",", ":")) + "\n"


def read_records(path: Path) -> list[Record]:
    records: list[Record] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw.strip():
            item = json.loads(raw)
            records.append(Record(validate_row(item["row"], f"{path}:{number}"), str(item["key"]), item.get("version")))
    return records


def write_records(path: Path, records: Iterable[Record]) -> None:
    path.write_text("".join(_record_line(r) for r in sorted(records, key=lambda r: str(r.row["id"]))), encoding="utf-8")


def _guard(params: Mapping[str, Any], root: Path) -> Any:
    from ...benchmark import load_benchmark_manifest
    from ...improve.memory import Guard, benchmark_cases
    from ...pairs import load_pair_catalog, select_split

    manifest = load_benchmark_manifest(root / str(params["manifest"]))
    holdout = select_split(load_pair_catalog(Path(str(params["catalog"]))), "holdout")
    return Guard.build([str(p) for p in params.get("populations") or []], benchmark_cases(manifest), holdout)


def write_snapshot(directory: Path, store: MemoryStore, params: Mapping[str, Any], root: Path | None = None) -> dict[str, Any]:
    """The store's rows after the guard ``params`` names (``catalog``, ``manifest``, ``populations``; paths relative to
    ``root``, the working directory) into ``directory``: ``rows.jsonl``, ``index.json`` and a ``done`` summary."""
    from ...improve.memory import index_digest

    here = Path.cwd()
    try:
        os.chdir(root or here)  # the pair catalog names its files relative to the repository root
        guard = _guard(params, Path.cwd())
    finally:
        os.chdir(here)
    directory.mkdir(parents=True, exist_ok=False)  # after the guard loaded: a failed load leaves no half-seeded task
    records = store.rows()
    kept, excluded = guard.apply(records)
    write_records(directory / "rows.jsonl", kept)
    info = {
        "store": store.describe(), "index_entries": len(store.index()), "index_digest": index_digest(store), "rows": len(records),
        "kept": len(kept), "excluded": excluded, "guard": dict(params),
    }  # fmt: skip
    (directory / "index.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {"status": "done", "units_done": 1, "units_total": 1, "usd": None, "calls": 0, "usage": {}, "model": None, "reused": info}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return info


# --- measure -------------------------------------------------------------------------------------------------------


def metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The increment's metrics over verdict, unit-cost and alert rows (a disputed final is neither agreed nor not)."""
    verdicts = [r for r in rows if r["kind"] == "verdict"]
    finals = {f: sum(1 for v in verdicts if v.get("final") == f) for f in ("agreed", "rejected", "disputed")}
    costs = [r.get("usd") for r in rows if r["kind"] == "unit_cost"]
    usd = None if any(c is None for c in costs) else round(sum(float(c or 0) for c in costs), 6)
    families: dict[str, list[int]] = {}
    for v in verdicts:
        tally = families.setdefault(str(v.get("family")), [0, 0])
        tally[0] += 1
        tally[1] += v.get("final") == "disputed"
    alerts: dict[str, dict[str, int]] = {}
    for a in (r for r in rows if r["kind"] == "alert"):
        role = "fixed" if a.get("pin_role") == "fixed" else "vulnerable"
        tally_a = alerts.setdefault(str(a.get("rule_id")), {"vulnerable": 0, "fixed": 0, "fixed_in_fix_range": 0})
        tally_a[role] += 1
        tally_a["fixed_in_fix_range"] += role == "fixed" and a.get("in_fix_range") is True
    coverage: dict[str, dict[str, int]] = {}  # language -> pins per coverage kind: a `none` pin's zero alerts mean nothing
    for c in (r for r in rows if r["kind"] == "coverage"):
        tally_c = coverage.setdefault(str(c.get("language")), {"quick": 0, "engine": 0, "none": 0})
        tally_c[str(c.get("coverage"))] = tally_c.get(str(c.get("coverage")), 0) + 1
    return {
        "cases": len({(v["repo"], v["pin"]) for v in verdicts}),
        "candidates": len(verdicts),
        **finals,
        "tiebreaks": sum(1 for v in verdicts if v.get("tiebreak")),
        "declared_sites_matched": sum(1 for v in verdicts if v.get("site_match") is True),
        "declared_sites_agreed": sum(1 for v in verdicts if v.get("site_match") is True and v.get("final") == "agreed"),
        "usd": usd,
        "usd_per_candidate": None if usd is None or not verdicts else round(usd / len(verdicts), 6),
        "dispute_rate": {f: {"candidates": n, "disputed": d, "rate": round(d / n, 4)} for f, (n, d) in sorted(families.items())},
        "alerts": dict(sorted(alerts.items())),
        "coverage": dict(sorted(coverage.items())),
    }


def measure(env: Mapping[str, str], output: Path) -> dict[str, Any]:
    run = env.get("OUSAST_RUN") or "unknown"
    current: list[Record] = []
    read: dict[str, int] = {}
    for name in sorted(k for k in env if k.startswith(INPUT_PREFIX)):
        path = Path(env[name])
        data = path.read_bytes()
        read[name.removeprefix(INPUT_PREFIX).lower()] = len(data)
        version = hashlib.sha256(data).hexdigest()
        for number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
            if raw.strip():
                row = validate_row(json.loads(raw), f"{path}:{number}")
                current.append(Record(row, f"runs/{run}/{row['task']}/{REMEMBER_OUTPUT}", version))
    if not current:
        raise ValueError(f"read no remember rows from {len(read)} inputs ({read}): an unread run is not an empty one")
    snapshot = read_records(Path(env["OUSAST_INPUT_SNAPSHOT"])) if env.get("OUSAST_INPUT_SNAPSHOT") else []
    merged = {str(r.row["id"]): r for r in snapshot}
    merged.update({str(r.row["id"]): r for r in current})  # this run's row wins over its earlier ingest
    write_records(output / "rows.jsonl", merged.values())
    report = {
        "run": run, "inputs_bytes": read, "rows": {"run": len(current), "snapshot": len(snapshot), "union": len(merged)},
        "run_metrics": metrics([r.row for r in current]), "store_metrics": metrics([r.row for r in snapshot]),
        "union_metrics": metrics([r.row for r in merged.values()]),
    }  # fmt: skip
    (output / "measure.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"rows": report["rows"]}


# --- propose and improve -------------------------------------------------------------------------------------------


def _project(env: Mapping[str, str]) -> tuple[Any, Path, Path, Path]:
    """(manifest, target, ledger, journal) in the repository at the commit under test; the working directory
    becomes the repository root, where the pair catalog's relative paths resolve."""
    from ...benchmark import load_benchmark_manifest, resolve_benchmark_source

    project = Path(env.get("OUSAST_PROJECT_DIR") or "")
    if not env.get("OUSAST_PROJECT_DIR") or not (project / str(env.get("OUSAST_LOOP_MANIFEST"))).is_file():
        raise ValueError(f"OUSAST_PROJECT_DIR {project} holds no benchmark manifest {env.get('OUSAST_LOOP_MANIFEST')}")
    os.chdir(project)
    manifest_path = Path(str(env["OUSAST_LOOP_MANIFEST"]))
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    ledger = target / CALIBRATION / "rule_policy.json"
    return manifest, target, ledger, ledger.with_name("improve_journal.json")


def _params(env: Mapping[str, str]) -> dict[str, Any]:
    populations = json.loads(env.get("OUSAST_QUALIFY_POPULATIONS") or "[]")
    return {"catalog": env.get("OUSAST_LOOP_CATALOG"), "manifest": env.get("OUSAST_LOOP_MANIFEST"), "populations": populations}


def propose(env: Mapping[str, str], output: Path) -> dict[str, Any]:
    from ...improve.journal import load_journal, next_round_index
    from ...improve.memory import disputed_families, propose_from_memory, write_sidecar, write_signals
    from ...ruleset import DEFAULT_RULESET_DIR, load_ruleset, read_rule_ledger

    records = read_records(Path(env["OUSAST_INPUT_ROWS"]))
    index = json.loads(Path(env["OUSAST_INPUT_INDEX"]).read_text(encoding="utf-8"))
    _, _, ledger, journal = _project(env)
    guard = _guard(_params(env), Path.cwd())
    rules = load_ruleset(DEFAULT_RULESET_DIR, ledger if ledger.is_file() else None)
    rounds = load_journal(journal)
    found = propose_from_memory(
        records, {r.rule_id: r for r in rules}, read_rule_ledger(ledger), rounds, excluded=guard, index_digest=str(index["index_digest"])
    )
    lines = [json.dumps({"edit": asdict(p.edit), "provenance": p.provenance}, sort_keys=True) + "\n" for p in found]
    (output / "proposals.jsonl").write_text("".join(lines), encoding="utf-8")
    sidecar = output / "journal.json"
    write_sidecar(sidecar, next_round_index(rounds), found)
    sidecar.with_name("memory_proposals.jsonl").touch()  # present when nothing was proposed, as a declared output
    write_signals(output, disputed_families(records, guard))
    kept, excluded = guard.apply(records)
    return {"proposals": len(found), "rows": len(records), "kept": len(kept), "excluded": excluded["rows"]}


def improve(env: Mapping[str, str], output: Path) -> dict[str, Any]:
    from ...gate import FALSE_POSITIVE_CEILING, RECALL_FLOOR
    from ...improve.evolve import run_round
    from ...improve.memory import MemoryProposal, outcome_of, outcome_rows, proposal_id_of
    from ...improve.validator import RuleStatusEdit
    from ...pairs import load_pair_catalog, select_split
    from ...policy import load_policy
    from ...ruleset import DEFAULT_RULESET_DIR

    path = Path(env["OUSAST_INPUT_PROPOSALS"])
    items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    proposals = [MemoryProposal(RuleStatusEdit(**item["edit"]), item["provenance"]) for item in items]
    manifest, target, ledger, journal = _project(env)
    pairs = select_split(load_pair_catalog(Path(str(env["OUSAST_LOOP_CATALOG"]))), "holdout")
    with tempfile.TemporaryDirectory(prefix="ousast-loop-") as scratch:
        work_ledger = Path(scratch) / "rule_policy.json"
        if ledger.is_file():
            shutil.copyfile(ledger, work_ledger)
        if journal.is_file():
            shutil.copyfile(journal, output / "journal.json")
        outcome = run_round(
            target, manifest, ledger_path=work_ledger, journal_path=output / "journal.json", ruleset_dir=DEFAULT_RULESET_DIR,
            policy=load_policy(), recall_floor=RECALL_FLOOR, fp_ceiling=FALSE_POSITIVE_CEILING, pair_cases=pairs, proposals=proposals,
        )  # fmt: skip
        if outcome.accepted and work_ledger.is_file():
            shutil.copyfile(work_ledger, output / "rule_policy.json")
    (output / "journal.json").touch()
    (output / "memory_proposals.jsonl").touch()
    memory_edits = [e.key() for e in outcome.edits if proposal_id_of(e)]
    verdict = {
        "accepted": outcome.accepted, "reason": outcome.reason, "round": outcome.round, "proposals": len(proposals),
        "memory_edits": memory_edits, "benchmark_edits": [e.key() for e in outcome.edits if not proposal_id_of(e)],
        "manifest": env.get("OUSAST_LOOP_MANIFEST"), "outcome": asdict(outcome),
        "adoption": ADOPTION.format(ledger=ledger.as_posix()) if outcome.accepted else None,
    }  # fmt: skip
    (output / "gate.json").write_text(json.dumps(verdict, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    status = outcome_of(outcome.reason, outcome.accepted)
    by_id = {p.proposal_id: p for p in proposals}
    gate_run = f"plane:{env.get('OUSAST_RUN') or 'unknown'}"
    rows = outcome_rows(outcome.edits, status, outcome.round, outcome.reason, by_id, gate_run) if status else []
    (output / REMEMBER_OUTPUT).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    return {"accepted": outcome.accepted, "reason": outcome.reason, "edits": len(outcome.edits), "memory_edits": len(memory_edits)}


def snapshot(env: Mapping[str, str], output: Path) -> dict[str, Any]:
    raise RuntimeError(
        "memory-snapshot ran in the sandbox: `ousast plane run` writes it on the host from the memory store before the Run "
        "starts (memory.seed), so the seed did not happen; rerun through `ousast plane run`"
    )


STEPS: dict[str, Callable[[Mapping[str, str], Path], dict[str, Any]]] = {
    "snapshot": snapshot, "measure": measure, "propose": propose, "improve": improve,
}  # fmt: skip


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = environ if environ is not None else os.environ
    output = Path(env["OUSAST_OUTPUT_DIR"]) if env.get("OUSAST_OUTPUT_DIR") else None
    summary: dict[str, Any] = {"status": "failed", "units_done": 0, "units_total": 1, "usd": 0, "calls": 0, "usage": {}, "model": None}
    here = Path.cwd()
    try:
        if output is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        if len(args) != 1 or args[0] not in STEPS:
            raise ValueError(f"expected one step of {sorted(STEPS)}, got {args}")
        output.mkdir(parents=True, exist_ok=True)
        summary.update(step=args[0], **STEPS[args[0]](env, output))
        summary.update(status="done", units_done=1)
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback
        summary["reason"] = traceback.format_exc()[-2000:]
    finally:
        os.chdir(here)
    if output is not None:
        (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    shown = {k: summary.get(k) for k in ("status", "step", "proposals", "accepted", "reason", "rows")}
    print(json.dumps(shown, default=str), file=sys.stderr)
    return 0 if summary["status"] == "done" else 2


__all__ = ["main", "measure", "metrics", "propose", "improve", "read_records", "write_records", "write_snapshot"]


if __name__ == "__main__":
    raise SystemExit(main())
