"""Stage 2, second design: triage per file, verify per file, report only what two passes agree on.

The first verifier (`verify_sinks.py`) asked one 6-step tool hunt per candidate function. Measured on pgAdmin
(verifier-check-2026-09-29.json): $0.014-0.020 per candidate, and on 180 candidates verified twice the two runs
flagged 15 and 13 with only 2 in common -- single-pass verdicts on borderline candidates flip. This design
changes three things, each checked against the 15 declared sites and those 26 flickering candidates:

1. TRIAGE, one no-tools call per file: the file's relevant chunks and its candidate functions, asking where the
   operation's data ORIGINATES. `request`, `parameter` and `stored` go on to verification; `internal` and
   `constant` do not; anything unclassified goes on (a failed call is never a "safe" verdict).
2. BATCHED verification, one 6-step tool hunt per file for up to `--per-hunt` surviving candidates, with one
   verdict per listed operation. The file read and the caller searches are shared instead of repeated ~5 times.
3. AGREEMENT: `--passes` independent hunts per file (fresh conversations); a candidate is reported only when
   every pass flags it. Findings from single passes are kept in the record as `disputed`.

Source only; the stage-1 candidates come from `model_sinks.py`. Results in `~/ousast-results/independent-<vN>-
<suffix>/scans/` in the shape `evaluate.py` scores; a per-case `.jsonl` makes a stopped run resumable per file.
EXPLORATORY: v2 is spent for tuning; this qualifies nothing.

Usage:
    python benchmarks/independent/verify_batched.py [--only ID,...] [--subset sets.json] [--passes 2] [--budget-usd 40]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402
from model_sinks import OPERATIONS, chunks  # noqa: E402
from verify_sinks import ACCOUNT_ERRORS, _Recording  # noqa: E402

from openultrasast.config import load_config  # noqa: E402
from openultrasast.model.endpoint import DEFAULT_DETECTOR_MODEL  # noqa: E402

VERIFY = {"request", "parameter", "stored"}
TRIAGE = (
    "Below is a source file with numbered lines, and a list of functions in it that each {operation}. For EACH "
    "listed function, say where the data used by that operation ORIGINATES, tracing within this file only:\n"
    "- request: an HTTP request (parameters, body, headers, cookies, uploads), a webhook or API payload;\n"
    "- parameter: a parameter of the function whose callers are not in this file;\n"
    "- stored: a database row, file or setting written earlier, possibly from external input;\n"
    "- internal: values the program computes from constants, the operator's environment, CLI arguments or "
    "trusted framework state;\n"
    "- constant: a literal.\n"
    'Answer with JSON only: {{"functions": [{{"function": "<name exactly as listed>", "data_origin": "<one of the five>"}}]}}.'
    "\n\nFunctions: {functions}\n\nFile: {path}\n\n{code}"
)
SYSTEM = (
    "You are a security reviewer with repository tools (read_file, grep_repo, find_refs). You are given several "
    "operations in ONE file, each named by its function. For EACH operation decide whether data an attacker "
    "controls -- HTTP request parameters, body, headers, cookies, uploaded or imported content, webhook or API "
    "payloads, values stored earlier from such input -- can reach it without a sufficient guard (validation or "
    "allowlisting, escaping that fits the exact context, parameterization, or a fixed destination). Use the tools "
    "to follow callers and data. Report an operation only if you can state the concrete path from the source to "
    "it. Answer with a JSON array: one object per vulnerable operation with path, line, function_name (exactly as "
    "listed), title and rationale (the source, each hop, and why no guard applies); [] if none is vulnerable or "
    "you cannot establish a path."
)

_CLIENT = None


def _client():
    global _CLIENT
    if _CLIENT is None:
        from openultrasast import tool_hunter

        load_config()
        _CLIENT = tool_hunter.resolve_hunter_client()
    return _CLIENT


def _relevant_code(text: str, lines: list[int], chunk_lines: int, max_chunks: int = 6) -> str:
    parts = chunks(text, chunk_lines)
    if not lines or any(line <= 0 for line in lines) or len(parts) <= max_chunks:
        return "\n".join(parts[:max_chunks])
    wanted = sorted({min((line - 1) // chunk_lines, len(parts) - 1) for line in lines})
    return "\n".join(parts[i] for i in wanted[:max_chunks])


def triage(root: Path, path: str, candidates: list[list], family: str, model: str, chunk_lines: int) -> dict[str, str]:
    """Function name -> data_origin for this file's candidates; a name missing from the answer is unclassified."""
    client = _client()
    try:
        text = (root / path).read_text(errors="ignore")
    except OSError:
        return {}
    names = sorted({fn for _, fn, _ in candidates})
    prompt = TRIAGE.format(operation=OPERATIONS[family], functions=json.dumps(names), path=path, code=_relevant_code(text, [ln for _, _, ln in candidates], chunk_lines))
    response = client.complete(model=model, messages=[{"role": "user", "content": prompt}], tools=[], timeout_seconds=90, json_object=True)
    try:
        items = json.loads(response.content or "{}").get("functions", [])
    except (json.JSONDecodeError, AttributeError):
        return {}
    return {str(i.get("function")): str(i.get("data_origin", "")).strip().lower() for i in items if isinstance(i, dict) and i.get("function") in names}


def hunt(root: Path, path: str, group: list[list], family: str, model: str, steps: int) -> tuple[list[dict], dict]:
    from openultrasast import tool_hunter
    from openultrasast.complexity.map import Hotspot

    recording = _Recording(_client())
    listing = "\n".join(f"- function `{fn}` around line {ln}" for _, fn, ln in group)
    prompt = (
        f"Operations to judge, all in `{path}`, each of which {OPERATIONS[family]}:\n{listing}\n"
        "The file is above. For each, trace where the operation's data comes from and whether it is guarded."
    )
    spots = [Hotspot(path=path, function_name=fn, score=1.0, band="candidate", signals={}, rationale="model-classified sink", test_hint=None, inventory_finding_ids=()) for _, fn, _ in group]
    found = tool_hunter.run_tool_hunter(root, spots, client=recording, model=model, max_steps=steps, system_prompt=SYSTEM, user_prompt=prompt, context_files=[path], tags=("sink-verifier",))
    names = {fn for _, fn, _ in group}
    rows = []
    for f in found:
        fn = f.function_name or ""
        if fn not in names:  # attribute by the nearest listed line when the model renamed the function
            fn = min(group, key=lambda c: abs((c[2] or 0) - (f.line or 0)))[1]
        # The verdict is about the candidate operation, so the site is the candidate's file and function; the
        # model's own location is kept beside it (it often names the file where the input enters instead).
        line = f.line if f.path == path else next(c[2] for c in group if c[1] == fn)
        rows.append({"candidate": f"{path}::{fn}", "site": f"{path}:{line or 0}:{fn}", "reported_at": f"{f.path}:{f.line or 0}", "family": family, "title": f.title, "witness": f.rationale[:600]})
    return rows, recording.usage()


def verify_file(root: str, path: str, candidates: list[list], family: str, args_: dict) -> dict:
    """One file, in a worker process: triage, then `passes` batched hunts over the survivors."""
    client = _client()
    before = float(client.cost_usd())
    record: dict = {"path": path, "candidates": candidates, "triage": {}, "passes": [], "usage": {}}
    try:
        if not args_["no_triage"]:
            record["triage"] = triage(Path(root), path, candidates, family, args_["model"], args_["chunk_lines"])
        kept = [c for c in candidates if record["triage"].get(c[1], "unclassified") in VERIFY | {"unclassified"} or record["triage"].get(c[1]) not in {"internal", "constant"}]
        record["kept"] = [c[1] for c in kept]
        usage: dict[str, int] = {}
        for _pass in range(args_["passes"]):
            flagged: list[dict] = []
            for i in range(0, len(kept), args_["per_hunt"]):
                rows, used = hunt(Path(root), path, kept[i : i + args_["per_hunt"]], family, args_["model"], args_["max_steps"])
                flagged += rows
                usage = {k: usage.get(k, 0) + used.get(k, 0) for k in set(usage) | set(used)}
            record["passes"].append(flagged)
        record["usage"] = usage
    except Exception as error:  # noqa: BLE001 -- recorded; an unverified file is not a clean one
        record["unverified"] = f"{type(error).__name__}: {str(error)[:160]}"
    record["usd"] = round(float(client.cost_usd()) - before, 4)
    return record


def agreement(record: dict) -> tuple[list[dict], list[dict]]:
    """(agreed, disputed): flagged in every pass vs in some."""
    if not record.get("passes"):
        return [], []
    by_pass = [{r["candidate"]: r for r in flagged} for flagged in record["passes"]]
    every = set.intersection(*(set(b) for b in by_pass))
    some = set.union(*(set(b) for b in by_pass))
    first = by_pass[0]
    pick = lambda c: next(b[c] for b in by_pass if c in b)  # noqa: E731
    return [dict(first[c], passes=len(by_pass)) for c in sorted(every)], [dict(pick(c), passes=sum(c in b for b in by_pass)) for c in sorted(some - every)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=HERE / "population-v2.toml")
    parser.add_argument("--only", default="")
    parser.add_argument("--subset", type=Path, help='JSON {case_id: [[path, function], ...]}: verify only these candidates')
    parser.add_argument("--model", default=DEFAULT_DETECTOR_MODEL)
    parser.add_argument("--max-steps", type=int, default=6)
    parser.add_argument("--per-hunt", type=int, default=6)
    parser.add_argument("--passes", type=int, default=2)
    parser.add_argument("--chunk-lines", type=int, default=400)
    parser.add_argument("--no-triage", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--budget-usd", type=float, default=40.0)
    parser.add_argument("--results-suffix", default="batched")
    parser.add_argument("--fixed", action="store_true", help="recheck the AGREED candidates of each case at its fixed pin (no triage)")
    args = parser.parse_args()
    load_config()
    evaluate.use(args.population)
    candidates_dir = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-modelsinks")
    evaluate.RESULTS = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-" + args.results_suffix)
    out_dir = evaluate.RESULTS / "scans"
    out_dir.mkdir(parents=True, exist_ok=True)
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    subset = json.loads(args.subset.read_text()) if args.subset else None
    settings = {k: getattr(args, k) for k in ("model", "max_steps", "per_hunt", "passes", "chunk_lines", "no_triage")}
    spent = 0.0
    for case in evaluate.cases():
        if only and case["id"] not in only or (subset is not None and case["id"] not in subset):
            continue
        label = "fixed_a" if args.fixed else "vulnerable_a"
        out = out_dir / f"{case['id']}--{label}.json"
        if out.is_file():
            continue
        log = out_dir / f"{case['id']}--{label}.jsonl"
        done = {r["path"]: r for r in (json.loads(row) for row in log.read_text().splitlines()) if "unverified" not in r} if log.is_file() else {}
        spent += sum(float(r.get("usd", 0.0)) for r in done.values())
        record = json.loads((candidates_dir / f"{case['id']}.json").read_text())
        unique = list({(p, fn): [p, fn, ln] for p, fn, ln in sorted(record["candidates"])}.values())
        if subset is not None:
            wanted = {tuple(x) for x in subset[case["id"]]}
            unique = [c for c in unique if (c[0], c[1]) in wanted]
        if args.fixed:
            # The agreed findings at the vulnerable pin, by (path, function), asked again at the fixed pin. Line
            # numbers are the vulnerable pin's; the file itself is in the prompt. A function the fix removed
            # cannot be asked and counts as removed.
            vulnerable_out = out_dir / f"{case['id']}--vulnerable_a.json"
            if not vulnerable_out.is_file():
                continue
            agreed = {tuple(f["candidate"].split("::", 1)) for f in json.loads(vulnerable_out.read_text())["findings"]}
            unique = [c for c in unique if (c[0], c[1]) in agreed]
            settings = dict(settings, no_triage=True)
        by_file: dict[str, list[list]] = {}
        for c in unique:
            by_file.setdefault(c[0], []).append(c)
        pending = {p: cs for p, cs in by_file.items() if p not in done}
        started = time.monotonic()
        checkout = evaluate.export(case, label, case["fixed" if args.fixed else "vulnerable"])
        if args.fixed:
            present = [c for c in unique if (checkout / c[0]).is_file()]
            removed = [f"{c[0]}::{c[1]}" for c in unique if (checkout / c[0]).is_file() is False]
            unique, by_file = present, {}
            for c in unique:
                by_file.setdefault(c[0], []).append(c)
            pending = {p: cs for p, cs in by_file.items() if p not in done}
        account_error = ""
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool, log.open("a") as sink:
                futures = {pool.submit(verify_file, str(checkout), p, cs, case["family"], settings): p for p, cs in pending.items()}
                for future in concurrent.futures.as_completed(futures):
                    if future.cancelled():
                        continue
                    rec = future.result()
                    if any(code in str(rec.get("unverified", "")) for code in ACCOUNT_ERRORS):
                        account_error = str(rec["unverified"])[:200]
                        for other in futures:
                            other.cancel()
                        continue
                    spent += float(rec.get("usd", 0.0))
                    sink.write(json.dumps(rec) + "\n")
                    sink.flush()
                    if "unverified" not in rec:
                        done[rec["path"]] = rec
                    if spent >= args.budget_usd:
                        for other in futures:
                            other.cancel()
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
        agreed, disputed = [], []
        for rec in done.values():
            a, d = agreement(rec)
            agreed += a
            disputed += d
        triaged_out = sum(len(r["candidates"]) - len(r.get("kept", [])) for r in done.values())
        usage = {k: sum(int(r.get("usage", {}).get(k, 0)) for r in done.values()) for k in ("prompt_tokens", "prompt_cache_hit_tokens", "completion_tokens", "calls")}
        complete = len(done) >= len(by_file) and not account_error
        result = {
            "root": "/case", "families": [case["family"]], "questions": len(unique), "completed": sum(len(r["candidates"]) for r in done.values()),
            "completed_regions": sorted(f"{c[0]}:{c[1]}" for r in done.values() for c in r["candidates"]),
            "triaged_out": triaged_out, "passes": args.passes, "usage": usage, "usd": round(sum(float(r.get("usd", 0.0)) for r in done.values()), 4),
            "seconds": round(time.monotonic() - started, 1), "findings": sorted(agreed, key=lambda f: f["site"]), "disputed": sorted(disputed, key=lambda f: f["site"]),
        }  # fmt: skip
        if args.fixed:
            result["removed_by_fix"] = removed
        if complete:
            out.write_text(json.dumps(result, indent=1) + "\n")
        print(json.dumps({"case": case["id"], "files": f"{len(done)}/{len(by_file)}", "candidates": len(unique), "triaged_out": triaged_out, "agreed": len(agreed), "disputed": len(disputed), "usd": result["usd"], "total_usd": round(spent, 4), "complete": complete}), flush=True)
        if account_error:
            print(json.dumps({"stopped": "account", "error": account_error}), flush=True)
            return 2
        if spent >= args.budget_usd:
            print(json.dumps({"stopped": "budget", "spent_usd": round(spent, 4)}), flush=True)
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
