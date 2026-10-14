"""Run deterministic access-control proofs on local frozen changes and score the arm."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import tempfile
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from benchmarks.unseen import score
from benchmarks.unseen.extract import SHA, InstrumentFailure
from benchmarks.unseen.replay import canonical, load_slice
from benchmarks.valid import metrics
from benchmarks.valid.catalog import local_git
from openultrasast.hunt.producers import Context, _Absent, _safe_path
from openultrasast.hunt.prover import prove_change


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def _record_path(out, identity):
    return out / (hashlib.sha256(identity.encode()).hexdigest() + ".json")


def _prove(change, repos, *, max_depth):
    started = time.monotonic()
    instrument = dict(
        hook_exit=0,
        hook_bytes_read=0,
        changed_bytes={},
        file_bytes={},
        head_verified=False,
        base_verified=False,
        suspect_fast=False,
        failure=None,
    )
    record = {
        **change,
        "done": True,
        "status": "prover_covered",
        "instrument": instrument,
        "findings": [],
        "traces": [],
        "coverage": {},
        "degradations": [],
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
    }
    try:
        if not all(SHA.fullmatch(change[side]) for side in ("base", "head")):
            raise InstrumentFailure("invalid revision")
        git = local_git(Path(repos[change["repo"]]).expanduser().resolve())
        git.run("cat-file", "-e", change["base"] + "^{commit}")
        instrument["base_verified"] = True
        with tempfile.TemporaryDirectory(prefix="ousast-prover-") as temporary:
            root = Path(temporary) / "head"
            added = False
            try:
                git.run("-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(root), change["head"])
                added = True
                checked_git = local_git(root)
                # Use the local-only Git runner even when expanding an inherited sparse checkout.
                if (
                    checked_git.runner(
                        ["git", "-C", str(root), "config", "--get", "core.sparseCheckout"], capture_output=True, text=True
                    ).stdout.strip()
                    == "true"
                ):
                    checked_git.run("sparse-checkout", "disable")
                if checked_git.run("status", "--porcelain", "--untracked-files=no").strip():
                    raise InstrumentFailure("incomplete checkout")
                ctx = Context(root, change)
                ctx.verify_head()
                instrument["head_verified"] = True
                changed = {file["path"] for file in change.get("files", [])}
                # Verify every source read, including hop files, before trusting a quiet verdict.
                for relative in sorted(changed | set(ctx.product_files)):
                    path = _safe_path(root, relative)
                    if not path.is_file():
                        held = checked_git.runner(["git", "-C", str(root), "cat-file", "-e", f"HEAD:{relative}"], capture_output=True)
                        if held.returncode == 0:
                            raise InstrumentFailure("unread tracked file")
                        continue  # a file deleted by this change has no head input
                    try:
                        text = ctx.read(relative)
                    except _Absent as error:
                        # A file git holds empty is read, not unread: the first smoke run failed four changes on
                        # legitimately empty files (`__init__.py`, an empty asset). Anything else absent is unread.
                        held = checked_git.runner(
                            ["git", "-C", str(root), "cat-file", "-s", f"HEAD:{relative}"], capture_output=True, text=True
                        )
                        if error.reason == "empty_source" and held.returncode == 0 and int(held.stdout.strip() or 0) == 0:
                            instrument["empty_files"] = instrument.get("empty_files", 0) + 1
                            continue
                        raise InstrumentFailure("unread tracked file") from error
                    # The byte table holds only files that were read; a zero here is a real zero-byte read, which
                    # stays on the record so the summary refuses it.
                    size = len(text.encode("utf-8"))
                    instrument["file_bytes"][relative] = size
                    if relative in changed:
                        instrument["changed_bytes"][relative] = size
                    print(f"{change['id']} {relative}: {size} bytes read", flush=True)
                    if not size:
                        raise InstrumentFailure("zero-byte read")
                result = prove_change(root, change, ctx, max_depth=max_depth)
                instrument["hook_bytes_read"] = sum(instrument["file_bytes"].values())
                record.update(
                    findings=list(result.findings),
                    traces=list(result.traces),
                    coverage=asdict(result.coverage),
                    degradations=list(result.degradations),
                )
                record["push"]["admission"]["defects"] = [
                    {**finding, "defect_id": finding["id"], "source": "prover", "locations": [[finding["path"], finding["line"]]]}
                    for finding in result.findings
                ]
            finally:
                if added:
                    git.run("worktree", "remove", "--force", str(root))
    except Exception as error:
        instrument.update(hook_exit=2, failure=type(error).__name__)
        record.update(status="instrument_failure", findings=[])
        record["push"]["admission"]["defects"] = []
        print(f"{change['id']}: instrument_failure ({type(error).__name__})", flush=True)
    record["seconds"] = time.monotonic() - started
    return record


def run(manifest, repos_path, out, *, slice_id="1", only="all", max_depth=3):
    if max_depth < 0 or only not in {"all", "ordinary", "vulnerability"}:
        raise ValueError("invalid prover arguments")
    manifest, repos_path, out = Path(manifest), Path(repos_path), Path(out)
    changes = load_slice(manifest, slice_id)
    if len({change["id"] for change in changes}) != len(changes):
        raise ValueError("duplicate change ids")
    changes = [change for change in changes if only == "all" or change["kind"] == only]
    index = out / "inputs.json"
    entries = json.loads(index.read_text()) if index.exists() else []
    if len({entry["item_id"] for entry in entries}) != len(entries):
        raise ValueError("duplicate inputs")
    indexed = {entry["item_id"]: entry for entry in entries}
    pending = []
    for change in changes:
        digest = hashlib.sha256(canonical({"change": change, "max_depth": max_depth, "arm": "prover-a"})).hexdigest()
        previous_entry = indexed.get(change["id"])
        if previous_entry and (previous_entry["change"] != change or previous_entry["input_digest"] != digest):
            raise ValueError("existing prover inputs do not match")
        entry = dict(item_id=change["id"], change=change, input_digest=digest)
        if not previous_entry:
            entries.append(entry)
        path = _record_path(out, change["id"])
        previous = json.loads(path.read_text()) if path.exists() else {}
        if previous and previous.get("input_digest") != digest:
            raise ValueError("existing prover inputs do not match")
        if previous.get("done"):
            print(f"{change['id']}: skipped (done)", flush=True)
        else:
            pending.append(entry)
    _write_json(index, entries)
    repos = json.loads(repos_path.read_text())
    failed = False
    for entry in pending:
        record = _prove(entry["change"], repos, max_depth=max_depth)
        record["input_digest"] = entry["input_digest"]
        _write_json(_record_path(out, entry["item_id"]), record)
        failed |= record["status"] == "instrument_failure"
    return 2 if failed else 0


def summarize(out, *, seed=0):
    out = Path(out)
    records = score.load_records(out)
    if not records or len({row["id"] for row in records}) != len(records):
        raise ValueError("missing or duplicate prover records")
    for record in records:
        instrument = record.get("instrument", {})
        if any(size == 0 for field in ("changed_bytes", "file_bytes") for size in instrument.get(field, {}).values()):
            raise ValueError("zero-byte read of a tracked file; summary refused")
    result = metrics.summarize(records, seed=seed)
    usable = [row for row in records if score.coverage(row) != "instrument_failure"]
    locations = [
        bool(score.catches({**row, **target, "files": [{"path": target["path"], "head_lines": [target["function_lines"]]}]}))
        for row in usable
        if row["kind"] == "vulnerability"
        for target in row.get("targets") or [row]
    ]
    repositories = {}
    framework_rows = {}
    fields = ("entry_points", "reached", "unreached", "operations_checked", "operations_discharged")
    for row in records:
        cov = row.get("coverage", {})
        repository = repositories.setdefault(
            row["repo"],
            {
                **dict.fromkeys(fields, 0),
                "files_by_language": Counter(),
                "frameworks_recognised": Counter(),
                "unchecked_by_reason": Counter(),
                "changes": 0,
            },
        )
        repository["changes"] += 1
        for field in fields:
            repository[field] += cov.get(field, 0)
        for field in ("files_by_language", "frameworks_recognised", "unchecked_by_reason"):
            repository[field].update(cov.get(field, {}))
        for framework, count in cov.get("frameworks_recognised", {}).items():
            table = framework_rows.setdefault(
                framework, {"files": 0, "changes": 0, **dict.fromkeys(fields, 0), "unchecked_by_reason": Counter()}
            )
            table["files"] += count
            table["changes"] += 1
            for field in fields:
                table[field] += cov.get(field, 0)
            table["unchecked_by_reason"].update(cov.get("unchecked_by_reason", {}))
    uncovered = sorted(repo for repo, cov in repositories.items() if not cov["frameworks_recognised"])
    for repo, cov in repositories.items():
        cov["status"] = "uncovered" if repo in uncovered else "covered"
        positives = [row for row in usable if row["repo"] == repo and row["kind"] == "vulnerability"]
        cov["recall"] = score.rate([bool(score.catches(row)) for row in metrics.scoring_records(positives)])
    seconds = [row["seconds"] for row in records]
    result.update(
        location_recall=score.rate(locations),
        per_repository=repositories,
        per_framework=framework_rows,
        uncovered_repositories=uncovered,
        covered_recall=score.rate(
            [
                bool(score.catches(row))
                for row in metrics.scoring_records(usable)
                if row["kind"] == "vulnerability" and row["repo"] not in uncovered
            ]
        ),
        uncovered_recall=score.rate(
            [
                bool(score.catches(row))
                for row in metrics.scoring_records(usable)
                if row["kind"] == "vulnerability" and row["repo"] in uncovered
            ]
        ),
        instrument_failures=sum(score.coverage(row) == "instrument_failure" for row in records),
        seconds_per_change=dict(n=len(seconds), mean=statistics.mean(seconds), median=statistics.median(seconds), maximum=max(seconds)),
        changes_over_120_seconds=[{"id": row["id"], "seconds": row["seconds"]} for row in records if row["seconds"] > 120],
    )
    # This is a training pool; the generic metric headline refers to unseen repositories.
    result["headline"] = result["headline"].replace("On unseen app repos:", "On the training pool:")
    _write_json(out / "summary.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    runner = commands.add_parser("run")
    runner.add_argument("pool", type=Path)
    runner.add_argument("--repos", type=Path, required=True)
    runner.add_argument("--out", type=Path, required=True)
    runner.add_argument("--slice", default="1")
    runner.add_argument("--only", choices=("all", "ordinary", "vulnerability"), default="all")
    runner.add_argument("--max-depth", type=int, default=3)
    summarizer = commands.add_parser("summarize")
    summarizer.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    if args.command == "run":
        status = run(args.pool, args.repos, args.out, slice_id=args.slice, only=args.only, max_depth=args.max_depth)
        if status:
            return status
    result = summarize(args.out)
    print(result["headline"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
