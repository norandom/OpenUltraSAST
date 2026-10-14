"""Feature table and separation screen over a frozen training pool, no model calls.

For every change of the pool's slice, check out its head, enumerate the candidate rows (touched functions at head
plus the labelled fix site) and compute the four producers. Rows are labelled 1 at an accepted fix site, 0 on an
ordinary push and null elsewhere on a positive. The screen then scores every engineered feature alone against the
label (ROC-AUC) and reports the strongest feature per annotation. Repositories are the clusters: with few of them
the screen is a direction, not a result, and the output says how many there are.

    PYTHONPATH=. .venv/bin/python benchmarks/measurements/2026-10-13-access-control-screen/table.py \\
        benchmarks/valid/train/pool-train.toml --repos ~/ousast-results/valid/train/repos_hist.json --out <dir>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from pathlib import Path

from openultrasast.hunt import features
from openultrasast.hunt.producers import compute_rows
from openultrasast.hunt.runner import _full_checkout as full_checkout
from openultrasast.hunt.table import FeatureTable, canonical_json
from openultrasast.stats import separation


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def changes_of(pool: Path, slice_id: int) -> list[dict]:
    data = tomllib.loads(pool.read_text())
    rows = next(value for value in data.values() if isinstance(value, list) and value and "changes" in value[0])
    out = []
    for row in rows:
        if int(row.get("slice", 1)) != slice_id:
            continue
        for change in row["changes"]:
            change = dict(change)
            change.setdefault("repo", row.get("repository") or row.get("repo") or row["id"])
            change.setdefault("id", change["case_id"])
            out.append(change)
    return out


def rows_for(change: dict, clone: Path) -> tuple[list[dict], dict]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ousast-table-") as temporary:
        root = Path(temporary) / "head"
        _git(clone, "worktree", "add", "--detach", str(root), change["head"])
        try:
            if _git(root, "rev-parse", "HEAD").strip() != change["head"]:
                raise RuntimeError("head_mismatch")
            full_checkout(root)
            rows = compute_rows(root, change)
        finally:
            _git(clone, "worktree", "remove", "--force", str(root))
    return rows, {"seconds": round(time.monotonic() - started, 2), "rows": len(rows)}


def unread_rows(rows: list[dict], repos: dict[str, str]) -> int:
    """Rows whose file the source producer could not read although git holds a non-empty blob at head.

    An empty or missing file in the worktree is a checkout failure, not a feature; the first build read 150 such
    rows as feature-free (every positive of one repository among them) and nothing in the screen said so."""
    count = 0
    checked: dict[tuple[str, str, str], bool] = {}
    for row in rows:
        if row.get("provenance.source.reason") not in ("empty_source", "FileNotFoundError"):
            continue
        key = (row["repo"], row["head"], row["path"])
        if key not in checked:
            clone = Path(repos[row["repo"]]).expanduser()
            size = subprocess.run(
                ["git", "-C", str(clone), "cat-file", "-s", f"{row['head']}:{row['path']}"], capture_output=True, text=True
            )
            checked[key] = size.returncode == 0 and int(size.stdout.strip() or 0) > 0
        count += checked[key]
    return count


def resume(rows_path: Path, log_path: Path) -> tuple[list[dict], list[dict]]:
    """Rows and log entries an earlier run wrote into the same output directory, one change at a time.

    The first screen over the second pool kept every row in memory and lost 422 finished changes when one change
    had to be stopped; now each change lands on disk as it finishes and a restart skips the finished ones.
    """
    if not log_path.exists():
        return [], []
    log = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    done = {entry["id"] for entry in log}
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines() if line.strip()] if rows_path.exists() else []
    return [row for row in rows if row["change_id"] in done], log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("pool", type=Path)
    parser.add_argument("--repos", type=Path, required=True, help="JSON map repo -> local clone with history")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--slice", type=int, default=1)
    args = parser.parse_args(argv)
    repos = json.loads(args.repos.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    rows_path, log_path = args.out / "rows.jsonl", args.out / "log.jsonl"
    rows, log = resume(rows_path, log_path)
    done = {entry["id"] for entry in log}
    if done:
        print(f"resuming: {len(done)} changes and {len(rows)} rows already on disk", flush=True)
    with rows_path.open("a", encoding="utf-8") as rows_stream, log_path.open("a", encoding="utf-8") as log_stream:
        for change in changes_of(args.pool, args.slice):
            if change["id"] in done:
                continue
            clone = Path(repos[change["repo"]]).expanduser()
            try:
                produced, info = rows_for(change, clone)
            except Exception as error:  # noqa: BLE001  (type only; a message can carry a path)
                info = {"failure": type(error).__name__}
                produced = []
            rows.extend(produced)
            entry = {"id": change["id"], "repo": change["repo"], "kind": change["kind"], **info}
            log.append(entry)
            # Rows first, the log entry last: a change without its entry is recomputed on resume and the rows it
            # wrote are dropped, so a kill between the two writes never duplicates rows.
            for row in produced:
                rows_stream.write(canonical_json(row) + "\n")
            rows_stream.flush()
            log_stream.write(json.dumps(entry) + "\n")
            log_stream.flush()
            print(f"{change['id'][:16]} {change['kind']} {info}", flush=True)
    table = FeatureTable(rows)
    table.write_jsonl(args.out / "table.jsonl")
    # The instrument gate: a producer that failed on every row saw an unread tree, not a feature-free one.
    provenance = {name: sum(bool(row.get(f"provenance.{name}.ok")) for row in rows) for name in ("diff", "source", "semantic", "taxonomy")}
    print("producer rows ok:", provenance, "of", len(rows), flush=True)
    if rows and provenance["source"] == 0:
        print("the source producer read nothing: refusing to screen an unread tree", file=sys.stderr)
        return 2
    unread = unread_rows(rows, repos)
    print("rows unread although git holds the file:", unread, flush=True)
    if unread:
        print("the checkout was incomplete for some rows: refusing to screen a partly unread tree", file=sys.stderr)
        return 2
    (args.out / "log.json").write_text(json.dumps(log, indent=1))
    frame = features.feature_frame(table)
    labelled = frame[frame["label"].isin([0, 1])]
    summary = {
        "producer_rows_ok": provenance,
        "table_digest": table.digest(),
        "rows": len(frame),
        "labelled": {"positive": int((labelled["label"] == 1).sum()), "negative": int((labelled["label"] == 0).sum())},
        "repositories": int(labelled["repo"].nunique()),
        "changes": int(labelled["change_id"].nunique()),
        "positive_repositories": int(labelled[labelled["label"] == 1]["repo"].nunique()),
        "source_failures": dict(Counter(row.get("provenance.source.reason") for row in rows if not row.get("provenance.source.ok"))),
        "unread_rows": unread,
        # The recall ceiling of a diff-scoped candidate set: positive rows a label-blind enumeration would reach.
        "positive_rows_on_changed_line": int(labelled[(labelled["label"] == 1) & (labelled["diff.on_changed_line"] == 1)].shape[0]),
        "positive_rows_with_deletions": int(labelled[(labelled["label"] == 1) & (labelled["diff.deletion_count"].fillna(0) > 0)].shape[0]),
    }
    columns = [name for name in features.ENGINEERED if name in frame.columns]
    per_feature = separation(labelled, "label", columns)
    per_feature["annotation"] = [features.ENGINEERED[name][1] for name in per_feature["column"]]
    per_feature.to_csv(args.out / "separation.csv", index=False)
    features.screen(labelled).to_csv(args.out / "screen.csv", index=False)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary))
    print(per_feature.sort_values("auc", key=lambda s: (s - 0.5).abs(), ascending=False).to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
