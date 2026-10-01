"""Engine signals for the labelled pair corpus, on the host (learned-decision-engine task 5, design "Cost on the 7 GB host").

Per labelled pair (``ousast learn labels`` rows of source ``pairs``) and side (``vuln``, ``fixed``): the side's
excerpt -- with the documents that register it -- is materialised into a temporary directory, and the Joern engine
runs on it in ``openultrasast:dev`` (``benchmarks/push/finding_dump.py`` from a FROZEN source export, ``--network
none --memory 3g``, the pair's labelled families, ONE container at a time). The result is one JSON per side under
``--out`` (``<pair>--<side>.json``), keyed by the side's content sha256 and the engine image id; a rerun skips sides
already recorded, so the job resumes where it stopped.

The instrument must have read its input (:func:`openultrasast.plane.engine_alerts.read_record`): no result file, no
``read N files`` line or ``questions == 0`` is recorded as ``state: failed`` with the reason (retried once), never as
zero findings. A side whose language the engine has no model for is ``state: none`` and is not run.

Guards: free disk is checked before every side and every 60 s while a container runs; below ``--min-free-gb`` the
container is killed by its name, the side is left unrecorded (``missing``) and the job stops. A file ``STOP`` in
``--out`` stops the job cleanly between sides. Progress lines go to ``--out/progress.jsonl``.

Usage::

    python benchmarks/learn/engine_pairs.py --labels labels-<sha>.jsonl --source <frozen export> --out <dir>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from openultrasast.pairs import DEFAULT_CATALOG, _materialize_side, load_pair_catalog
from openultrasast.plane.engine_alerts import EngineAlertsError, docker_command, frozen_source, read_record
from openultrasast.plane.tasks.alerts import engine_languages
from openultrasast.preprocess import detect_language

SIDES = ("vuln", "fixed")
_OFFERED = re.compile(r"^read (\d+) files, \d+ bytes; (\d+) regions offer", re.MULTILINE)


def free_gb(path: Path) -> float:
    return shutil.disk_usage(path).free / 1e9


def units(labels: Path, catalog: Path) -> list[tuple[object, str, tuple[str, ...]]]:
    """(pair case, side, families) for every labelled pair, in name order."""
    families: dict[str, set[str]] = {}
    for line in labels.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["source"] == "pairs" and row["unit"] == "pin" and row["family"] != "unknown":
            families.setdefault(row["source_ref"], set()).add(row["family"])
    cases = {case.name: case for case in load_pair_catalog(catalog)}
    return [(cases[name], side, tuple(sorted(families[name]))) for name in sorted(families) for side in SIDES]


def image_id(image: str) -> str:
    done = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image], capture_output=True, text=True, check=False)
    if done.returncode != 0 or not done.stdout.strip():
        raise SystemExit(f"no engine image {image}")
    return done.stdout.strip()


def run_side(
    command: list[str], name: str, timeout: float, out: Path, min_free: float
) -> tuple[subprocess.CompletedProcess[str] | None, str]:
    """Run one container; a watchdog kills it by name when free disk drops below ``min_free`` GB."""
    tripped: list[str] = []
    done = threading.Event()

    def watch() -> None:
        while not done.wait(60.0):
            if free_gb(out) < min_free:
                tripped.append(f"free disk {free_gb(out):.2f} GB < {min_free} GB")
                subprocess.run(["docker", "kill", name], capture_output=True, check=False)
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True, check=False)
        completed = None
    done.set()
    return completed, (tripped[0] if tripped else "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--source", type=Path, required=True, help="frozen export: git archive HEAD src benchmarks/push/finding_dump.py")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--image", default="openultrasast:dev")
    parser.add_argument("--deadline", type=float, default=600.0)
    parser.add_argument("--min-free-gb", type=float, default=1.0)
    parser.add_argument("--limit", type=int, default=0, help="stop after this many sides were run (0: all)")
    args = parser.parse_args()
    source = frozen_source(args.source)
    args.out.mkdir(parents=True, exist_ok=True)
    image = image_id(args.image)
    covered = engine_languages()
    progress = (args.out / "progress.jsonl").open("a", encoding="utf-8")
    ran = 0
    for case, side, families in units(args.labels, args.catalog):
        result_path = args.out / f"{case.name}--{side}.json"
        if result_path.is_file():
            continue
        if (args.out / "STOP").exists() or (args.limit and ran >= args.limit):
            print("stopped between sides", flush=True)
            return 0
        if free_gb(args.out) < args.min_free_gb:
            print(f"disk guard: {free_gb(args.out):.2f} GB free; stopping", flush=True)
            return 4
        excerpt = case.vuln_file if side == "vuln" else case.fixed_file
        if not excerpt.is_file():
            entry = {"state": "failed", "reason": "excerpt not materialised"}
        else:
            entry = {"sha256": hashlib.sha256(excerpt.read_bytes()).hexdigest()}
            language = detect_language(Path(case.relpath)) or "other"
            if language not in covered:
                entry.update(state="none", reason=f"no engine model for {language}")
            else:
                entry.update(_scan(case, side, families, source, args, image))
                ran += 1
                if entry.get("state") == "missing":
                    print(json.dumps({"pair": case.name, "side": side, **entry}), flush=True)
                    return 4
        record = {"pair": case.name, "side": side, "families": list(families), "image": image, **entry}
        result_path.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        line = {k: record.get(k) for k in ("pair", "side", "state", "questions", "completed", "seconds", "reason")}
        line["findings"] = len(record.get("findings") or [])
        progress.write(json.dumps(line) + "\n")
        progress.flush()
        print(json.dumps(line), flush=True)
    return 0


def _scan(case: object, side: str, families: tuple[str, ...], source: Path, args: argparse.Namespace, image: str) -> dict:
    reason = ""
    for attempt in (1, 2):
        with tempfile.TemporaryDirectory(prefix="ep-", dir=args.out) as tmp:
            checkout = _materialize_side(Path(tmp) / "case", case, side=side)
            out_dir = Path(tmp) / "out"
            out_dir.mkdir()
            name = f"ousast-ep-{hashlib.sha1(f'{case.name}{side}'.encode()).hexdigest()[:12]}"
            command = docker_command(source, checkout, out_dir, "result", ",".join(families), args.deadline, args.image)
            command[2:2] = ["--name", name]
            completed, tripped = run_side(command, name, args.deadline + 300, args.out, args.min_free_gb)
            if tripped:
                return {"state": "missing", "reason": tripped}
            if completed is None:
                reason = f"timeout after {args.deadline + 300:.0f}s"
                continue
            log = (completed.stdout or "") + "\n" + (completed.stderr or "")
            try:
                record = read_record(out_dir / "result.json", log, completed.returncode)
            except EngineAlertsError as exc:
                reason = f"attempt {attempt}: {exc}"[:600]
                offered = _OFFERED.search(log)
                result = out_dir / "result.json"
                if offered is not None and int(offered.group(1)) > 0 and result.is_file():
                    # It read its input and finished without asking: deterministic (a retry asks nothing either). Still
                    # `failed` by the design's rule (questions == 0 is never zero findings); the reason keeps it apart
                    # from a launch failure, because on a fixed side "no question" may mean "no sink left".
                    recorded = json.loads(result.read_text(encoding="utf-8"))
                    regions = int(offered.group(2))
                    why = "no region offers the families" if regions == 0 else f"no question asked for {regions} regions"
                    return {"state": "failed", "reason": why, "files": int(offered.group(1)), "regions": regions,
                            "seconds": recorded.get("seconds"), "degradations": recorded.get("degradations")}  # fmt: skip
                continue
            return {"state": "ran", **{k: v for k, v in record.items() if k != "root"}}
    return {"state": "failed", "reason": reason}


if __name__ == "__main__":
    sys.exit(main())
