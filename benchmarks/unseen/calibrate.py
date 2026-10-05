"""Paired native/cluster deadline calibration; publish only opaque IDs and numbers."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from datetime import date
from pathlib import Path

from benchmarks.ax.batch import write_json
from benchmarks.unseen.replay import canonical, load_slice, run_replays, sample_changes
from benchmarks.unseen.score import coverage, load_records


def stage_times(record):
    if coverage(record) == "instrument_failure":
        raise ValueError("calibration instrument failed")
    push = record["push"]
    if "deadline_exhausted" in json.dumps(push) or any(t.get("status") == "failed" for t in push.get("quick_tier", [])):
        raise ValueError("calibration deadline exhausted or quick tier failed; increase deadline")
    raw = push.get("timings", {})
    timings = {}
    for key, value in raw.items():
        key = re.sub(r"^comparison_\d+_", "", key)
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid stage timing")
        timings[key] = timings.get(key, 0) + value
    required = ("resolution_seconds", "provenance_seconds", "preparation_seconds", "quick_seconds", "snapshot_seconds")
    if any(key not in timings for key in required):
        raise ValueError("missing completed quick-stage timings")
    scans = [r["scan"] for r in push.get("scans", [])]
    if any(s.get("degradations") for s in scans):
        raise ValueError("incomplete engine stages; calibration cannot use degraded scans")
    if not scans or any(k not in s for s in scans for k in ("build_seconds", "query_seconds")):
        raise ValueError("missing engine timings")
    result = {
        "snapshot": timings["snapshot_seconds"],  # Nested inside preparation; never counted twice.
        "preparation": timings["preparation_seconds"],
        "quick": timings["quick_seconds"],
        "quick_total": sum(timings[k] for k in required if k != "snapshot_seconds"),
        "engine_build": sum(s["build_seconds"] for s in scans),
        "engine_queries": sum(s["query_seconds"] for s in scans),
        "hook": record["instrument"].get("timings", {}).get("pre-push"),
    }
    if any(not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0 for v in result.values()):
        raise ValueError("missing or nonpositive stage timing")
    return result


def slowdown(native, cluster, *, seed=0, draws=2000):
    if not native or len(native) != len(cluster):
        raise ValueError("calibration needs paired timings")
    if any(not math.isfinite(v) or v <= 0 for v in [*native, *cluster]):
        raise ValueError("timings must be finite and positive")
    ratios = [b / a for a, b in zip(native, cluster, strict=True)]
    rng = random.Random(seed)
    bootstrap = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(draws))
    return {
        "n": len(ratios),
        "factor": statistics.median(ratios),
        "bootstrap95": [bootstrap[int(0.025 * (draws - 1))], bootstrap[int(0.975 * (draws - 1))]],
    }


def calibration_record(native, cluster):
    nn, cc = ({r["id"]: r for r in rows} for rows in (native, cluster))
    if not nn or nn.keys() != cc.keys() or len(nn) != len(native) or len(cc) != len(cluster):
        raise ValueError("calibration requires exactly paired unique changes")
    pairs = []
    for key in sorted(nn):
        if nn[key].get("lane") != "docker" or cc[key].get("lane") != "ax":
            raise ValueError("calibration requires native docker and cluster ax lanes")
        pairs.append(
            {"change_id": hashlib.sha256(str(key).encode()).hexdigest(), "native": stage_times(nn[key]), "cluster": stage_times(cc[key])}
        )
    return {
        "status": "ok",
        "changes": len(pairs),
        "pairs": pairs,
        **{
            stage: slowdown([p["native"][stage] for p in pairs], [p["cluster"][stage] for p in pairs])
            for stage in ("quick_total", "engine_build", "engine_queries")
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-manifest", type=Path)
    parser.add_argument("--slice", default="1")
    parser.add_argument("--sample", type=int, default=20)
    parser.add_argument("--deadline", type=int, default=600)
    parser.add_argument("--image", required=True)
    parser.add_argument("--docker-image-bytes", type=int, required=True, help="unpacked image size upper bound")
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--out", type=Path, default=Path.home() / "ousast-results/unseen/calibration")
    parser.add_argument("--record", type=Path, default=Path("benchmarks/measurements") / f"{date.today()}-unseen-calibration/record.json")
    args = parser.parse_args()
    if args.deadline < 1 or args.sample < 1:
        parser.error("deadline and sample must be positive")
    args.arm = "default"
    changes = sample_changes(load_slice(args.manifest, args.slice, args.private_manifest), args.sample)
    failed = False
    for lane, directory in (("docker", "native"), ("ax", "cluster")):
        failed |= run_replays(changes, args, args.out / directory, lane, deadline=args.deadline)
    result = {"status": "failed", "changes": len(changes)}
    if not failed:
        try:
            result = calibration_record(load_records(args.out / "native"), load_records(args.out / "cluster"))
        except ValueError as exc:
            result["reason"] = str(exc)  # Only locally controlled diagnostics.
    result.update(
        image=args.image, deadline_seconds=args.deadline, sample_digest=hashlib.sha256(canonical([c["id"] for c in changes])).hexdigest()
    )
    write_json(args.record, result)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
