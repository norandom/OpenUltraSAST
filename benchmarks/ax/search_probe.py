"""Dispatch the packaged no-model probe using the shared engine/replay transport.

python -m benchmarks.ax.search_probe --lane ax --image IMAGE@sha256:DIGEST --out /tmp/probe
For kind, select --lane kind and supply its --kubeconfig; Docker uses the same PUT protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from benchmarks.ax.batch import AXLane, DockerLane, Item, Workload, dispatch, validate_image


def validate_result(data: bytes, output: Path) -> None:
    if len(data) > 1024 * 1024:
        raise ValueError("oversized probe result")
    record = json.loads(data)
    if not isinstance(record, dict) or record.get("status") not in ("ok", "instrument_failure"):
        raise ValueError("invalid probe result")
    if record["status"] == "ok" and (
        set(record.get("oracles", {})) != {"sql", "path", "command", "ssrf", "xss"}
        or record.get("isolation_check", {}).get("status") not in ("ok", "skipped")
    ):
        raise ValueError("incomplete probe")
    (output / "result.json").write_text(json.dumps(record))


def probe_workload(image: str, deadline: float = 900) -> Workload:
    validate_image(image)
    return Workload(image, frozenset({"RESULT_URL"}), deadline, validate_result, kind="search-probe")


def probe_item(image: str) -> Item:
    return Item(
        "v1",
        {},
        "result.json",
        ("python3", "-m", "openultrasast.search.probe"),
        {},
        hashlib.sha256(("search-probe-v1:" + image).encode()).hexdigest(),
    )


def run_probe(args) -> bool:
    workload = probe_workload(args.image, args.deadline)
    transport = (DockerLane if args.lane == "docker" else AXLane)(args, workload)
    return dispatch([probe_item(args.image)], workload, args.out, {args.lane: transport}, lanes=(args.lane,), max_attempts=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--lane", choices=("ax", "kind", "docker"), default="ax")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--deadline", type=float, default=900)
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--docker-image-bytes", type=int)
    return 1 if run_probe(parser.parse_args()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
