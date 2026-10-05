"""Build anonymous coordinator proof records from completed dispatcher outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def records(root):
    return [json.loads(path.read_text()) for path in sorted(root.glob("*.json")) if path.name not in {"progress.json", "inputs.json"}]


def replay_proof(roots):
    lanes = {lane: records(root) for lane, root in roots.items()}
    if any(len(rows) != 5 for rows in lanes.values()):
        raise ValueError("proof requires exactly five completed changes per lane")
    keys = [{row["input_digest"] for row in rows} for rows in lanes.values()]
    if not all(key == keys[0] for key in keys):
        raise ValueError("lane input identities differ")
    quick = {}
    evidence = {}
    for lane, rows in lanes.items():
        quick[lane] = {}
        evidence[lane] = []
        for row in rows:
            inst = row.get("instrument", {})
            if (
                row.get("status") not in {"quick_only", "engine_covered"}
                or not inst.get("hook_bytes_read")
                or inst.get("suspect_fast")
                or inst.get("jvm_wall_seconds", 0) < 5
            ):
                raise ValueError("proof instrument has unread input or implausible JVM time")
            quick[lane][row["input_digest"]] = digest([t.get("findings", []) for t in row["push"].get("quick_tier", [])])
            evidence[lane].append(
                {
                    "input_digest": row["input_digest"],
                    "seconds": inst["seconds"],
                    "jvm_seconds": inst["jvm_wall_seconds"],
                    "bytes": inst["hook_bytes_read"],
                    "exit_code": inst["hook_exit"],
                }
            )
    equal = all(value == next(iter(quick.values())) for value in quick.values())
    if not equal:
        raise ValueError("quick-tier findings differ across lanes")
    return {"lanes": evidence, "quick_tier_equal": True, "quick_digests": quick, "cleanup": "completed-before-checkpoint"}


def engine_proof(root, baseline):
    current = records(root)
    old = {digest([r["repo"], r["pin"]]): r for r in records(baseline) if "repo" in r and "pin" in r}
    current = [r for r in current if "repo" in r and "pin" in r and not all(u.get("status") == "unsupported" for u in r["units"])]
    if len(current) != 2:
        raise ValueError("engine proof requires exactly two pins")
    evidence = []

    def stable(record):
        return [
            {key: u.get(key) for key in ("unit", "status", "questions_asked", "questions_completed", "witness_rows", "traces")}
            for u in record["units"]
        ]

    for row in current:
        key = digest([row["repo"], row["pin"]])
        previous = old[key]
        instruments = [u.get("instrument", {}) for u in row["units"]]
        if (
            not row.get("done")
            or not any(i.get("bytes", 0) > 0 for i in instruments)
            or not any(stage.get("seconds", 0) >= 5 for i in instruments for stage in i.get("jvm", []))
        ):
            raise ValueError("engine proof lacks bytes or realistic JVM time")
        evidence.append(
            {
                "pin_digest": key,
                "seconds": row.get("seconds"),
                "record_digest": digest(stable(row)),
                "baseline_digest": digest(stable(previous)),
                "equal": stable(row) == stable(previous),
                "instrument": [
                    {
                        "bytes": u.get("instrument", {}).get("bytes", 0),
                        "cpg_bytes": u.get("instrument", {}).get("cpg_bytes", 0),
                        "jvm": [
                            {key: stage.get(key) for key in ("seconds", "exit_code", "success", "heap_mb")}
                            for stage in u.get("instrument", {}).get("jvm", [])
                        ],
                    }
                    for u in row["units"]
                ],
            }
        )
    return {"pins": evidence, "differences": sum(not e["equal"] for e in evidence), "cleanup": "completed-before-checkpoint"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("engine", "replay"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--records", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--kind-records", type=Path)
    parser.add_argument("--ax-records", type=Path)
    parser.add_argument("--vm-records", type=Path)
    args = parser.parse_args()
    result = (
        engine_proof(args.records, args.baseline)
        if args.kind == "engine"
        else replay_proof({"kind": args.kind_records, "ax": args.ax_records, "vm": args.vm_records})
    )
    result.update(
        image=args.image, commit=subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
