"""Dispatch frozen unseen changes or a five-change project-history proof."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import subprocess
import tarfile
import tomllib
from pathlib import Path

from benchmarks.ax.batch import AXLane, DockerLane, Item, Workload, dispatch, write_json
from benchmarks.unseen.score import coverage


def make_item(change, arm, image, *, deadline_scale=1.0, lane="ax", deadline=None):
    if arm not in {"default", "long_deadline"}:
        raise ValueError("unknown replay arm")
    identity = hashlib.sha256(str(change["id"]).encode()).hexdigest()[:14]
    if not math.isfinite(deadline_scale) or deadline_scale <= 0:
        raise ValueError("deadline scale must be finite and positive")
    base = deadline if deadline is not None else 30 if arm == "default" else 300
    applied = round(base * (1 if lane == "docker" else deadline_scale))
    if applied < 1:
        raise ValueError("scaled deadline must be at least one second")
    spec = {
        **change,
        "id": identity,
        "hook_flags": ["--deadline", str(applied)],
        "image": image,
        "base_deadline_seconds": base,
        "deadline_seconds": applied,
        "deadline_scale": deadline_scale,
        "applied_deadline_scale": 1.0 if lane == "docker" else deadline_scale,
    }
    data = json.dumps(spec, sort_keys=True).encode()
    digest = hashlib.sha256(data).hexdigest()
    return Item(
        "replay-" + identity,
        {"SPEC_URL": data},
        "result.dat",
        ("python3", "/app/benchmarks/unseen/replay_entry.py"),
        {},
        digest,
        {"SPEC_URL": "spec.dat"},
    )


def validate_result(data, output):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        required = {"push.json", "push.txt", "engine.json", "instrument.json"}
        if {m.name for m in members} != required or any(not m.isfile() for m in members):
            raise ValueError("replay result requires push, engine and instrument.json")
        payload = {m.name: archive.extractfile(m).read() for m in members}
    instrument = json.loads(payload["instrument.json"])
    push = json.loads(payload["push.json"])
    record = {"instrument": instrument, "push": push}
    record["status"] = coverage(record)
    # Transport/scheduler needs an explicit OOM signal, not a quiet failed replay.
    if "OutOfMemoryError" in json.dumps(push) or "JVM out of memory" in json.dumps(push):
        record["status"] = "oom"
    output.mkdir(parents=True, exist_ok=True)
    for name, body in payload.items():
        (output / name).write_bytes(body)
    (output / "result.dat").write_bytes(data)
    write_json(output / "result.json", record)
    return record


def proof_changes(root):
    """Only the operator's project history; no pool data or fetches."""

    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()

    changes = []
    for head in git("rev-list", "--no-merges", "--max-count=100", "HEAD", "--", "src").splitlines():
        base = git("rev-parse", head + "^")
        changed = git("diff", "--name-only", base, head).splitlines()
        if not any(name.startswith("src/") and name.endswith(".py") for name in changed):
            continue
        changes.append(
            {
                "id": hashlib.sha256(head.encode()).hexdigest(),
                "repository_url": "https://github.com/norandom/OpenUltraSAST.git",
                "repo": "project-proof",
                "kind": "ordinary",
                "base": base,
                "head": head,
            }
        )
        if len(changes) == 5:
            break
    if len(changes) != 5:
        raise ValueError("history lacks five source changes")
    return changes


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_slice(path, slice_id, private_path=None):
    if path.suffix != ".toml":
        frozen = json.loads(path.read_text())
        changes = frozen["changes"]
        if frozen["sha256"] != hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest():
            raise ValueError("frozen changes digest mismatch")
        return changes
    if not path.name.startswith("pool-"):
        raise ValueError("replay requires a frozen pool, never a draft")
    pool = tomllib.loads(path.read_text())
    freeze = json.loads(path.with_name("freeze-" + path.stem.removeprefix("pool-") + ".json").read_text())
    if hashlib.sha256(canonical(pool)).hexdigest() != freeze["freeze_digest"]:
        raise ValueError("frozen pool digest mismatch")
    private_path = private_path or path.parent / "private" / path.name
    private = {}
    if private_path.exists():
        private = {row["id"]: row for row in tomllib.loads(private_path.read_text()).get("repository", [])}
    changes = []
    for public in pool.get("repository", []):
        if str(public["slice"]) != str(slice_id):
            continue
        row = public
        if public.get("private"):
            row = private.get(public["id"])
            if row is None:
                raise ValueError("missing private pool entry")
            payload = {"url": row["url"], "commits": [[c["base"], c["head"]] for c in row["changes"]]}
            if hashlib.sha256(canonical(payload)).hexdigest() != public["sha256"]:
                raise ValueError("private pool digest mismatch")
        for change in row["changes"]:
            identity = hashlib.sha256(canonical([public["id"], change["kind"], change["base"], change["head"]])).hexdigest()
            changes.append(
                {
                    **change,
                    "id": identity,
                    "repo": public["id"],
                    "repository_url": row["url"],
                    "freeze_digest": freeze["freeze_digest"],
                    "slice": slice_id,
                }
            )
    if not changes:
        raise ValueError("frozen slice has no changes")
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="frozen JSON: changes array plus sha256 of canonical changes JSON")
    parser.add_argument("--proof-history", action="store_true", help="write a five-change own-history manifest, then exit")
    parser.add_argument("--image")
    parser.add_argument("--private-manifest", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--arm", choices=("default", "long_deadline"), default="default")
    parser.add_argument("--pool", default="p1")
    parser.add_argument("--slice", default="1")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--lane", choices=("ax", "kind", "docker", "mixed"), default="mixed")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--deadline-scale", type=float, default=1.0)
    group.add_argument("--calibration", type=Path)
    parser.add_argument("--native-sample", type=int, default=0)
    parser.add_argument("--docker-image-bytes", type=int, help="unpacked image size upper bound, required for VM pull")
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--atespace", default="default")
    args = parser.parse_args()
    if args.proof_history:
        changes = proof_changes(Path.cwd())
        write_json(args.manifest, {"changes": changes, "sha256": hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()})
        return 0
    if not args.image:
        parser.error("--image digest is required")
    changes = load_slice(args.manifest, args.slice, args.private_manifest)
    factor = args.deadline_scale
    if args.calibration:
        calibration = json.loads(args.calibration.read_text())
        if calibration.get("status") != "ok" or calibration.get("image") != args.image:
            parser.error("calibration must be successful and match the replay image")
        factor = calibration["quick_total"]["factor"]
    if args.native_sample < 0 or (args.native_sample and args.lane not in {"ax", "kind"}):
        parser.error("--native-sample requires an ax or kind cluster run and a positive K")
    items = [make_item(change, args.arm, args.image, deadline_scale=factor, lane=args.lane) for change in changes]
    if len({i.id for i in items}) != len(items):
        parser.error("duplicate change identity")
    args.out = args.out or Path.home() / "ousast-results/unseen" / args.pool / args.slice / args.arm
    if args.dry_run:
        print(json.dumps({"items": len(items), "input_digest": hashlib.sha256(canonical([i.input_digest for i in items])).hexdigest()}))
        return 0
    if args.out.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error("raw replay output must be outside the repository")
    failed = run_replays(changes, args, args.out, args.lane, deadline_scale=factor)
    if args.native_sample:
        failed |= run_replays(sample_changes(changes, args.native_sample), args, args.out / "native", "docker", deadline_scale=factor)
    return 2 if failed else 0


def sample_changes(changes, count):
    if count < 1:
        raise ValueError("sample size must be positive")
    if len({str(c["id"]) for c in changes}) != len(changes):
        raise ValueError("duplicate change identity")
    return sorted(changes, key=lambda c: hashlib.sha256(str(c["id"]).encode()).digest())[:count]


def run_replays(changes, args, out, lane, *, deadline_scale=1.0, deadline=None):
    if out.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("raw replay output must be outside the repository")
    items = [make_item(c, args.arm, args.image, deadline_scale=deadline_scale, lane=lane, deadline=deadline) for c in changes]
    write_json(
        out / "inputs.json",
        [{"item_id": item.id, "change": change, "input_digest": item.input_digest} for item, change in zip(items, changes, strict=True)],
    )
    maximum = max(
        max(json.loads(i.inputs["SPEC_URL"])["deadline_seconds"], json.loads(i.inputs["SPEC_URL"])["base_deadline_seconds"]) for i in items
    )
    workload = Workload(args.image, frozenset({"SPEC_URL", "RESULT_URL"}), maximum + 600, validate_result, kind="replay")
    lanes = ("ax", "ax", "docker") if lane == "mixed" else (lane,) * (2 if lane in {"ax", "kind"} else 1)
    original = {item.id: change for item, change in zip(items, changes, strict=True)}
    executors = {}
    for name in set(lanes):
        transport = (DockerLane if name == "docker" else AXLane)(args, workload)

        def execute(item, output, attempt, transport=transport, name=name):
            spec = original[item.id]
            # Re-render on placement, including VM fallback: native is always unscaled.
            placed = make_item(spec, args.arm, args.image, deadline_scale=deadline_scale, lane=name, deadline=deadline)
            placed.id = item.id
            record = {**json.loads(placed.inputs["SPEC_URL"]), "lane": name, **transport(placed, output, attempt)}
            if (output / "result.dat").exists():
                key = f"unseen/{placed.input_digest}/{name}/result.dat"
                transport.store._put(key, (output / "result.dat").read_bytes())
                record["result_object"] = key
            return record

        executors[name] = execute
    return dispatch(items, workload, out, executors, lanes=lanes)


if __name__ == "__main__":
    raise SystemExit(main())
