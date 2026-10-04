"""Dispatch frozen unseen changes or a five-change project-history proof."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path

from benchmarks.ax.batch import AXLane, DockerLane, Item, Workload, dispatch, write_json
from benchmarks.unseen.score import coverage


def make_item(change, arm, image):
    if arm not in {"default", "long_deadline"}:
        raise ValueError("unknown replay arm")
    identity = hashlib.sha256(str(change["id"]).encode()).hexdigest()[:14]
    spec = {**change, "id": identity, "hook_flags": [] if arm == "default" else ["--deadline", "300"], "image": image}
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
    items = [make_item(change, args.arm, args.image) for change in changes]
    if len({i.id for i in items}) != len(items):
        parser.error("duplicate change identity")
    args.out = args.out or Path.home() / "ousast-results/unseen" / args.pool / args.slice / args.arm
    if args.dry_run:
        print(json.dumps({"items": len(items), "input_digest": hashlib.sha256(canonical([i.input_digest for i in items])).hexdigest()}))
        return 0
    if args.out.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error("raw replay output must be outside the repository")
    write_json(
        args.out / "inputs.json",
        [{"item_id": item.id, "change": change, "input_digest": item.input_digest} for item, change in zip(items, changes, strict=True)],
    )
    workload = Workload(args.image, frozenset({"SPEC_URL", "RESULT_URL"}), 600 if args.arm == "default" else 900, validate_result)
    lanes = ("ax", "ax", "docker") if args.lane == "mixed" else (args.lane,) * (2 if args.lane in {"ax", "kind"} else 1)
    executors = {}
    for lane in set(lanes):
        transport = (DockerLane if lane == "docker" else AXLane)(args, workload)

        def execute(item, output, attempt, transport=transport):
            record = {**json.loads(item.inputs["SPEC_URL"]), **transport(item, output, attempt)}
            if (output / "result.dat").exists():
                # Durable archive lives separately from attempt staging objects, which are deleted.
                key = f"unseen/{item.input_digest}/result.dat"
                transport.store._put(key, (output / "result.dat").read_bytes())
                record["result_object"] = key
            return record

        executors[lane] = execute
    return 2 if dispatch(items, workload, args.out, executors, lanes=lanes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
