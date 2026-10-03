"""Resumable, serial, labelled-function Joern traces. No network or live-source mounts.

Pair pins are excerpt blob identities, NOT commits: materialize their catalog side
and registration documents. Repository pins are exported from existing local clones.
The analyzer is git archive HEAD src plus a hashed snapshot of this uncommitted tool's
implementation files; this allows review/worktree use without making a commit.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

from engine_trace_worker import safe_path, unit_record, write_json

from openultrasast.learn.examples import read_jsonl
from openultrasast.learn.labels import load_sources, repo_name
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params
from openultrasast.pairs import _materialize_side, load_pair_catalog
from openultrasast.plane.engine_alerts import export_pin
from openultrasast.plane.memory import FileStore
from openultrasast.plane.tasks.alerts import engine_languages
from openultrasast.preprocess import detect_language

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = Path.home() / "ousast-results/plane/engine-trace"
SNAPSHOT_FILES = (
    "benchmarks/learn/engine_trace.py",
    "benchmarks/learn/engine_trace_worker.py",
    "src/openultrasast/model/trace.py",
    "src/openultrasast/model/taint.py",
    "src/openultrasast/cpg/queries/taint.sc",
)
STATUSES = ("path", "asked-nothing", "failed", "timeout", "unsupported")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def pin_name(pin):
    return digest([pin["repo"], pin["pin"]]) + ".json"


def join_units(units, examples, include_typescript=False):
    index = {row["id"]: row for row in examples}
    missing = [u["unit"] for u in units if u["unit"] not in index]
    if missing:
        raise ValueError(f"example snapshot missing {len(missing)}/{len(units)} unit IDs; supply --examples JSONL; first: {missing[0]}")
    covered = engine_languages() - {"typescript"}
    if include_typescript:
        covered |= {"typescript"}
    result = []
    for unit in units:
        example = index[unit["unit"]]
        if any(example[key] != unit[key] for key in ("family", "label", "group")):
            raise ValueError(f"unit/example identity mismatch: {unit['unit']}")
        file, sep, function = example["candidate"].partition("::")
        if not sep or not function:
            raise ValueError(f"unit has no labelled function: {unit['unit']}")
        language = detect_language(Path(file)) or example.get("language", "other")
        model_language = "javascript" if language == "typescript" else language
        spec = taint_specs(language=model_language).get(unit["family"]) if language in covered else None
        result.append(
            {
                **unit,
                "repo": example["repo"],
                "pin": example["pin"],
                "file": file,
                "function": function,
                "language": language,
                "source": example["source"],
                "excerpt": example["source"] == "pairs",
                "pin_role": example.get("pin_role", ""),
                "supported": spec is not None,
                "reason": "" if spec else f"no admitted taint model: {language}/{unit['family']}",
            }
        )
    return result


def make_plan(units, out, only_family=None, limit=0, *, include_typescript=False):
    grouped = defaultdict(list)
    for unit in units:
        if not only_family or unit["family"] == only_family:
            # Include admission options even when a unit's support happens to stay
            # unchanged. Old results cannot mark a different selection as complete.
            identity = {"unit": unit, "include_typescript": include_typescript}
            grouped[unit["repo"], unit["pin"]].append({**unit, "input_digest": digest(identity)})
    plan = []
    for (repo, pin), rows in sorted(grouped.items()):
        item = {"repo": repo, "pin": pin, "units": sorted(rows, key=lambda r: r["unit"])}
        item["selection"] = digest(item["units"])
        done = out / pin_name(item)
        if done.exists():
            old = json.loads(done.read_text())
            recorded = {r["unit"]: r.get("input_digest") for r in old.get("units", [])}
            if old.get("done") and all(recorded.get(r["unit"]) == r["input_digest"] for r in rows):
                continue
        sources = {r["source"] for r in rows}
        # Inventory medians: harvest sides 31s, advisory sides 47s; v1 pins 182s, v2 pins 498s.
        item["estimated_seconds"] = (
            (47 if any(s.startswith("advisory") for s in sources) else 31)
            if any(r.get("excerpt") for r in rows) or any(s.startswith("advisory") for s in sources)
            else (182 if sources == {"population-v1"} else 498)
        )
        if not any(r["supported"] for r in rows):
            item["estimated_seconds"] = 0
        plan.append(item)
    # limit counts runnable pins, not unsupported records.
    if limit:
        chosen = []
        count = 0
        for pin in plan:
            runnable = any(r["supported"] for r in pin["units"])
            if runnable and count >= limit:
                continue
            chosen.append(pin)
            count += runnable
        return chosen
    return plan


class Inputs:
    """Resolve only the explicitly listed, spent corpora. Never fetch a missing clone."""

    def __init__(self, root, cache):
        self.cache = cache
        self.pairs = []
        self.repos = defaultdict(list)
        sources = load_sources()
        for source in sources.sources:
            if source.kind == "pairs":
                self.pairs.extend(load_pair_catalog(root / source.files[0]))
            elif source.kind == "population":
                if source.id not in {"population-v1", "population-v2"}:
                    continue
                data = tomllib.loads((root / source.files[0]).read_text())
                for case in data.get("case", []):
                    self.repos[repo_name(case["repo"])].append((cache / "independent" / case["id"], case))
            elif source.kind == "recipes":
                for file in source.files:
                    data = tomllib.loads((root / file).read_text())
                    recipe = data.get("repo", data)
                    # Recipes carry a top-level URL and a pinned checkout cache.
                    if isinstance(recipe, dict):
                        self.repos[repo_name(str(recipe.get("url", "")))].append((cache / "repos" / str(data.get("name", "")), data))
        self.hashes = {}

    def pair_for(self, row):
        side = "fixed" if row["pin_role"] == "fixed" else "vuln"
        candidates = [
            c for c in self.pairs if c.relpath == row["file"] and repo_name(c.repo or f"{c.slice}:{c.name}") == repo_name(row["repo"])
        ]
        matches = []
        for case in candidates:
            path = case.fixed_file if side == "fixed" else case.vuln_file
            if path.is_file():
                if path not in self.hashes:
                    data = path.read_bytes()
                    # Harvest hashes decoded text, so universal newline conversion is part
                    # of its identity (one recorded ThreatByte excerpt uses CRLF).
                    normalized = path.read_text().encode("utf-8")
                    self.hashes[path] = {
                        hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() for body in (data, normalized)
                    }
                if row["pin"] in self.hashes[path]:
                    matches.append(case)
        if len(matches) == 1:
            return matches[0], side
        if len(candidates) == 1:
            # Earlier stores used label_pin rather than the excerpt digest.
            from openultrasast.learn.examples import label_pin

            case = candidates[0]
            if row["pin"] == label_pin({"source": "pairs", "source_ref": case.name, "pin_role": row["pin_role"]}):
                return case, side
        raise ValueError(f"cannot uniquely resolve excerpt {row['repo']}@{row['pin']}:{row['file']}")

    def materialize(self, pin, target):
        rows = pin["units"]
        for row in rows:
            safe_path(target, row["file"])
            if row.get("mapping_error"):
                raise ValueError(row["mapping_error"])
        if all(r.get("excerpt") for r in rows):
            seen = set()
            for row in rows:
                case, side = self.pair_for(row)
                if (case.name, side) not in seen:
                    files = [(case.relpath, case.fixed_file if side == "fixed" else case.vuln_file)]
                    files.extend((rel, fixed if side == "fixed" else vuln) for rel, vuln, fixed in case.context_files)
                    for rel, source in files:
                        dest = safe_path(target, rel)
                        if dest.exists() and dest.read_bytes() != source.read_bytes():
                            raise ValueError(f"conflicting excerpt/context at one pin: {rel}")
                    _materialize_side(target, case, side=side)
                    seen.add((case.name, side))
            return
        if all(r["source"] == "dev-php" for r in rows):
            # Export the exact requested commit from the local recipe checkout.
            for recipe in (ROOT / "benchmarks/repos").glob("*.toml"):
                data = tomllib.loads(recipe.read_text())
                if repo_name(str(data.get("url", ""))) == repo_name(pin["repo"]):
                    checkout = self.cache / "repos" / data["name"] / pin["pin"][:12]
                    export_pin(checkout, pin["pin"], target)
                    return
        for clone, _ in self.repos[repo_name(pin["repo"])]:
            check = subprocess.run(["git", "-C", str(clone), "cat-file", "-e", pin["pin"] + "^{commit}"], capture_output=True)
            if check.returncode == 0:
                export_pin(clone, pin["pin"], target)
                return
        raise ValueError(f"no local clone contains {pin['repo']}@{pin['pin']}")


def freeze_source(target):
    target.mkdir(parents=True)
    archive = target.parent / "source.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD", "src"], stdout=stream, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(target)], check=True)
    archive.unlink()
    overlay = {}
    for name in SNAPSHOT_FILES:
        data = (ROOT / name).read_bytes()
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        overlay[name] = hashlib.sha256(data).hexdigest()
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    return {"head": head, "overlay_sha256": overlay}


def docker_command(source, checkout, out, name, image, deadline, question_deadline):
    return [
        "docker",
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--network",
        "none",
        "--memory",
        "3g",
        "--pull",
        "never",
        "--entrypoint",
        "python",
        "-e",
        "PYTHONPATH=/frozen/src",
        "-v",
        f"{source}:/frozen:ro",
        "-v",
        f"{checkout}:/case:ro",
        "-v",
        f"{out}:/out",
        image,
        "/frozen/benchmarks/learn/engine_trace_worker.py",
        "--worker",
        "/out/pin.json",
        "--deadline",
        str(deadline),
        "--question-deadline",
        str(question_deadline),
    ]


def prepare_questions(pin, root, question_deadline):
    """Prepare metadata on the host, before entering the dependency-minimal image."""
    active = [u for u in pin["units"] if u["supported"]]
    languages = {"javascript" if u["language"] == "typescript" else u["language"] for u in active}
    if len(languages) != 1:
        raise ValueError(f"one pin has multiple frontend languages: {sorted(languages)}")
    language = next(iter(languages))
    from openultrasast.learn.features import entry_names
    from openultrasast.mapping import php_hook_callbacks
    from openultrasast.plane.harvest import declares
    from openultrasast.preprocess import preprocess_repository

    _, targets = preprocess_repository(root)
    entries, _ = entry_names(root, {u["file"] for u in active})
    hooks = ";".join(f"{h}:{f}" for h, functions in php_hook_callbacks(root, targets).items() for f in functions)
    requests = {}
    specs = taint_specs(language=language)
    for u in active:
        if not declares(safe_path(root, u["file"]).read_text(errors="replace").splitlines(), u["file"], u["function"]):
            raise ValueError(f"labelled function not declared: {u['file']}::{u['function']}")
        excerpt = u.get("excerpt", False)
        params = request_params(
            specs[u["family"]],
            file=u["file"],
            function=u["function"],
            trace=True,
            parameter_sources=excerpt or u["function"] in entries,
            call_depth=0 if excerpt else 3,
            hook_callbacks=hooks,
        )
        params["questionDeadline"] = str(question_deadline)
        requests[u["unit"]] = params
    return requests


def run_pin(pin, source, provenance, inputs, out, args):
    with tempfile.TemporaryDirectory(prefix="trace-pin-", dir=out) as scratch:
        scratch = Path(scratch)
        checkout, output = scratch / "case", scratch / "output"
        output.mkdir()
        try:
            inputs.materialize(pin, checkout)
            write_json(output / "pin.json", {**pin, "questions": prepare_questions(pin, checkout, args.question_deadline)})
            name = "ousast-trace-" + pin_name(pin)[:16]
            command = docker_command(source, checkout, output, name, args.image, args.deadline, args.question_deadline)
            started = time.monotonic()
            done = None
            try:
                done = subprocess.run(command, capture_output=True, text=True, timeout=args.deadline)
                status, reason = "failed", f"container exit {done.returncode}: {done.stderr[-1000:]}"
                (output / "container.log").write_text(done.stdout + "\n" + done.stderr)
            except subprocess.TimeoutExpired:
                done = None
                status, reason = "timeout", f"container deadline {args.deadline}s"
            finally:
                # Never start the next pin unless this container is known to be gone.
                try:
                    removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
                except subprocess.SubprocessError as exc:
                    raise RuntimeError(f"cannot confirm container {name} stopped; refusing another launch") from exc
                if done is None and removed.returncode != 0:
                    raise RuntimeError(f"cannot remove timed-out container {name}; refusing another launch")
            result_path = output / "result.json"
            if not result_path.exists():
                reason = f"container produced no result: {reason}"
            record = json.loads(result_path.read_text()) if result_path.exists() else {**pin, "units": []}
            if not record.get("done"):
                previous = {u["unit"]: u for u in record["units"]}
                record["units"] = []
                for unit in pin["units"]:
                    row = previous.get(unit["unit"], unit_record(unit, status))
                    if row["status"] not in {"path", "asked-nothing"}:
                        row.update(
                            status=status if unit["supported"] else "unsupported", reason=reason if unit["supported"] else unit["reason"]
                        )
                    record["units"].append(row)
            record["container_exit"] = done.returncode if done else None
            if done is not None and done.returncode != 0:
                for row in record["units"]:
                    if row["supported"]:
                        row.update(status="failed", reason=reason)
            record.update(done=True, seconds=time.monotonic() - started, analyzer=provenance, image=args.image)
            if (output / "container.log").exists():
                shutil.copyfile(output / "container.log", out / pin_name(pin).replace(".json", ".log"))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            record = {
                **pin,
                "done": True,
                "analyzer": provenance,
                "units": [unit_record(u, "failed" if u["supported"] else "unsupported", str(exc)) for u in pin["units"]],
            }
        save_pin(out / pin_name(pin), record)
        print(
            json.dumps({"repo": pin["repo"], "pin": pin["pin"], "statuses": dict(Counter(u["status"] for u in record["units"]))}),
            flush=True,
        )
        return any(u["status"] in {"failed", "timeout"} for u in record["units"])


def save_pin(path, record):
    if path.exists():
        old = json.loads(path.read_text())
        selected = {u["unit"] for u in record["units"]}
        record["units"].extend(u for u in old.get("units", []) if u["unit"] not in selected)
    write_json(path, record)


def summary(out):
    if not out.is_dir():
        raise ValueError(f"results root does not exist: {out}")
    family, source = defaultdict(Counter), defaultdict(Counter)
    pairs = defaultdict(dict)
    units = {}
    result_files = 0
    for path in sorted(out.glob("*.json")):
        record = json.loads(path.read_text())
        if not record.get("done"):
            continue
        result_files += 1
        for unit in record["units"]:
            if unit["unit"] in units:
                raise ValueError(f"duplicate result for {unit['unit']}")
            units[unit["unit"]] = unit
            family[unit["family"]][unit["status"]] += 1
            source[unit["source"]][unit["status"]] += 1
            if unit["pair"]:
                pairs[unit["family"], unit["pair"]][unit["label"]] = unit["status"]
    asymmetry = Counter()
    completed = Counter()
    for sides in pairs.values():
        if set(sides) != {0, 1}:
            asymmetry["incomplete-pair"] += 1
            continue
        key = {(True, False): "vulnerable-only", (False, True): "fixed-only", (True, True): "both", (False, False): "neither"}[
            sides[1] == "path", sides[0] == "path"
        ]
        asymmetry[key] += 1
        if all(s in {"path", "asked-nothing"} for s in sides.values()):
            completed[key] += 1
    return {
        "result_files_read": result_files,
        "units": len(units),
        "by_family": {k: {s: v[s] for s in STATUSES} for k, v in sorted(family.items())},
        "by_source": {k: {s: v[s] for s in STATUSES} for k, v in sorted(source.items())},
        "pair_asymmetry": dict(asymmetry),
        "pair_asymmetry_both_answered": dict(completed),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=Path, default=ROOT / "plane/experiments/exp-005-graph-slice.units.jsonl")
    parser.add_argument("--examples", type=Path, help="frozen example JSONL instead of the local memory store")
    parser.add_argument("--memory", type=Path, default=Path.home() / "ousast-results/plane/memory")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/openultrasast")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--image", default="openultrasast:dev")
    parser.add_argument("--deadline", type=int, default=900)
    parser.add_argument("--question-deadline", type=int, default=120)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--only-family")
    parser.add_argument("--include-typescript", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    if min(args.deadline, args.question_deadline) <= 0 or args.limit < 0:
        parser.error("deadlines must be positive; limit must be nonnegative")
    if args.summary:
        print(json.dumps(summary(args.out), indent=2))
        return 0
    # Even inherited opt-ins must not make catalog resolution fetch.
    os.environ["GIT_NO_LAZY_FETCH"] = "1"
    os.environ.pop("OPENULTRASAST_PAIRS_NETWORK", None)
    os.environ.pop("OPENULTRASAST_REPOS_NETWORK", None)
    examples = read_jsonl(args.examples) if args.examples else [r.row for r in FileStore(args.memory).rows(kind="example")]
    try:
        units = join_units(read_jsonl(args.units), examples, args.include_typescript)
    except ValueError as exc:
        parser.error(str(exc))
    inputs = Inputs(ROOT, args.cache)
    # Resolve pair source names for leak-audit coverage before calculating the resume key.
    for unit in units:
        if unit["source"] == "pairs":
            try:
                case, _ = inputs.pair_for(unit)
                unit["source"] = case.slice
                unit["excerpt"] = True
            except ValueError as exc:
                unit["mapping_error"] = str(exc)
    plan = make_plan(units, args.out, args.only_family, args.limit, include_typescript=args.include_typescript)
    # Planning is read-only, including unsupported pins. All persistence stays below this return.
    if args.dry_run:
        print(
            json.dumps(
                {
                    "pins": len(plan),
                    "runnable_pins": sum(any(u["supported"] for u in p["units"]) for p in plan),
                    "units": sum(len(p["units"]) for p in plan),
                    "estimated_seconds": sum(p["estimated_seconds"] for p in plan),
                    "estimate_basis": "inventory medians: excerpt 31/47s, repository 182/498s; not a deadline guarantee",
                    "plan": plan,
                },
                indent=2,
            )
        )
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    lock = (args.out / ".lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another trace runner holds this results root")
    failures = False
    if any(u["supported"] for pin in plan for u in pin["units"]):
        image = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", args.image], capture_output=True, text=True, check=True
        )
        args.image = image.stdout.strip()
        if not args.image:
            raise ValueError("Docker returned no local image identity")
    with tempfile.TemporaryDirectory(prefix="trace-source-", dir=args.out) as scratch:
        source = Path(scratch) / "frozen"
        provenance = freeze_source(source)
        for pin in plan:
            if (args.out / "STOP").exists():
                break
            if not any(u["supported"] for u in pin["units"]):
                save_pin(
                    args.out / pin_name(pin),
                    {**pin, "done": True, "units": [unit_record(u, "unsupported", u["reason"]) for u in pin["units"]]},
                )
                continue
            failures |= run_pin(pin, source, provenance, inputs, args.out, args)
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
