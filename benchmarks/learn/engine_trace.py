"""Resumable, serial, labelled-function Joern traces. No network or live-source mounts.

Pair pins are excerpt blob identities, NOT commits: materialize their catalog side
and registration documents. Repository pins are exported from existing local clones.
The analyzer is git archive HEAD src plus a hashed snapshot of this uncommitted tool's
four implementation files; this allows review/worktree use without making a commit.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.learn.examples import read_jsonl
from openultrasast.learn.labels import load_sources, repo_name
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params
from openultrasast.model.trace import parse_trace
from openultrasast.pairs import _materialize_side, load_pair_catalog
from openultrasast.plane.engine_alerts import export_pin
from openultrasast.plane.memory import FileStore
from openultrasast.plane.tasks.alerts import engine_languages
from openultrasast.preprocess import detect_language

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = Path.home() / "ousast-results/plane/engine-trace"
SNAPSHOT_FILES = (
    "benchmarks/learn/engine_trace.py",
    "src/openultrasast/model/trace.py",
    "src/openultrasast/model/taint.py",
    "src/openultrasast/cpg/queries/taint.sc",
)
STATUSES = ("path", "asked-nothing", "failed", "timeout", "unsupported")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def pin_name(pin):
    return digest([pin["repo"], pin["pin"]]) + ".json"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def safe_path(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"path escapes input root: {name}")
    return path


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


def make_plan(units, out, only_family=None, limit=0):
    grouped = defaultdict(list)
    for unit in units:
        if not only_family or unit["family"] == only_family:
            grouped[unit["repo"], unit["pin"]].append({**unit, "input_digest": digest(unit)})
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


def instrument_failure(proof):
    if not proof.get("files") or not proof.get("bytes"):
        return "instrument read zero files or zero bytes"
    if not proof.get("cpg_bytes"):
        return "instrument produced no CPG bytes"
    for stage in proof.get("jvm", []):
        if stage["seconds"] < 5:
            return f"implausibly fast JVM step: {stage['command']} in {stage['seconds']:.3f}s (<5s)"
    if not proof.get("jvm"):
        return "no JVM step recorded"
    return ""


class MeasuredBackend(JoernBackend):
    """Use the shipped backend with a process watchdog, no concurrent query threads."""

    def __init__(self, deadline, question_deadline, checkpoint):
        super().__init__(build_timeout=deadline, query_timeout=deadline, session_transport=False)
        self.deadline = time.monotonic() + deadline
        self.question_deadline = question_deadline
        self.checkpoint = checkpoint
        self.stages = []
        self.asked = []
        self.answers = {}
        self.completion_counts = Counter()
        self.timed_out = False
        self.fatal = ""

    def _run(self, command, *, timeout, cwd=None):
        if self.fatal or self.timed_out:
            return None
        if time.monotonic() >= self.deadline:
            self.timed_out = True
            return None
        started = time.monotonic()
        end = min(self.deadline, started + timeout)
        question_end = end
        jvm = Path(command[0]).name != "php"
        output = bytearray()
        pending = b""
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, env=self._jvm_env(), start_new_session=True
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= min(end, question_end):
                        self.timed_out = True
                        break
                    for key, _ in selector.select(min(0.2, max(0, min(end, question_end) - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output.extend(chunk)
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            try:
                                event = json.loads(line)
                            except ValueError:
                                continue
                            if not isinstance(event, dict):
                                continue
                            if "__question__" in event:
                                self.asked.append(event["__question__"])
                                question_end = min(end, time.monotonic() + self.question_deadline)
                            if "id" in event and "rows" in event:
                                self.answers[event["id"]] = event["rows"]
                                self.completion_counts[event["id"]] += 1
                                question_end = end
                            self.checkpoint()
            if not self.timed_out:
                process.wait(timeout=max(0.01, end - time.monotonic()))
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            process.stdout.close()
        elapsed = time.monotonic() - started
        if jvm:
            self.stages.append({"command": Path(command[0]).name, "seconds": elapsed, "exit": process.returncode})
            if elapsed < 5:
                self.fatal = f"implausibly fast JVM step: {command[0]} in {elapsed:.3f}s (<5s)"
        self.checkpoint()
        return subprocess.CompletedProcess(command, process.returncode if not self.fatal else 1, output.decode(errors="replace"), "")


def unit_record(unit, status, reason="", **extra):
    return {
        **unit,
        "status": status,
        "reason": reason,
        "witness_rows": [],
        "traces": [],
        "instrument": {"files": [], "bytes": 0, "cpg_bytes": 0, "jvm": []},
        "questions": {},
        "questions_asked": [],
        "questions_completed": [],
        **extra,
    }


def worker(pin, root, out, deadline, question_deadline):
    proof = {"files": [], "bytes": 0, "cpg_bytes": 0, "jvm": []}
    record = {
        **pin,
        "done": False,
        "instrument": proof,
        "units": [unit_record(u, "unsupported" if not u["supported"] else "timeout", u["reason"]) for u in pin["units"]],
    }

    def checkpoint():
        # Checkpoints retain raw completed rows even if the outer container deadline fires.
        # They remain timeout until the finished JVM's instrument proof is validated.
        for row in record["units"]:
            rid = row["unit"]
            row["instrument"] = proof
            row["questions_asked"] = [rid] if rid in backend.asked else []
            if rid in backend.answers:
                row["questions_completed"] = [rid]
                row["witness_rows"] = [r for r in backend.answers[rid] if isinstance(r, dict) and "kind" not in r and "sink" in r]
        write_json(out, record)

    backend = MeasuredBackend(deadline, question_deadline, checkpoint)
    proof["jvm"] = backend.stages
    cpg = None
    try:
        active = [u for u in pin["units"] if u["supported"]]
        for file in sorted({u["file"] for u in active}):
            data = safe_path(root, file).read_bytes()
            proof["files"].append({"file": file, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            proof["bytes"] += len(data)
            print(f"read {file}: {len(data)} bytes", flush=True)
        if not proof["bytes"]:
            raise ValueError("instrument read zero files or zero bytes")
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
        specs = taint_specs(language="javascript" if language == "typescript" else language)
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
        record["questions"] = requests
        for unit_row in record["units"]:
            unit_row["questions"] = {unit_row["unit"]: requests[unit_row["unit"]]} if unit_row["unit"] in requests else {}
        write_json(out, record)
        cpg = backend.build(root, language=language)
        if cpg is None:
            raise ValueError(backend.fatal or backend.last_failure or ("pin deadline" if backend.timed_out else "CPG build failed"))
        proof["cpg_bytes"] = sum(p.stat().st_size for p in cpg.cpg_path.parent.rglob("*.bin"))
        failure = instrument_failure(proof)
        if failure:
            raise ValueError(failure)
        if cpg.run_batch_once is None:
            raise ValueError("backend offers no batch operation")
        answers = cpg.run_batch_once("taint", requests) or {}
        record["census"] = answers.get("__census__", [])
        failure = backend.fatal or instrument_failure(proof)
        census = record["census"]
        if census and int(census[0].get("files", 0)) <= 0:
            failure = failure or "query census read zero files"
        elif not census and not backend.timed_out:
            failure = failure or "query census is missing"
        for index, unit in enumerate(pin["units"]):
            if not unit["supported"]:
                continue
            rid = unit["unit"]
            extra = {
                "questions": {rid: requests[rid]},
                "questions_asked": [rid] if rid in backend.asked else [],
                "questions_completed": [rid] if rid in answers else [],
                "instrument": proof,
            }
            rows = answers.get(rid)
            # A batch across backend shards is complete only when every shard answered.
            # The legacy merger can return a union even when one shard was killed.
            shards = int(census[0].get("shards", 1)) if census else 1
            shard_incomplete = shards > 1 and getattr(backend, "completion_counts", {}).get(rid, 0) < shards
            if rows is not None:
                raw_flows = [r for r in rows if isinstance(r, dict) and "kind" not in r and "sink" in r]
                extra.update(witness_rows=raw_flows, traces=[parse_trace(r) for r in raw_flows])
            if shard_incomplete:
                extra["questions_completed"] = []
            dropped = any(p.endswith(unit["file"]) for p in cpg.unparsed)
            names = census[0].get("file_names", []) if census else []
            file_missing = not any(str(p).removeprefix("./") == unit["file"] or str(p).endswith("/" + unit["file"]) for p in names)
            if file_missing and rows is not None:
                dropped = True
            if failure or dropped:
                status, reason = "failed", failure or "labelled file was dropped or absent from query census"
            elif rows is None or shard_incomplete:
                status, reason = ("timeout" if backend.timed_out else "failed"), "question did not complete"
            else:
                flows = [r for r in rows if isinstance(r, dict) and "kind" not in r and "sink" in r]
                if any(not row.get("trace") for row in flows):
                    raise ValueError("taint witness returned without requested trace")
                extra.update(witness_rows=flows, traces=[parse_trace(r) for r in flows])
                status, reason = ("path" if flows else "asked-nothing"), ""
            record["units"][index] = unit_record(unit, status, reason, **extra)
    except (OSError, ValueError, RuntimeError) as exc:
        for index, unit in enumerate(pin["units"]):
            if unit["supported"]:
                record["units"][index] = unit_record(
                    unit,
                    "timeout" if backend.timed_out and not backend.fatal else "failed",
                    str(exc),
                    instrument=proof,
                    questions={unit["unit"]: record["questions"][unit["unit"]]} if unit["unit"] in record.get("questions", {}) else {},
                    witness_rows=[r for r in backend.answers.get(unit["unit"], []) if isinstance(r, dict) and "sink" in r],
                    questions_completed=[unit["unit"]] if unit["unit"] in backend.answers else [],
                    questions_asked=[unit["unit"]] if unit["unit"] in backend.asked else [],
                )
    finally:
        if cpg and cpg.cleanup:
            cpg.cleanup()
        record["questions_asked"] = list(dict.fromkeys(backend.asked))
        record["questions_completed"] = [rid for u in record["units"] for rid in u["questions_completed"]]
        record["done"] = True
        write_json(out, record)
    return record


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
        "/frozen/benchmarks/learn/engine_trace.py",
        "--worker",
        "/out/pin.json",
        "--deadline",
        str(deadline),
        "--question-deadline",
        str(question_deadline),
    ]


def run_pin(pin, source, provenance, inputs, out, args):
    with tempfile.TemporaryDirectory(prefix="trace-pin-", dir=out) as scratch:
        scratch = Path(scratch)
        checkout, output = scratch / "case", scratch / "output"
        output.mkdir()
        try:
            inputs.materialize(pin, checkout)
            write_json(output / "pin.json", pin)
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
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.deadline, args.question_deadline) <= 0 or args.limit < 0:
        parser.error("deadlines must be positive; limit must be nonnegative")
    if args.worker:
        worker(json.loads(args.worker.read_text()), Path("/case"), Path("/out/result.json"), args.deadline, args.question_deadline)
        return 0
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
    plan = make_plan(units, args.out, args.only_family, args.limit)
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
