"""Container-only Joern trace worker; host prepares all corpus and question metadata.

Keep this module independent of learn/plane and their optional dependencies. The
frozen host invokes this file directly in the shipped, offline analyzer image.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.trace import parse_trace


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


FRONTENDS = {"php2cpg", "pysrc2cpg", "jssrc2cpg", "javasrc2cpg", "c2cpg", "joern-parse"}
MIN_CPG_BYTES = 1024
HEAP_MB = 2560
EXCLUDED_DIRS = frozenset({"tests", "test", "docs", "node_modules", "vendor", "dist", "build", "templates", "migrations"})


def instrument_failure(proof):
    if any(stage.get("oom") for stage in proof.get("jvm", [])):
        return "JVM out of memory"
    if not proof.get("files") or not proof.get("bytes"):
        return "instrument read zero files or zero bytes"
    if proof.get("cpg_bytes", 0) <= MIN_CPG_BYTES:
        return "frontend wrote no CPG"
    for stage in proof.get("jvm", []):
        if stage["command"] in FRONTENDS:
            if stage.get("cpg_bytes", 0) <= MIN_CPG_BYTES:
                return "frontend wrote no CPG"
        elif stage["command"] == "joern" and stage["seconds"] < 5:
            return f"implausibly fast JVM step: {stage['command']} in {stage['seconds']:.3f}s (<5s)"
    if not proof.get("jvm"):
        return "no JVM step recorded"
    return ""


class MeasuredBackend(JoernBackend):
    """Use the shipped backend with a process watchdog, no concurrent query threads."""

    def __init__(self, deadline, question_deadline, checkpoint):
        super().__init__(build_timeout=deadline, query_timeout=deadline, session_transport=False, heap_mb=HEAP_MB)
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
        binary = Path(command[0]).name
        frontend = binary in FRONTENDS
        query = binary == "joern" and "--script" in command
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
        if frontend or query:
            stage = {
                "command": binary,
                "argv": command,
                "heap_mb": self._heap_mb(),
                "java_tool_options": self._jvm_env()["JAVA_TOOL_OPTIONS"],
                "seconds": elapsed,
                "exit": process.returncode,
                "oom": b"OutOfMemoryError" in output,
            }
            self.stages.append(stage)
            if frontend:
                # Capture the exact frontend output before build failure cleanup or overlays.
                output_arg = next((i + 1 for i, arg in enumerate(command[:-1]) if arg in {"-o", "--output"}), None)
                cpg_path = (Path(cwd or Path.cwd()) / command[output_arg]).resolve() if output_arg is not None else None
                stage["cpg_path"] = str(cpg_path) if cpg_path is not None else None
                stage["cpg_bytes"] = cpg_path.stat().st_size if cpg_path is not None and cpg_path.is_file() else 0
                if stage["cpg_bytes"] <= MIN_CPG_BYTES:
                    self.fatal = "frontend wrote no CPG"
            elif elapsed < 5:
                self.fatal = f"implausibly fast JVM step: {command[0]} in {elapsed:.3f}s (<5s)"
        if b"OutOfMemoryError" in output:
            self.fatal = "JVM out of memory"
        self.checkpoint()
        return subprocess.CompletedProcess(command, process.returncode if not self.fatal else 1, output.decode(errors="replace"), "")


def unit_record(unit, status, reason="", **extra):
    return {
        **unit,
        "status": status,
        "reason": reason,
        "witness_rows": [],
        "traces": [],
        "instrument": {"files": [], "bytes": 0, "cpg_path": None, "cpg_bytes": 0, "jvm": []},
        "questions": {},
        "questions_asked": [],
        "questions_completed": [],
        **extra,
    }


def worker_language(pin, root, out, deadline, question_deadline, persist=write_json):
    proof = {
        "files": [],
        "bytes": 0,
        "cpg_path": None,
        "cpg_bytes": 0,
        "jvm": [],
        "heap_mb": HEAP_MB,
        "excludes": sorted(EXCLUDED_DIRS),
        "materialization": pin.get("materialization", {}),
    }
    record = {
        **pin,
        "done": False,
        "instrument": proof,
        "units": [unit_record(u, "unsupported" if not u["supported"] else "timeout", u["reason"]) for u in pin["units"]],
    }

    def checkpoint():
        # Checkpoints retain raw completed rows even if the outer container deadline fires.
        # They remain timeout until the finished JVM's instrument proof is validated.
        for stage in backend.stages:
            if "cpg_path" in stage:
                proof["cpg_path"] = stage["cpg_path"]
                proof["cpg_bytes"] = stage["cpg_bytes"]
        for row in record["units"]:
            rid = row["unit"]
            row["instrument"] = proof
            row["questions_asked"] = [rid] if rid in backend.asked else []
            if rid in backend.answers:
                row["questions_completed"] = [rid]
                row["witness_rows"] = [r for r in backend.answers[rid] if isinstance(r, dict) and "kind" not in r and "sink" in r]
        persist(out, record)

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
        requests = pin["questions"]
        if set(requests) != {u["unit"] for u in active}:
            raise ValueError("prepared questions do not match supported units")
        record["questions"] = requests
        for unit_row in record["units"]:
            unit_row["questions"] = {unit_row["unit"]: requests[unit_row["unit"]]} if unit_row["unit"] in requests else {}
        persist(out, record)
        cpg = backend.build(root, language=language)
        if cpg is None:
            raise ValueError(backend.fatal or backend.last_failure or ("pin deadline" if backend.timed_out else "CPG build failed"))
        if proof["cpg_path"] is None:
            proof["cpg_path"] = str(cpg.cpg_path)
            proof["cpg_bytes"] = cpg.cpg_path.stat().st_size if cpg.cpg_path.is_file() else 0
        failure = instrument_failure(proof)
        if failure:
            raise ValueError(failure)
        if cpg.run_batch_once is None:
            raise ValueError("backend offers no batch operation")
        answers = cpg.run_batch_once("taint", requests) or {}
        record["census"] = answers.get("__census__", [])
        failure = backend.fatal or instrument_failure(proof)
        if not backend.asked and not backend.timed_out:
            failure = failure or "query produced no markers"
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
            elif not rows and rid not in backend.asked:
                status, reason = "failed", "query produced no markers"
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
        persist(out, record)
    return record


def worker(pin, root, out, deadline, question_deadline):
    """Run language partitions sequentially under one shared container deadline."""
    languages = sorted({"javascript" if u["language"] == "typescript" else u["language"] for u in pin["units"] if u["supported"]})
    if len(languages) <= 1:
        return worker_language(pin, root, out, deadline, question_deadline)
    end = time.monotonic() + deadline
    record = {
        **pin,
        "done": False,
        "units": [
            unit_record(u, "timeout" if u["supported"] else "unsupported", "pin deadline" if u["supported"] else u["reason"])
            for u in pin["units"]
        ],
        "instruments": {},
    }

    def persist(_, partial):
        updates = {u["unit"]: u for u in partial["units"]}
        record["units"] = [updates.get(u["unit"], u) for u in record["units"]]
        record["instruments"][language] = partial["instrument"]
        record["questions_asked"] = [rid for u in record["units"] for rid in u["questions_asked"]]
        record["questions_completed"] = [rid for u in record["units"] for rid in u["questions_completed"]]
        write_json(out, record)

    write_json(out, record)
    for language in languages:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        units = [
            u for u in pin["units"] if u["supported"] and ("javascript" if u["language"] == "typescript" else u["language"]) == language
        ]
        questions = {u["unit"]: pin["questions"][u["unit"]] for u in units}
        worker_language({**pin, "units": units, "questions": questions}, root, out, remaining, question_deadline, persist)
    record["done"] = True
    write_json(out, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--deadline", type=int, default=900)
    parser.add_argument("--question-deadline", type=int, default=120)
    args = parser.parse_args()
    if min(args.deadline, args.question_deadline) <= 0:
        parser.error("deadlines must be positive")
    worker(json.loads(args.worker.read_text()), Path("/case"), Path("/out/result.json"), args.deadline, args.question_deadline)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
