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
import tempfile
import time
from collections import Counter
from pathlib import Path

from engine_trace_parse import parse_trace

from openultrasast.cpg.backend import DATAFLOW_OVERLAY, JoernBackend, _render, extract_payload
from openultrasast.cpg.session import EngineSession
from openultrasast.model.contracts import ExecutionBudget


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
CLUSTER_JVM_FLAGS = (
    "-Xms1700m -Xmx1700m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m "
    "-XX:MaxDirectMemorySize=256m -Xss512k -XX:ActiveProcessorCount=2 -XX:+UseG1GC"
)
ENGINE_BUG = "engine bug: jssrc2cpg ObjectPropertyCallLinker"
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
        elif (
            stage["command"] == "joern" or (stage["command"] == "joern-session" and stage.get("step") == "start" and stage.get("success"))
        ) and stage["seconds"] < 5:
            return f"implausibly fast JVM step: {stage['command']} in {stage['seconds']:.3f}s (<5s)"
    if not proof.get("jvm"):
        return "no JVM step recorded"
    return ""


class MeasuredBackend(JoernBackend):
    """Use the shipped backend with process and resident-session watchdogs."""

    def __init__(self, deadline, question_deadline, checkpoint, heap_profile="vm"):
        if heap_profile not in {"vm", "cluster"}:
            raise ValueError(f"unknown heap profile: {heap_profile}")
        self.heap_profile = heap_profile
        super().__init__(
            build_timeout=deadline,
            query_timeout=deadline,
            session_transport=False,
            heap_mb=1700 if heap_profile == "cluster" else HEAP_MB,
        )
        self.deadline = time.monotonic() + deadline
        self.question_deadline = question_deadline
        self.checkpoint = checkpoint
        self.stages = []
        self.asked = []
        self.answers = {}
        self.completion_counts = Counter()
        self.timed_out = False
        self.fatal = ""
        self.labelled_files = []
        self.retry_pending = False
        self.retries = []
        self.session_fallback = ""

    def _jvm_env(self):
        env = super()._jvm_env()
        if self.heap_profile == "cluster":
            # Bound every JVM, including the child spawned by the Joern launcher.
            env["JAVA_TOOL_OPTIONS"] = CLUSTER_JVM_FLAGS
            env.pop("_JAVA_OPTIONS", None)
            env.pop("JDK_JAVA_OPTIONS", None)
        return env

    def _session_stage(self, name, action):
        started = time.monotonic()
        result = None
        try:
            result = action()
            return result
        finally:
            self.stages.append(
                {
                    "command": "joern-session",
                    "step": name,
                    "success": result is not None and result is not False,
                    "seconds": time.monotonic() - started,
                    "heap_mb": self._heap_mb(),
                    "java_tool_options": self._jvm_env()["JAVA_TOOL_OPTIONS"],
                }
            )
            self.checkpoint()

    def _fallback_session(self, reason):
        self.session_fallback = reason
        if self._session is not None:
            detail = self._session.log_tail()
            if "OutOfMemoryError" in detail:
                self.fatal = "JVM out of memory"
                self.stages[-1]["oom"] = True
            self.stages[-1]["output_tail"] = detail
        self.close_session()
        self.checkpoint()

    def _session_for(self, cpg_path):
        if self.session_fallback or self.fatal or self.timed_out:
            return None
        try:
            if self._session is None:
                self._session = EngineSession(
                    cpg_path.parent / "engine-session",
                    ExecutionBudget(self.deadline, 5),
                    self._jvm_env(),
                    startup_allowance_seconds=min(180, max(20, (self.deadline - time.monotonic()) / 3)),
                )
                if not self._session_stage("start", self._session.start):
                    self._fallback_session(self._session.failure or "session_start_failed")
                    return None
            if self._session.loaded_graph != str(cpg_path):
                if not self._session_stage("load", lambda: self._session.load(cpg_path, timeout=self.query_timeout)):
                    self._fallback_session(self._session.failure or "session_load_failed")
                    return None
                self._defined.clear()
            return self._session
        except (OSError, RuntimeError) as exc:
            self._fallback_session(f"session_start_or_load:{exc}")
            return None

    def _session_payload(self, cpg_path, query, params):
        session = self._session_for(cpg_path)
        if session is None:
            return None
        end = min(self.deadline, time.monotonic() + self.query_timeout)
        question_end = end
        prior_asked = list(self.asked)
        prior_answers = dict(self.answers)
        prior_counts = self.completion_counts.copy()
        consumed = 0
        streamed = ""

        def observe(output):
            nonlocal consumed, question_end, streamed
            streamed = output
            lines = output[consumed:].splitlines(keepends=True)
            for line in lines:
                if not line.endswith("\n"):
                    break
                consumed += len(line)
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
            if time.monotonic() >= min(end, question_end):
                self.timed_out = True
                return False
            return True

        def run():
            source = (self.queries_dir / f"{query}.sc").read_text()
            # Same shipped script/parameters as JoernBackend, using the graph loaded above.
            if source.count("importCpg(cpgFile)") != 1:
                return None
            symbol = f"ousast_{query}"
            if query not in self._defined:
                source = source.replace("importCpg(cpgFile)", "()", 1)
                source = source.replace("@main def exec(", f"def {symbol}(", 1)
                if session.define(source, timeout=max(0, end - time.monotonic())) is None:
                    return None
                self._defined.add(query)
            arguments = ", ".join(f"{name} = {json.dumps(_render(value))}" for name, value in sorted(params.items()))
            session.output_observer = observe
            try:
                answer = session.evaluate(f"{symbol}({arguments})", timeout=max(0, end - time.monotonic()))
            finally:
                session.output_observer = None
            if answer is not None:
                observe(answer.stdout)
                return answer.stdout
            return None

        failure = ""
        try:
            body = self._session_stage(query, run)
        except (OSError, RuntimeError) as exc:
            body = None
            failure = f"session_{query}:{exc}"
        if self.timed_out:
            self.close_session()
            return streamed
        parsed = extract_payload(body) if body is not None else None
        if not isinstance(parsed, dict):
            # Discard markers from an unverified attempt before replaying the script.
            self.asked[:] = prior_asked
            self.answers = prior_answers
            self.completion_counts = prior_counts
            self._fallback_session(failure or session.failure or f"session_{query}_payload_missing")
            return None
        if query == "census":
            self.stages[-1]["files"] = int(parsed.get("files", 0))
            if self.stages[-1]["files"] <= 0:
                self.fatal = "query census read zero files"
        return body

    def _apply_overlays(self, cpg_path, scratch):
        session = self._session_for(cpg_path)
        result = False
        if session is not None:
            body = self._session_payload(cpg_path, "overlay", {"cpgFile": str(cpg_path)})
            saved = session.scratch / "workspace" / cpg_path.name / "cpg.bin"
            if body is not None and saved.is_file():
                import shutil

                shutil.copyfile(saved, cpg_path)
                result = True
            elif body is not None:
                self._fallback_session("session_overlay_saved_graph_missing")
        if not result:
            result = super()._apply_overlays(cpg_path, scratch)
        # An optional overlay failure must not prevent the taint-only attempt.
        if self.fatal == ENGINE_BUG and not self.timed_out:
            self.retry_pending = True
            self.fatal = ""
        return result

    def _batch_once(self, cpg_path, query, requests):
        if self.fatal or self.timed_out:
            return None
        if not self.retry_pending:
            answers = super()._batch_once(cpg_path, query, requests)
            if self.fatal != ENGINE_BUG:
                return answers
        if query != "taint" or self.timed_out or self.retries:
            self.fatal = ENGINE_BUG
            return None
        self.retry_pending = False
        self.fatal = ""
        retry = {"reason": ENGINE_BUG, "mode": "taint-only", "completed": False}
        self.retries.append(retry)
        # Do not reuse rows/markers from the failed attempt as completion evidence.
        self.asked.clear()
        self.answers.clear()
        self.completion_counts.clear()
        original = self.queries_dir
        with tempfile.TemporaryDirectory(prefix="trace-taint-", dir=cpg_path.parent) as scratch:
            script = (original / "taint.sc").read_text()
            marker = "importCpg(cpgFile)"
            if script.count(marker) != 1:
                self.fatal = ENGINE_BUG
                return None
            # Loading without enhancement skips the failing JS postprocessing passes.
            # A raw graph without dataflow cannot establish a negative answer.
            script = script.replace(
                marker,
                "importCpg(cpgFile, enhance = false)\n"
                f'  require(cpg.metaData.overlays.l.contains("{DATAFLOW_OVERLAY}"), '
                '"taint-only retry requires saved dataflowOss overlay")',
            )
            self.queries_dir = Path(scratch)
            (self.queries_dir / "taint.sc").write_text(script)
            try:
                answers = super()._batch_once(cpg_path, query, requests)
            finally:
                self.queries_dir = original
        retry["completed"] = answers is not None and not self.fatal and not self.timed_out
        if not retry["completed"]:
            self.fatal = ENGINE_BUG
        return answers

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
            lines = output.decode(errors="replace").splitlines()
            stage["labelled_file_logs"] = {
                file: [line for line in lines if file in line or Path(file).name in line]
                for file in self.labelled_files
                if any(file in line or Path(file).name in line for line in lines)
            }
            self.stages.append(stage)
            if query and process.returncode != 0:
                # stderr is merged into stdout above; drop JVM frames before taking
                # the tail so they cannot crowd out the exception's message.
                lines = [
                    line.strip()
                    for line in output.decode(errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith(("at ", "... "))
                ]
                stage["output_tail"] = "\n".join(lines[-20:])
                if not self.timed_out:
                    self.fatal = f"joern query exited {process.returncode}"
            if frontend:
                # Capture the exact frontend output before build failure cleanup or overlays.
                output_arg = next((i + 1 for i, arg in enumerate(command[:-1]) if arg in {"-o", "--output"}), None)
                cpg_path = (Path(cwd or Path.cwd()) / command[output_arg]).resolve() if output_arg is not None else None
                stage["cpg_path"] = str(cpg_path) if cpg_path is not None else None
                stage["cpg_bytes"] = cpg_path.stat().st_size if cpg_path is not None and cpg_path.is_file() else 0
                if stage["cpg_bytes"] <= MIN_CPG_BYTES:
                    self.fatal = "frontend wrote no CPG"
            elif elapsed < 5 and not self.fatal:
                self.fatal = f"implausibly fast JVM step: {command[0]} in {elapsed:.3f}s (<5s)"
        if b"ObjectPropertyCallLinker failed" in output and b"Assignment statement with 3 arguments" in output:
            self.fatal = ENGINE_BUG
            stage["engine_bug"] = ENGINE_BUG
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


def worker_language(pin, root, out, deadline, question_deadline, persist=write_json, heap_profile="vm"):
    proof = {
        "files": [],
        "bytes": 0,
        "cpg_path": None,
        "cpg_bytes": 0,
        "jvm": [],
        "heap_mb": 1700 if heap_profile == "cluster" else HEAP_MB,
        "heap_profile": heap_profile,
        "java_tool_options": CLUSTER_JVM_FLAGS
        if heap_profile == "cluster"
        else f"{os.environ.get('JAVA_TOOL_OPTIONS', '').strip()} -Xmx{HEAP_MB}m".strip(),
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
        if getattr(backend, "session_fallback", ""):
            proof["session_fallback"] = backend.session_fallback
        for row in record["units"]:
            rid = row["unit"]
            row["instrument"] = proof
            row["questions_asked"] = [rid] if rid in backend.asked else []
            if rid in backend.answers:
                row["questions_completed"] = [rid]
                row["witness_rows"] = [r for r in backend.answers[rid] if isinstance(r, dict) and "kind" not in r and "sink" in r]
        persist(out, record)

    backend = MeasuredBackend(deadline, question_deadline, checkpoint, **({"heap_profile": heap_profile} if heap_profile != "vm" else {}))
    proof["jvm"] = backend.stages
    proof["retries"] = getattr(backend, "retries", [])
    backend.labelled_files = sorted({u["file"] for u in pin["units"] if u["supported"]})
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
        requests = {rid: {key: _render(value) for key, value in params.items()} for rid, params in pin["questions"].items()}
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
            names = census[0].get("file_names", []) if census else []
            file_missing = not any(str(p).removeprefix("./") == unit["file"] or str(p).endswith("/" + unit["file"]) for p in names)
            dropped = file_missing and rows is not None
            if failure or dropped:
                status, reason = "failed", failure or "labelled file was dropped or absent from query census"
                if dropped:
                    logs = [line for stage in backend.stages for line in stage.get("labelled_file_logs", {}).get(unit["file"], [])]
                    reason += "\n" + ("\n".join(dict.fromkeys(logs)) if logs else "frontend emitted no log lines mentioning labelled file")
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
        if hasattr(backend, "close_session"):
            backend.close_session()
        if cpg and cpg.cleanup:
            cpg.cleanup()
        for stage in backend.stages:
            if stage["command"] == "joern" and stage.get("exit") and "output_tail" in stage:
                detail = f"joern query exited {stage['exit']}: {stage['output_tail'] or 'no output'}"
                for row in record["units"]:
                    if row["supported"] and row["status"] in {"failed", "timeout"}:
                        row["reason"] = f"{row['reason']}\n{detail}".strip()
        record["questions_asked"] = list(dict.fromkeys(backend.asked))
        record["questions_completed"] = [rid for u in record["units"] for rid in u["questions_completed"]]
        record["done"] = True
        persist(out, record)
    return record


def worker(pin, root, out, deadline, question_deadline, heap_profile="vm"):
    """Run language partitions sequentially under one shared container deadline."""
    languages = sorted({"javascript" if u["language"] == "typescript" else u["language"] for u in pin["units"] if u["supported"]})
    if len(languages) <= 1:
        return worker_language(pin, root, out, deadline, question_deadline, heap_profile=heap_profile)
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
        worker_language(
            {**pin, "units": units, "questions": questions}, root, out, remaining, question_deadline, persist, heap_profile=heap_profile
        )
    record["done"] = True
    write_json(out, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--deadline", type=int, default=900)
    parser.add_argument("--question-deadline", type=int, default=120)
    parser.add_argument("--heap-profile", choices=("cluster", "vm"), default="vm")
    parser.add_argument("--root", type=Path, default=Path("/case"))
    parser.add_argument("--output", type=Path, default=Path("/out/result.json"))
    args = parser.parse_args()
    if min(args.deadline, args.question_deadline) <= 0:
        parser.error("deadlines must be positive")
    worker(json.loads(args.worker.read_text()), args.root, args.output, args.deadline, args.question_deadline, args.heap_profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
