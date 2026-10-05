"""Engine workload adapter for the shared AX transport."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from engine_trace_k8s import pack

from benchmarks.ax.batch import AXLane, Item, SandboxFailure, Workload, manifest
from benchmarks.ax.batch import task_state as task_state
from openultrasast.plane.memory import open_store as open_store


def task_manifest(name, args, urls):
    return manifest(
        name, engine_workload(args, lambda *_: None), engine_item({}, "pin", b"", args), urls, args.atespace, validate_name=False
    )


def engine_workload(args, validate):
    return Workload(args.image, frozenset({"SOURCE_URL", "QUESTIONS_URL", "RESULT_URL"}), args.deadline, validate, kind="pass")


def engine_item(pin, pin_id, source, args):
    return Item(
        pin_id,
        {"SOURCE_URL": source, "QUESTIONS_URL": json.dumps(pin).encode()},
        "result.dat",
        ("python3", "/app/benchmarks/learn/engine_task_entry.py"),
        {"DEADLINE": str(args.deadline), "QUESTION_DEADLINE": str(args.question_deadline)},
        "",
        {"SOURCE_URL": "source.dat", "QUESTIONS_URL": "questions.json"},
    )


class AX(AXLane):
    def __init__(self, args, store=None, pause=time.sleep, clock=time.monotonic):
        super().__init__(args, engine_workload(args, lambda *_: None), store, pause, clock)

    def receive(self, data, output, pin):
        # Validate in isolation: malformed results must never become usable checkpoints.
        with tempfile.TemporaryDirectory(prefix="engine-ax-result-") as temporary:
            root = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.extractall(root, filter="data")
            record = json.loads((root / "result.json").read_text())
            units = record.get("units", [])
            if record.get("done") and record.get("status") == "failed" and not units:
                # Questions download can fail before the actor learns any unit identities.
                # Keep that explicit failure, filling identities only from the host input.
                record = {
                    **pin,
                    **record,
                    "units": [
                        {
                            **unit,
                            "status": "failed" if unit["supported"] else "unsupported",
                            "reason": record.get("reason", "AX task entry failed"),
                            "instrument": {"files": [], "bytes": 0, "cpg_path": None, "cpg_bytes": 0, "jvm": []},
                            "questions": {},
                            "questions_asked": [],
                            "questions_completed": [],
                            "witness_rows": [],
                            "traces": [],
                        }
                        for unit in pin["units"]
                    ],
                }
                units = record["units"]
                (root / "result.json").write_text(json.dumps(record))
            expected = [u["unit"] for u in pin["units"]]
            actual = [u["unit"] for u in units]
            if not record.get("done") or sorted(actual) != sorted(expected):
                raise ValueError("AX Task returned incomplete or mismatched units")
            output.mkdir(parents=True, exist_ok=True)
            # Keep the artifacts without interpreting any remote paths as host destinations.
            shutil.copytree(root, output, dirs_exist_ok=True)

    def execute(self, checkout, output, pin, pin_id):
        import copy

        self = copy.copy(self)
        self.workload = engine_workload(self.args, lambda data, target: self.receive(data, target, pin))
        attempts = []
        try:
            for attempt in range(2):
                try:
                    return self._execute_attempt(engine_item(pin, pin_id, pack(checkout), self.args), output, attempt, attempts)
                except SandboxFailure:
                    if attempt == 0:
                        self.pause(10)
            return subprocess.CompletedProcess([], 1, "", "AX sandbox failed twice"), None
        finally:
            (output / "ax_attempts.json").write_text(json.dumps(attempts))
            result_path = output / "result.json"
            if result_path.exists():
                record = json.loads(result_path.read_text())
                record["ax_attempts"] = attempts
                result_path.write_text(json.dumps(record))
