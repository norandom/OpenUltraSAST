"""Dispatch three fresh key-free AX tasks for each verification side."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from pathlib import Path

from benchmarks.ax.batch import AXLane, CapacityDeadline, Item, SearchExecutorTask, Workload, validate_image
from openultrasast.search.verify import RunObservation, SideRecord
from openultrasast.search.verify_task import MAX_RESULT_BYTES, pack_checkout


def side_record(value):
    if not isinstance(value, dict) or value.get("isolation_mode") != "task-boundary":
        raise ValueError("missing task-boundary attestation")
    fields = SideRecord.__dataclass_fields__
    # AXLane adds transport metadata outside the task record.
    data = {key: value[key] for key in fields if key in value}
    if data.get("outcome") not in {"observed", "could_not_run", "could_not_build", "no_oracle", "inconclusive"}:
        raise ValueError("invalid side outcome")
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) > 1:
        raise ValueError("task must return one repetition")
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("invalid observation")
        if type(run.get("observed")) is not bool or not isinstance(run.get("evidence"), str):
            raise ValueError("invalid observation")
    if data["outcome"] == "observed" and len(runs) != 1:
        raise ValueError("missing completed observation")
    for number in [
        data.get("elapsed_seconds"),
        *(data.get(k, 0) for k in ("build_seconds", "ready_seconds", "run_seconds", "scratch_peak_bytes")),
        *(run.get("elapsed_seconds") for run in runs),
    ]:
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError("invalid observation measurement")
    if not isinstance(data.get("reason"), str):
        raise ValueError("invalid side reason")
    data["runs"] = tuple(RunObservation(**run) for run in runs)
    return SideRecord(**data)


def validate_result(data, output):
    if len(data) > MAX_RESULT_BYTES:
        raise ValueError("oversized side result")
    side_record(json.loads(data))
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_bytes(data)


class AXSideDispatcher:
    """Host adapter passed as verify(task_dispatcher=...); never caches runs."""

    def __init__(self, args, image, output, *, lane=None, prepare=None):
        validate_image(image)
        self.output = Path(output)
        self.args, self.image, self.lane = args, image, lane
        self.prepare = prepare

    def __call__(self, *, side, demo, family, timeout_seconds, fresh_task):
        if fresh_task is not True or side.command or side.build_command or side.dependencies:
            raise ValueError("verification accepts checkout and declarative inputs only")
        # The trusted host selects an executor for this side. Build/package work
        # finishes there before any verifier worker slot is acquired.
        workload = Workload(self.image, frozenset({"VERIFY_INPUT_URL", "RESULT_URL"}), timeout_seconds * 6 + 60, validate_result, kind="search-verify")
        lane = self.lane or AXLane(self.args, workload)
        spec = {"demo": demo, "family": family, "timeout_seconds": timeout_seconds}
        try:
            if self.prepare is not None:
                archive = self.prepare(side, spec)
            else:
                with SearchExecutorTask(lane, pack_checkout(side.checkout)) as executor:
                    archive = executor.prepare(spec)
        except (ValueError, CapacityDeadline) as exc:
            return SideRecord("could_not_build", (), 0, str(exc), isolation_mode="task-boundary")
        records = []
        for _ in range(3):
            identity = uuid.uuid4().hex
            item = Item(
                identity,
                {"VERIFY_INPUT_URL": archive},
                "result.json",
                ("python3", "-m", "openultrasast.search.verify_task"),
                {},
                hashlib.sha256(archive).hexdigest(),
            )
            output = self.output / identity
            output.mkdir(parents=True)
            raw = lane(item, output, 1)
            # Roundtrip enforces JSON types for test adapters as for remote tasks.
            if raw.get("status") == "capacity_timeout":
                return SideRecord("could_not_run", (), 0, "AX capacity deadline", isolation_mode="task-boundary")
            result = side_record(json.loads(json.dumps(raw)))
            records.append(result)
            if result.outcome != "observed":
                break
        last = records[-1]
        return SideRecord(
            last.outcome,
            tuple(run for r in records for run in r.runs),
            sum(r.elapsed_seconds for r in records),
            last.reason,
            sum(r.build_seconds for r in records),
            sum(r.ready_seconds for r in records),
            sum(r.run_seconds for r in records),
            max(r.scratch_peak_bytes for r in records),
            isolation_mode="task-boundary",
            chromium_no_sandbox=any(r.chromium_no_sandbox for r in records),
            phase=last.phase,
            exit_code=last.exit_code,
            stderr=last.stderr,
        )
