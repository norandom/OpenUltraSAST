"""Compact presentation and complete artifacts for an already-decided push."""

from __future__ import annotations

import json
import math
import multiprocessing
import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from openultrasast.model.contracts import ChangeContext, ExecutionBudget
from openultrasast.model.scan import ModelScanResult
from openultrasast.push.contracts import PushComparison, PushResolution, PushResult, SnapshotManifest
from openultrasast.push.policy import AdmissionResult, _context_boundaries
from openultrasast.redaction import redact_secrets


@dataclass(frozen=True)
class ScanRecord:
    comparison: PushComparison
    side: Literal["base", "head"]
    scan: ModelScanResult


@dataclass(frozen=True)
class PushReport:
    result: PushResult
    admission: AdmissionResult
    scans: tuple[ScanRecord, ...]
    provenance: Mapping[str, str]
    timings: Mapping[str, float]
    resolution: PushResolution | None = None
    snapshots: tuple[SnapshotManifest, ...] = ()
    change_context: ChangeContext | None = None
    change_contexts: tuple[ChangeContext, ...] = ()
    model_assistance: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_assistance", MappingProxyType(dict(self.model_assistance)))
        object.__setattr__(self, "provenance", MappingProxyType(dict(self.provenance)))
        object.__setattr__(self, "timings", MappingProxyType(dict(self.timings)))
        ids = tuple(defect.defect_id for defect in self.admission.defects)
        if ids != self.result.actionable_defect_ids:
            raise ValueError("report must retain the exact admitted defect set and order")
        if any(
            not all((d.witnesses, d.locations, d.consequences, d.repairs, d.change_evidence, d.comparisons)) for d in self.admission.defects
        ):
            raise ValueError("actionable summaries require witnesses, locations, consequence, repair and change evidence")
        admitted = {d.candidate.delta.defect_id for d in self.admission.dispositions if d.admitted}
        if admitted != set(ids):
            raise ValueError("report must retain every admitted candidate disposition")
        comparisons = {analysis.comparison for analysis in self.result.analyses}
        if self.result.coverage_status == "complete_within_scope" and self.admission.coverage_reasons:
            raise ValueError("complete comparison cannot hide admission coverage gaps")
        if any(record.comparison not in comparisons or record.side not in ("base", "head") for record in self.scans):
            raise ValueError("scan evidence must belong to an exact reported comparison and side")
        for analysis in self.result.analyses:
            heads = [record.scan for record in self.scans if record.comparison == analysis.comparison and record.side == "head"]
            if any(scope not in [scan.scope for scan in heads] for scope in analysis.scopes):
                raise ValueError("reported scope requires the actual head scan evidence")
            completed = {outcome.identity for scan in heads for outcome in scan.question_outcomes if outcome.status == "completed"}
            if not set(analysis.completed_questions) <= completed:
                raise ValueError("completed questions require completed recorded outcomes")
            if analysis.coverage_status == "complete_within_scope":
                bases = [record.scan for record in self.scans if record.comparison == analysis.comparison and record.side == "base"]
                if not bases or any(not _completed_scan(scan) for scan in (*heads, *bases)):
                    raise ValueError("complete comparison requires completed head and base evidence")
        required = {"repository", "engine", "facts", "queries", "policy"}
        if not required <= self.provenance.keys() or any(not isinstance(v, str) or not v.strip() for v in self.provenance.values()):
            raise ValueError("report requires repository, engine, facts, queries and policy provenance")
        if "total_seconds" not in self.timings or any(
            type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in self.timings.values()
        ):
            raise ValueError("report requires finite nonnegative timings including total_seconds")


@dataclass(frozen=True)
class ReportDelivery:
    result: PushResult
    text: str
    artifact: Path | None
    error: str | None
    reporting_seconds: float = 0.0

    @property
    def exit_code(self) -> int:
        return int(self.result.push_disposition == "block")


def _completed_scan(scan: ModelScanResult) -> bool:
    return bool(
        scan.scope
        and scan.scope.population_complete
        and not scan.scope.deferred
        and not _context_boundaries(scan)
        and not scan.degradations
        and {q.identity for q in scan.scope.selected} == {q.identity for q in scan.question_outcomes if q.status == "completed"}
        and all(q.status == "completed" for q in scan.question_outcomes)
    )


def _write_artifact(report: PushReport, target: Path, temporary: Path, connection: Connection) -> None:
    """Only this bounded child performs serialization or filesystem operations."""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                payload = {
                    "schema_version": 1,
                    "model_assistance": dict(report.model_assistance),
                    "change_contexts": [item.to_payload() for item in report.change_contexts],
                    "snapshots": [item.to_payload() for item in report.snapshots],
                    "change_context": report.change_context.to_payload() if report.change_context else None,
                    "result": report.result.to_payload(),
                    "admission": report.admission.to_payload(),
                    "scans": [asdict(record) for record in report.scans],
                    "provenance": dict(report.provenance),
                    "timings": dict(report.timings),
                    "timing_scope": "Caller stage measurements; publication and rendering duration is returned in ReportDelivery.",
                    "resolution": report.resolution.to_payload() if report.resolution else None,
                }
                json.dump(payload, stream, ensure_ascii=True, allow_nan=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        connection.send(None)
    except Exception as error:
        connection.send("artifact_write_failed:" + type(error).__name__)
    finally:
        connection.close()


def _save(report: PushReport, target: Path, budget: ExecutionBudget) -> str | None:
    # Persist completed evidence during the remaining cancellation/report allowance.
    # Never restart that allowance for a late caller.
    end = budget.deadline_monotonic + budget.cancellation_allowance_seconds
    if time.monotonic() >= end:
        return "report_deadline_exhausted"
    reserve = min(0.1, budget.cancellation_allowance_seconds / 2)
    reader = writer = process = None
    try:
        temporary = target.with_name("." + target.name + ".partial-" + uuid.uuid4().hex)
        context = multiprocessing.get_context("fork")
        reader, writer = context.Pipe(duplex=False)
        process = context.Process(target=_write_artifact, args=(report, target, temporary, writer), daemon=True)
        process.start()
        writer.close()
        process.join(max(0.0, end - time.monotonic() - reserve))
        if process.is_alive():
            process.kill()
            process.join(max(0.0, end - time.monotonic()))
            return "report_deadline_exhausted"
        if process.exitcode != 0 or not reader.poll():
            return "artifact_writer_failed"
        error = reader.recv()
        return None if error is None else error if isinstance(error, str) else "artifact_writer_failed"
    except (OSError, ValueError, EOFError, RuntimeError):
        return "artifact_writer_unavailable"
    finally:
        if writer is not None:
            writer.close()
        if reader is not None:
            reader.close()
        if process is not None:
            if process.is_alive():
                process.kill()
                process.join(max(0.0, end - time.monotonic()))
            if not process.is_alive():
                process.close()


def _short(value: str, limit: int = 180) -> str:
    # Bound before escaping: repository-controlled names/witnesses cannot add lines
    # or terminal escapes. Full spelling and every witness remain in the artifact.
    clipped = value if len(value) <= limit else value[: limit // 2] + "..." + value[-limit // 2 :]
    return json.dumps(clipped, ensure_ascii=True)[1:-1]


def render_report(report: PushReport, *, artifact: Path | None, error: str | None = None) -> str:
    lines: list[str] = []
    defects = report.admission.defects
    for defect in defects[:3]:
        path, line = defect.locations[0]
        choices = report.model_assistance.get("selections", {})
        index = choices.get(defect.defect_id, 0) if isinstance(choices, dict) else 0
        if type(index) is not int or not 0 <= index < len(defect.witnesses):
            index = 0
        witness = defect.witnesses[index]
        supported = [
            disposition.candidate.delta
            for disposition in report.admission.dispositions
            if disposition.admitted and disposition.candidate.delta.defect_id == defect.defect_id
        ]
        delta = next((candidate for candidate in supported if candidate.witness == witness), supported[0])
        # Keep the displayed location/change bound to the chosen admitted witness,
        # including when a defect was deduplicated across revisions or locations.
        witness = delta.witness or defect.witnesses[0]
        if delta.head_operation is not None:
            path, line = delta.head_operation.path, delta.head_operation.line
        change = (
            "A protection present in the base is missing here."
            if delta.reason == "discharge_removed"
            else "This change connects input to the operation."
        )
        lines.extend(
            (
                f"- {_short(defect.family)} at {_short(path, 4096)}:{line}: {_short(defect.consequences[0])}",
                f"  Evidence: {_short(redact_secrets(witness))}; Change: {change} ({_short(defect.change_evidence[0])})",
                f"  Fix: {_short(defect.repairs[0])}",
            )
        )
    if len(defects) > 3:
        lines.append(f"{len(defects) - 3} more actionable defects retained in the detailed result.")
    if not defects:
        coverage = report.result.coverage_status
        if coverage == "complete_within_scope":
            completed = sum(len(analysis.completed_questions) for analysis in report.result.analyses)
            lines.append(f"No actionable defects in {completed} completed checks within the recorded scope.")
        elif coverage == "not_applicable":
            lines.append("No applicable code updates to check.")
        elif coverage == "unavailable":
            lines.append("No analysis result is available.")
        else:
            lines.append("No actionable defects reported; analysis is incomplete.")
    notices = []
    if report.result.coverage_status in ("incomplete", "unavailable"):
        reasons = report.admission.coverage_reasons
        if any("deadline" in reason for reason in reasons):
            notices.append("Analysis did not finish. Rerun with a longer analysis deadline.")
        elif any("capability" in reason for reason in reasons):
            notices.append("Some checks are not enabled for normal alerts. Review capability coverage in the details.")
        else:
            notices.append(
                "Some checks could not be completed. Review the comparison details and resolve the recorded gaps before retrying."
            )
    if error == "artifact_inside_repository":
        notices.append("Details could not be saved. Choose an artifact path outside the analyzed repository.")
    elif error:
        notices.append("Details could not be saved. Retry with a writable artifact path and available reporting time.")
    if notices:
        lines.append("Notice: " + " ".join(notices))
    if artifact is not None:
        lines.append("Details: " + _short(str(artifact), 4096))
    if report.result.push_disposition == "block":
        lines.append("Push blocked by the configured policy.")
    return "\n".join(lines) + "\n"


def deliver_report(report: PushReport, artifact: Path, *, execution_budget: ExecutionBudget) -> ReportDelivery:
    started = time.monotonic()
    error = _save(report, artifact, execution_budget)
    saved = artifact if error is None else None
    text = render_report(report, artifact=saved, error=error)
    return ReportDelivery(report.result, text, saved, error, time.monotonic() - started)
