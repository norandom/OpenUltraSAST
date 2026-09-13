"""Bounded, local base/head replay through the existing repository driver."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import selectors
import time
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from openultrasast.config import PushConfig
from openultrasast.cpg.backend import joern_version, resolve_cpg_backend
from openultrasast.mapping import analyze_entry_points
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import ScanRegion, regions_for
from openultrasast.model.scan import ScanBudget, scan_repository
from openultrasast.model.shipped import declared_sources
from openultrasast.preprocess import build_file_target, enumerate_source_files
from openultrasast.push.contracts import ComparisonAnalysis, SnapshotManifest
from openultrasast.push.policy import (
    AdmissionCandidate,
    AdmissionResult,
    CapabilityKey,
    admission_push_result,
    admit_candidates,
    compare_targeted_base,
    semantics_digest,
)
from openultrasast.push.report import PushReport, ReportDelivery, ScanRecord, _completed_scan, deliver_report, render_report
from openultrasast.push.snapshot import SnapshotAdapter

_T = TypeVar("_T")


def _prepare(function: Callable[[], _T], budget: ExecutionBudget) -> _T:
    """Bound pure local discovery/metadata work, including serialization, on Linux.

    Read incrementally while the child writes; no pipe-buffer deadlock or unbounded
    blocking recv. The child never launches engines or project code.
    """
    if time.monotonic() >= budget.deadline_monotonic:
        raise TimeoutError("deadline_exhausted")
    reader, writer = os.pipe()

    def child() -> None:
        os.close(reader)
        try:
            payload: tuple[bool, Any]
            try:
                payload = (True, function())
            except Exception as error:
                payload = (False, type(error).__name__)
            with os.fdopen(writer, "wb") as stream:
                pickle.dump(payload, stream, protocol=5)
        finally:
            os._exit(0)

    process = multiprocessing.get_context("fork").Process(target=child)
    data = bytearray()
    try:
        process.start()
        os.close(writer)
        writer = -1
        with selectors.DefaultSelector() as selector:
            selector.register(reader, selectors.EVENT_READ)
            while selector.get_map():
                remaining = budget.deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("deadline_exhausted")
                for key, _ in selector.select(min(0.05, remaining)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(chunk)
                        if len(data) > 32 * 1024**2:
                            raise ValueError("preparation_output_limit")
        process.join(max(0, budget.deadline_monotonic - time.monotonic()))
        if process.is_alive() or process.exitcode != 0 or not data:
            raise RuntimeError("preparation_worker_failed")
        success, result = pickle.loads(data)  # trusted child, never repository-provided pickle
        if not success:
            raise RuntimeError("preparation_failed:" + result)
        return cast(_T, result)
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)
        if process.pid is not None:
            if process.is_alive():
                process.kill()
                process.join(max(0, budget.deadline_monotonic + budget.cancellation_allowance_seconds - time.monotonic()))
            if not process.is_alive():
                process.close()


def _discover(root: Path) -> tuple[tuple[ScanRegion, ...], tuple[bytes, ...]]:
    # Same proposer and declaration-based shipping rules as ordinary scans. Do not
    # call preprocess's live-HEAD probe on a materialized, intentionally Git-free tree.
    files = enumerate_source_files(root)
    targets = [build_file_target(root, path) for path in files]
    regions = regions_for(analyze_entry_points(root, targets), targets, shipped=declared_sources(root))
    # Conservatively seed every tracked declaration/non-source file. This is change
    # context only, never a graph allowlist or a second scope selector.
    sources = set(files)
    declarations = tuple(os.fsencode(str(p.relative_to(root))) for p in root.rglob("*") if p.is_file() and p not in sources)
    return regions, declarations


def _provenance(repository: Path, scan_budget: ScanBudget) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]

    def digest(paths: list[Path]) -> str:
        hasher = hashlib.sha256()
        for path in sorted(paths):
            hasher.update(str(path.relative_to(root)).encode())
            hasher.update(path.read_bytes())
        return hasher.hexdigest()

    version = joern_version()
    engine = "joern-" + (".".join(map(str, version)) if version else "unavailable_or_unidentified")
    return {
        "repository": str(repository.absolute()),
        "engine": engine,
        "facts": digest(list((root / "ruleset").rglob("*.toml"))),
        "queries": digest(list((root / "cpg/queries").glob("*.sc"))),
        "policy": digest(list((root / "push").glob("*.py"))),
        "core": digest(list((root / "model").glob("*.py")) + list((root / "cpg").glob("*.py"))),
        "semantics": semantics_digest(engine_identity=engine, options=asdict(scan_budget)),
        "ranking_mode": "evidence",
        "model": "disabled",
        "capabilities": "empty_registry_pending_task_8.3",
        "cache": "cold_no_reuse",
    }


def replay(
    repository: Path,
    *,
    base: str,
    head: str,
    artifact: Path,
    config: PushConfig | None = None,
    backend: Any = None,
    max_regions: int = 500,
) -> ReportDelivery:
    """Run a single explicit comparison; exit policy never stands for coverage."""
    config = config or PushConfig()
    if max_regions < 1:
        raise ValueError("max_regions must be positive")
    started = time.monotonic()
    budget = ExecutionBudget(started + config.deadline_seconds, config.cancellation_allowance_seconds)
    scan_budget = ScanBudget(max_model_calls=0, max_regions=max_regions, order_by_evidence=True)
    records: list[ScanRecord] = []
    manifests: list[SnapshotManifest] = []
    reasons: list[str] = []
    admission = AdmissionResult((), (), ())
    comparison = None
    context = None
    timings: dict[str, float] = {
        "deadline_seconds": config.deadline_seconds,
        "cancellation_allowance_seconds": config.cancellation_allowance_seconds,
    }
    provenance = {key: "unavailable_preparation_incomplete" for key in ("engine", "facts", "queries", "policy")}
    provenance.update(repository=str(repository.absolute()), model="disabled", requested_base=base, requested_head=head)
    stage = "resolution"
    stage_started = started
    try:
        adapter = SnapshotAdapter(repository, execution_budget=budget)
        comparison = adapter.resolve_replay(base, head)
        timings[stage + "_seconds"] = time.monotonic() - stage_started
        stage, stage_started = "provenance", time.monotonic()
        provenance.update(_prepare(lambda: _provenance(repository, scan_budget), budget))
        timings[stage + "_seconds"] = time.monotonic() - stage_started
        stage, stage_started = "preparation", time.monotonic()
        with adapter.materialize(comparison.head_oid, budget=budget) as tip:
            manifests.append(tip.manifest)
            assert comparison.base_oid is not None
            with adapter.materialize(comparison.base_oid, budget=budget) as old:
                manifests.append(old.manifest)
                for manifest in manifests:
                    reasons.extend("snapshot:" + boundary.reason for boundary in manifest.boundaries)
                head_regions, head_declarations = _prepare(lambda: _discover(tip.root), budget)
                base_regions, base_declarations = _prepare(lambda: _discover(old.root), budget)
                context = adapter.compare(comparison, declaration_paths=tuple(set(head_declarations + base_declarations)), budget=budget)
                context = replace(context, unresolved_boundaries=tuple(dict.fromkeys((*context.unresolved_boundaries, *reasons))))
                reasons.extend(context.unresolved_boundaries)
                timings[stage + "_seconds"] = time.monotonic() - stage_started
                stage, stage_started = "head", time.monotonic()
                head_scan = scan_repository(
                    tip.root,
                    head_regions,
                    backend=backend or resolve_cpg_backend(),
                    budget=scan_budget,
                    execution_budget=budget,
                    ranking_mode="evidence",
                    unit="repository",
                    population_complete=all(m.complete for m in manifests),
                    change_context=context,
                )
                records.append(ScanRecord(comparison, "head", head_scan))
                timings[stage + "_seconds"] = time.monotonic() - stage_started
                stage, stage_started = "base", time.monotonic()
                delta = compare_targeted_base(
                    old.root,
                    head=head_scan,
                    head_regions=head_regions,
                    base_regions=base_regions,
                    context=context,
                    backend=backend or resolve_cpg_backend(),
                    execution_budget=budget,
                    scan_budget=scan_budget,
                    head_semantics=provenance["semantics"],
                    base_semantics=provenance["semantics"],
                )
                if delta.base_scan is not None:
                    records.append(ScanRecord(comparison, "base", delta.base_scan))
                reasons.extend(delta.coverage_reasons)
                timings[stage + "_seconds"] = time.monotonic() - stage_started
                stage, stage_started = "admission", time.monotonic()
                candidates = tuple(
                    AdmissionCandidate(
                        c,
                        CapabilityKey(
                            c.head_operation.question.language if c.head_operation else "unknown",
                            "unspecified",
                            "unspecified",
                            c.family,
                            c.head_operation.mechanism if c.head_operation else "taint",
                            "unreviewed",
                            delta.semantics,
                        ),
                        comparison,
                        tuple(reasons),
                    )
                    for c in delta.candidates
                )
                admission = _prepare(lambda: admit_candidates(candidates), budget)
                timings[stage + "_seconds"] = time.monotonic() - stage_started
                stage, stage_started = "cleanup", time.monotonic()
        timings[stage + "_seconds"] = time.monotonic() - stage_started
    except Exception as error:
        reasons.append(stage + "_failed:" + type(error).__name__)
        timings[stage + "_seconds"] = time.monotonic() - stage_started
    if time.monotonic() >= budget.deadline_monotonic:
        reasons.append("deadline_exhausted")
    head_records = [r.scan for r in records if r.side == "head"]
    for record in records:
        if record.scan.scope is not None:
            reasons.extend(record.scan.scope.unresolved_boundaries)
    if not records or not all(_completed_scan(r.scan) for r in records):
        reasons.append("analysis_incomplete")
    if not any(r.side == "base" for r in records):
        reasons.append("base_comparison_unavailable")
    admission = replace(admission, coverage_reasons=tuple(dict.fromkeys((*admission.coverage_reasons, *reasons))))
    analyses: tuple[ComparisonAnalysis, ...] = ()
    if comparison is not None:
        scopes = tuple(scan.scope for scan in head_records if scan.scope is not None)
        completed = tuple(outcome.identity for scan in head_records for outcome in scan.question_outcomes if outcome.status == "completed")
        coverage: Literal["unavailable", "incomplete", "complete_within_scope"] = (
            "unavailable" if not records else "incomplete" if admission.coverage_reasons else "complete_within_scope"
        )
        analyses = (ComparisonAnalysis(comparison, scopes, completed, coverage),)
    result = admission_push_result(admission, analyses, config=config)
    timings["total_seconds"] = time.monotonic() - started
    report = PushReport(result, admission, tuple(records), provenance, timings, snapshots=tuple(manifests), change_context=context)
    try:
        artifact.resolve().relative_to(repository.resolve())
    except ValueError:
        pass
    else:
        write_error = "artifact_inside_repository"
        return ReportDelivery(result, render_report(report, artifact=None, error=write_error), None, write_error)
    return deliver_report(report, artifact, execution_budget=budget)
