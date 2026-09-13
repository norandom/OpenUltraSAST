"""Bounded, local base/head replay through the existing repository driver."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import selectors
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from openultrasast.config import PushConfig
from openultrasast.cpg.artifact import digest_value
from openultrasast.cpg.backend import JoernBackend, engine_runtime_identity, joern_version
from openultrasast.mapping import analyze_entry_points
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.layout import layout_facts
from openultrasast.model.regions import ScanRegion, regions_for
from openultrasast.model.scan import ScanBudget, scan_repository
from openultrasast.model.shipped import declared_sources
from openultrasast.preprocess import build_file_target, enumerate_source_files
from openultrasast.push.cache import ArtifactCache, SemanticKeys
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison, PushResult, SnapshotManifest
from openultrasast.push.policy import (
    ActionableDefect,
    AdmissionCandidate,
    AdmissionResult,
    CapabilityKey,
    admission_push_result,
    admit_candidates,
    compare_targeted_base,
    semantics_digest,
)
from openultrasast.push.report import PushReport, ReportDelivery, ScanRecord, _completed_scan, deliver_report, render_report
from openultrasast.push.reuse import ReusingBackend, declaration_identity, discovery
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
    runtime = engine_runtime_identity()
    integration = digest(list((root / "cpg").glob("*.py")))
    return {
        "repository": str(repository.absolute()),
        "engine_runtime": runtime,
        "engine": engine,
        "facts": digest(list((root / "ruleset").rglob("*.toml"))),
        "graph_layout": digest_value(
            {
                "facts": [asdict(row) for row in layout_facts()],
                "implementation": digest([root / "model/layout.py", root / "model/partitions.py"]),
            }
        ),
        "queries": digest(list((root / "cpg/queries").glob("*.sc"))),
        "policy": digest(list((root / "push").glob("*.py"))),
        "core": digest(list((root / "model").glob("*.py")) + list((root / "cpg").glob("*.py"))),
        "semantics": semantics_digest(
            engine_identity=engine, options={**asdict(scan_budget), "engine_runtime": runtime, "engine_integration": integration}
        ),
        "ranking_mode": "evidence",
        "model": "disabled",
        "capabilities": "empty_registry_pending_task_8.3",
        "cache": "cold_no_reuse",
    }


def _discovery_identity() -> str:
    root = Path(__file__).resolve().parents[1]
    # Discovery invokes the shipped mapper, preprocessing, layout and family specs.
    # Hash code bytes, never a mutable import name or a repository-provided version.
    return digest_value([(p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob("*.py"))])


def _analyze(
    repository: Path,
    *,
    base: str,
    head: str,
    artifact: Path,
    config: PushConfig | None = None,
    backend: Any = None,
    max_regions: int = 500,
    cache_dir: Path | None = None,
    execution_budget: ExecutionBudget,
    resolved: PushComparison | None = None,
) -> PushReport:
    """Run a single explicit comparison; exit policy never stands for coverage."""
    config = config or PushConfig()
    if max_regions < 1:
        raise ValueError("max_regions must be positive")
    if cache_dir is not None and cache_dir.resolve().is_relative_to(repository.resolve()):
        raise ValueError("cache directory must be outside the analyzed repository")
    started = time.monotonic()
    budget = execution_budget
    scan_budget = ScanBudget(max_model_calls=0, max_regions=max_regions, order_by_evidence=True)
    if backend is None:
        backend = JoernBackend()
    cache = None
    cache_semantics = None
    reused: list[ReusingBackend] = []
    records: list[ScanRecord] = []
    manifests: list[SnapshotManifest] = []
    reasons: list[str] = []
    admission = AdmissionResult((), (), ())
    comparison = resolved
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
        comparison = resolved or adapter.resolve_replay(base, head)
        timings[stage + "_seconds"] = time.monotonic() - stage_started
        stage, stage_started = "provenance", time.monotonic()
        provenance.update(_prepare(lambda: _provenance(repository, scan_budget), budget))
        timings[stage + "_seconds"] = time.monotonic() - stage_started
        if cache_dir is not None:
            cache = ArtifactCache(cache_dir, max_bytes=config.cache_max_bytes)
            cache_semantics = SemanticKeys(
                provenance["facts"],
                provenance["queries"],
                digest_value({"query_parameters": "complete-joern-request-v1"}),
                digest_value({"ranking_mode": "evidence", "options": asdict(scan_budget)}),
                provenance["policy"],
                provenance["model"],
                provenance["capabilities"],
                config.mode,
            )
            provenance["cache"] = "validated_local_reuse"
        discovery_identity = digest_value({"code": _prepare(lambda: _discovery_identity(), budget), "facts": provenance["facts"]})
        stage, stage_started = "preparation", time.monotonic()
        with adapter.materialize(comparison.head_oid, budget=budget) as tip:
            manifests.append(tip.manifest)
            assert comparison.base_oid is not None
            old_context = (
                nullcontext(tip) if comparison.base_oid == comparison.head_oid else adapter.materialize(comparison.base_oid, budget=budget)
            )
            with old_context as old:
                manifests.append(old.manifest)
                for manifest in manifests:
                    reasons.extend("snapshot:" + boundary.reason for boundary in manifest.boundaries)
                timings["snapshot_seconds"] = time.monotonic() - stage_started
                timings["snapshot_reuses"] = int(comparison.base_oid == comparison.head_oid)
                discovery_started = time.monotonic()
                head_regions, head_declarations, head_hit = _prepare(
                    lambda: discovery(tip.root, tip.manifest, cache=cache, identity=discovery_identity, budget=budget, discover=_discover),
                    budget,
                )
                base_regions, base_declarations, base_hit = _prepare(
                    lambda: discovery(old.root, old.manifest, cache=cache, identity=discovery_identity, budget=budget, discover=_discover),
                    budget,
                )
                timings["discovery_seconds"] = time.monotonic() - discovery_started
                timings["discovery_hits"] = int(head_hit) + int(base_hit)
                head_backend = base_backend = backend
                if (
                    cache is not None
                    and cache_semantics is not None
                    and isinstance(backend, JoernBackend)
                    and all(m.complete for m in manifests)
                ):
                    head_backend = ReusingBackend(
                        backend,
                        cache,
                        cache_semantics,
                        declarations=declaration_identity(tip.manifest, head_declarations),
                        exclusions=provenance["graph_layout"],
                    )
                    base_backend = ReusingBackend(
                        backend,
                        cache,
                        cache_semantics,
                        declarations=declaration_identity(old.manifest, base_declarations),
                        exclusions=provenance["graph_layout"],
                    )
                    reused.extend((head_backend, base_backend))
                context = adapter.compare(comparison, declaration_paths=tuple(set(head_declarations + base_declarations)), budget=budget)
                context = replace(context, unresolved_boundaries=tuple(dict.fromkeys((*context.unresolved_boundaries, *reasons))))
                reasons.extend(context.unresolved_boundaries)
                timings[stage + "_seconds"] = time.monotonic() - stage_started
                stage, stage_started = "head", time.monotonic()
                head_scan = scan_repository(
                    tip.root,
                    head_regions,
                    backend=head_backend,
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
                    backend=base_backend,
                    execution_budget=budget,
                    scan_budget=scan_budget,
                    head_semantics=provenance["semantics"],
                    base_semantics=provenance["semantics"],
                    cache=cache,
                    cache_semantics=cache_semantics,
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
    timings["graph_hits"] = sum(item.graph_hits for item in reused)
    timings["query_hits"] = sum(item.query_hits for item in reused)
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
    return report


def _deliver(repository: Path, report: PushReport, artifact: Path, budget: ExecutionBudget) -> ReportDelivery:
    if artifact.resolve().is_relative_to(repository.resolve()):
        error = "artifact_inside_repository"
        return ReportDelivery(report.result, render_report(report, artifact=None, error=error), None, error)
    return deliver_report(report, artifact, execution_budget=budget)


def replay(
    repository: Path,
    *,
    base: str,
    head: str,
    artifact: Path,
    config: PushConfig | None = None,
    backend: Any = None,
    max_regions: int = 500,
    cache_dir: Path | None = None,
) -> ReportDelivery:
    config = config or PushConfig()
    budget = ExecutionBudget(time.monotonic() + config.deadline_seconds, config.cancellation_allowance_seconds)
    report = _analyze(
        repository,
        base=base,
        head=head,
        artifact=artifact,
        config=config,
        backend=backend,
        max_regions=max_regions,
        cache_dir=cache_dir,
        execution_budget=budget,
    )
    return _deliver(repository, report, artifact, budget)


def push(
    repository: Path,
    *,
    updates: str | Callable[[], str],
    remote_name: str,
    remote_url: str,
    artifact: Path,
    config: PushConfig | None = None,
    backend: Any = None,
    max_regions: int = 500,
    cache_dir: Path | None = None,
    execution_budget: ExecutionBudget | None = None,
) -> ReportDelivery:
    """Consume one Git transaction. Resolution, every comparison and reporting share a deadline."""
    config = config or PushConfig()
    if max_regions < 1:
        raise ValueError("max_regions must be positive")
    if cache_dir is not None and cache_dir.resolve().is_relative_to(repository.resolve()):
        raise ValueError("cache directory must be outside the analyzed repository")
    started = time.monotonic()
    budget = execution_budget or ExecutionBudget(started + config.deadline_seconds, config.cancellation_allowance_seconds)
    reports: list[PushReport] = []
    analyses: list[ComparisonAnalysis] = []
    reasons: list[str] = []
    resolution = None
    try:
        data = _prepare(updates, budget) if callable(updates) else updates
        if len(data.encode("utf-8")) > 1024 * 1024:
            raise ValueError("push_input_limit")
        adapter = SnapshotAdapter(repository, comparison_base=config.comparison_base, execution_budget=budget)
        resolution = adapter.resolve_updates(data)
        reasons.extend("resolution:" + row.disposition for row in resolution.updates if row.disposition not in ("ready", "deleted"))
        for comparison in resolution.comparisons:
            if comparison.base_oid is None or time.monotonic() >= budget.deadline_monotonic:
                analyses.append(ComparisonAnalysis(comparison, (), (), "unavailable"))
                reasons.append("base_comparison_unavailable" if comparison.base_oid is None else "deadline_exhausted")
                continue
            report = _analyze(
                repository,
                base=comparison.base_oid,
                head=comparison.head_oid,
                artifact=artifact,
                config=config,
                backend=backend,
                max_regions=max_regions,
                cache_dir=cache_dir,
                execution_budget=budget,
                resolved=comparison,
            )
            reports.append(report)
            analyses.extend(report.result.analyses)
    except Exception as error:
        reasons.append("push_input_failed:" + type(error).__name__)
    if time.monotonic() >= budget.deadline_monotonic:
        reasons.append("deadline_exhausted")
    defects: dict[str, ActionableDefect] = {}
    for report in reports:
        for defect in report.admission.defects:
            previous = defects.get(defect.defect_id)
            if previous is None:
                defects[defect.defect_id] = defect
            else:
                fields = ("witnesses", "locations", "comparisons", "refs", "change_evidence", "consequences", "repairs", "evaluation_ids")
                defects[defect.defect_id] = replace(
                    previous,
                    **cast(dict[str, Any], {key: tuple(dict.fromkeys((*getattr(previous, key), *getattr(defect, key)))) for key in fields}),
                )
    admission = AdmissionResult(
        tuple(defects.values()),
        tuple(d for r in reports for d in r.admission.dispositions),
        tuple(dict.fromkeys((*reasons, *(g for r in reports for g in r.admission.coverage_reasons)))),
    )
    result = admission_push_result(admission, tuple(analyses), config=config)
    if resolution is not None and not resolution.comparisons and not reasons:
        result = PushResult((), "none", "not_applicable", "allow", ())
    provenance = dict(reports[0].provenance) if reports else {key: "not_run" for key in ("engine", "facts", "queries", "policy")}
    # Remote URLs can contain credentials. Retain identity without persisting secrets.
    provenance.update(
        repository=str(repository.absolute()),
        model="disabled",
        remote_name=remote_name or "unnamed",
        remote_url_sha256=hashlib.sha256(remote_url.encode()).hexdigest(),
    )
    timings = {f"comparison_{i}_{k}": v for i, r in enumerate(reports) for k, v in r.timings.items()}
    timings.update(
        total_seconds=time.monotonic() - started,
        deadline_seconds=config.deadline_seconds,
        cancellation_allowance_seconds=config.cancellation_allowance_seconds,
    )
    report = PushReport(
        result,
        admission,
        tuple(s for r in reports for s in r.scans),
        provenance,
        timings,
        resolution=resolution,
        snapshots=tuple(s for r in reports for s in r.snapshots),
        change_contexts=tuple(r.change_context for r in reports if r.change_context is not None),
    )
    return _deliver(repository, report, artifact, budget)
