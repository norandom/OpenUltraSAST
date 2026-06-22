from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from .benchmark import (
    create_benchmark_run,
    evaluate_benchmark,
    load_baseline_findings,
    load_benchmark_manifest,
    load_findings,
    resolve_benchmark_source,
    write_benchmark_artifacts,
)
from .calibration import (
    FalsePositiveLearning,
    calibrate_rankings,
    learnings_from_verifications,
    load_false_positive_learnings,
    merge_false_positive_learnings,
    write_false_positive_learnings,
    write_ranking_calibrations,
)
from .config import load_config
from .findings import StaticFinding, quick_scan_findings, write_findings
from .harness import HarnessRuntime, HarnessTraceWriter, write_harness_config
from .hunter import run_hunter_pool, write_hunter_trajectories
from .index import build_code_chunks
from .mapping import analyze_entry_points, attach_reachability_hints, ingest_sarif, write_entry_points, write_static_hints
from .policy import assert_rules_resolve, load_policy
from .preprocess import preprocess_repository, write_preprocess_artifact
from .rank import rank_targets, write_rankings
from .reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from .ruleset import DEFAULT_RULESET_DIR, load_ruleset
from .run import ScanRun, create_scan_run
from .scoring import build_score_artifact
from .verification import VerificationResult, verify_findings, write_verification_results

CALIBRATION_DIR = ".openultrasast/calibration"


@dataclass(frozen=True)
class ScanOutcome:
    scan_id: str
    run_dir: Path
    file_target_count: int
    ranked_target_count: int
    finding_count: int
    calibrations_applied: int
    exit_code: int


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ousast")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("quick", "standard", "deep"), default="quick")
    scan.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    scan.add_argument("--fail-on", choices=("never", "findings", "verified"), default="never")

    index = subparsers.add_parser("index", help="chunk a local repository for embedding index construction")
    index.add_argument("path", type=Path)
    index.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    index.add_argument("--chunk-lines", type=int, default=80)

    benchmark = subparsers.add_parser("benchmark", help="run a benchmark manifest and write scoreboard artifacts")
    benchmark.add_argument("manifest", type=Path)
    benchmark.add_argument("--mode", choices=("quick", "standard", "deep"), default="quick")
    benchmark.add_argument("--config", type=Path, default=Path("openultrasast.toml"))

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.config, args.mode, args.fail_on)
    if args.command == "index":
        return _index(args.path, args.config, args.chunk_lines)
    if args.command == "benchmark":
        return _benchmark(args.manifest, args.config, args.mode)
    return 2


def _scan(path: Path, config_path: Path, mode: str, fail_on: str) -> int:
    outcome = _run_scan(path, config_path, mode, fail_on)
    _print_scan_outcome(outcome)
    return outcome.exit_code


def _run_scan(path: Path, config_path: Path, mode: str, fail_on: str) -> ScanOutcome:
    if mode == "deep":
        raise SystemExit("mode 'deep' is specified but sandboxed dynamic analysis is not implemented")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"scan path is not a directory: {path}")

    config = load_config(config_path if config_path.exists() else None)
    run = create_scan_run(path, config)
    runtime = HarnessRuntime(
        scan_id=run.scan_id,
        config=config,
        trace_writer=HarnessTraceWriter(run.root / "trace" / "events.jsonl"),
    )
    write_harness_config(config=config, processors=[], contract_mode="strict", path=run.root / "harness.json")
    runtime.start(mode=mode, target=run.target)
    policy = runtime.run_stage("policy_load", load_policy)
    ruleset = runtime.run_stage("ruleset_load", lambda: load_ruleset(DEFAULT_RULESET_DIR))
    runtime.run_stage("policy_check", lambda: assert_rules_resolve(ruleset, policy))
    static_hints = runtime.run_stage("static_mapping", lambda: _load_static_hints(config.static_analysis.sarif_paths))
    write_static_hints(static_hints, run.root / "mapping" / "static_hints.json")
    snapshot, targets = runtime.run_stage(
        "preprocess",
        lambda: preprocess_repository(run.target, run.root / "preprocess" / "file_targets.json", static_hints),
    )
    entry_points = runtime.run_stage("entry_point_mapping", lambda: analyze_entry_points(run.target, targets))
    write_entry_points(entry_points, run.root / "mapping" / "entry_points.json")
    targets = attach_reachability_hints(targets, entry_points)
    write_preprocess_artifact(snapshot, targets, run.root / "preprocess" / "file_targets.json")
    rankings = runtime.run_stage("rank", lambda: rank_targets(targets))
    ledger_path = run.target / CALIBRATION_DIR / "false_positive_learnings.json"
    prior_learnings = load_false_positive_learnings(ledger_path)
    rankings, calibrations = runtime.run_stage("calibrate", lambda: calibrate_rankings(rankings, prior_learnings))
    applied_calibrations = [calibration for calibration in calibrations if calibration.applied_learning_ids]
    write_rankings(rankings, run.root / "rank" / "ranking.json")
    write_ranking_calibrations(calibrations, run.root / "calibration" / "applied_calibrations.json")
    if mode == "standard":
        hunter_result = runtime.run_stage(
            "hunter_pool",
            lambda: run_hunter_pool(run.target, targets, rankings, scan_id=run.scan_id, ruleset=ruleset, policy=policy),
        )
        findings = hunter_result.findings
        trajectories = hunter_result.trajectories
    else:
        findings = runtime.run_stage(
            "quick_findings",
            lambda: quick_scan_findings(
                run.target,
                targets,
                rankings,
                ruleset,
                policy,
                min_emit_priority=config.ruleset.min_emit_priority,
                min_emit_precision=config.ruleset.min_emit_precision,
            ),
        )
        trajectories = []
    # Shadow-status rules fire but are excluded from the report and the score;
    # their outcomes are preserved separately for precision tracking.
    shadow_findings = [finding for finding in findings if finding.status == "shadow"]
    if shadow_findings:
        findings = [finding for finding in findings if finding.status != "shadow"]
        write_findings(shadow_findings, run.root / "shadow_findings.json")
    findings_path = run.root / "findings.json"
    verification_path = run.root / "verification.json"
    markdown_path = run.root / "report.md"
    sarif_path = run.root / "report.sarif"
    manifest_path = run.root / "manifest.json"
    trajectories_path = run.root / "traces" / "hunter_trajectories.jsonl"
    write_findings(findings, findings_path)
    if trajectories:
        write_hunter_trajectories(trajectories, trajectories_path)
    verifications = runtime.run_stage("verify", lambda: verify_findings(findings))
    write_verification_results(verifications, verification_path)
    runtime.run_stage(
        "record_calibration",
        lambda: _persist_calibration_feedback(run, ledger_path, prior_learnings, findings, verifications),
    )
    cwe_by_rule = {rule.rule_id: rule.cwe for rule in ruleset}
    rule_cwe_by_id = {finding.finding_id: cwe_by_rule.get(finding.finding_id.split(":", 1)[0], "") for finding in findings}
    score_artifact = runtime.run_stage(
        "score",
        lambda: build_score_artifact(
            findings,
            rule_cwe_by_id,
            policy,
            k=config.score.k,
            min_score=config.score.min_score,
            block_severity_reachable=config.score.block_severity_reachable,
            blocking=config.score.blocking,
        ),
    )
    score_path = run.root / "score.json"
    score_path.write_text(json.dumps(score_artifact.to_dict(), indent=2, sort_keys=True) + "\n")
    runtime.run_stage("report", lambda: write_markdown_report(findings, markdown_path, verifications))
    runtime.run_stage("sarif", lambda: write_sarif_report(findings, verifications, sarif_path))
    runtime.run_stage(
        "manifest",
        lambda: write_manifest(
            run=run,
            findings=findings,
            verifications=verifications,
            artifact_paths=_artifact_paths(
                findings=findings_path,
                verification=verification_path,
                markdown=markdown_path,
                sarif=sarif_path,
                score=score_path,
                trajectories=trajectories_path if trajectories else None,
            ),
            path=manifest_path,
            score=score_artifact.to_dict(),
        ),
    )
    runtime.finish(status="succeeded")
    return ScanOutcome(
        scan_id=run.scan_id,
        run_dir=run.root,
        file_target_count=len(targets),
        ranked_target_count=len(rankings),
        finding_count=len(findings),
        calibrations_applied=len(applied_calibrations),
        exit_code=scan_exit_code(findings, verifications, fail_on),
    )


def _persist_calibration_feedback(
    run: ScanRun,
    ledger_path: Path,
    prior_learnings: list[FalsePositiveLearning],
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
) -> list[FalsePositiveLearning]:
    # Store rejected or held findings as scoped learnings for the next scan.
    new_learnings = learnings_from_verifications(findings, verifications)
    merged = merge_false_positive_learnings(prior_learnings, new_learnings)
    write_false_positive_learnings(merged, ledger_path)
    write_false_positive_learnings(new_learnings, run.root / "calibration" / "false_positive_learnings.json")
    return merged


def _print_scan_outcome(outcome: ScanOutcome) -> None:
    print(f"scan_id={outcome.scan_id}")
    print(f"run_dir={outcome.run_dir}")
    print(f"file_targets={outcome.file_target_count}")
    print(f"ranked_targets={outcome.ranked_target_count}")
    print(f"findings={outcome.finding_count}")
    print(f"calibrations_applied={outcome.calibrations_applied}")


def _load_static_hints(sarif_paths: tuple[str, ...]) -> list[object]:
    hints: list[object] = []
    for sarif_path in sarif_paths:
        path = Path(sarif_path)
        if path.exists():
            hints.extend(ingest_sarif(path))
    return hints


def _artifact_paths(**paths: Path | None) -> dict[str, Path]:
    return {name: path for name, path in paths.items() if path is not None}


def _benchmark(manifest_path: Path, config_path: Path, mode: str) -> int:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise SystemExit(f"benchmark manifest is not a file: {manifest_path}")
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    run = create_benchmark_run(target, manifest)
    started_at = perf_counter()
    outcome = _run_scan(target, config_path, mode, "never")
    runtime_seconds = perf_counter() - started_at
    findings = _load_scan_findings(outcome.run_dir)
    baseline_findings = load_baseline_findings(manifest_path, manifest)
    result = evaluate_benchmark(
        run=run,
        mode=mode,
        findings=findings,
        scan_id=outcome.scan_id,
        scan_run_dir=outcome.run_dir,
        runtime_seconds=runtime_seconds,
        baseline_findings=baseline_findings,
    )
    write_benchmark_artifacts(run, manifest_path, result)
    _print_scan_outcome(outcome)
    print(f"benchmark_run_id={run.benchmark_run_id}")
    print(f"benchmark_run_dir={run.root}")
    print(f"benchmark_expected={result.metrics.expected_findings_total}")
    print(f"benchmark_matched={result.metrics.matched_findings_total}")
    print(f"benchmark_missed={result.metrics.missed_findings_total}")
    return 0


def _load_scan_findings(run_dir: Path) -> list[StaticFinding]:
    return load_findings(run_dir / "findings.json")


def _index(path: Path, config_path: Path, chunk_lines: int) -> int:
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"index path is not a directory: {path}")
    config = load_config(config_path if config_path.exists() else None)
    run = create_scan_run(path, config)
    snapshot, targets = preprocess_repository(run.target, run.root / "preprocess" / "file_targets.json")
    chunks = build_code_chunks(run.target, targets, max_lines=chunk_lines)
    payload = {
        "store": config.embeddings.store or "json-local",
        "embedding_model": config.embeddings.model,
        "repo_root": snapshot.root,
        "repo_commit": snapshot.commit,
        "chunk_count": len(chunks),
        "chunks": [chunk.__dict__ for chunk in chunks],
    }
    path_out = run.root / "index" / "chunks.json"
    path_out.parent.mkdir(parents=True, exist_ok=True)
    path_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"scan_id={run.scan_id}")
    print(f"run_dir={run.root}")
    print(f"chunks={len(chunks)}")
    print(f"index_artifact={path_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
