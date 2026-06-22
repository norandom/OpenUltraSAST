from __future__ import annotations

import argparse
import json
import tempfile
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
    fp_reachability_overrides,
    learnings_from_verifications,
    load_false_positive_learnings,
    merge_false_positive_learnings,
    write_false_positive_learnings,
    write_ranking_calibrations,
)
from .config import load_config
from .findings import StaticFinding, quick_scan_findings, write_findings
from .fusion import FusionDecision, fuse_findings_dispatch
from .gate import FALSE_POSITIVE_CEILING, RECALL_FLOOR
from .harness import HarnessRuntime, HarnessTraceWriter, write_harness_config
from .harness_ext import has_harnessx
from .hunter import run_hunter_pool, write_hunter_trajectories
from .hunter_harness import HxScanOrchestrator
from .improve import RoundOutcome, run_improvement
from .index import build_code_chunks
from .mapping import analyze_entry_points, attach_reachability_hints, ingest_sarif, write_entry_points, write_static_hints
from .policy import assert_rules_resolve, load_policy
from .preprocess import preprocess_repository, write_preprocess_artifact
from .rank import rank_targets, write_rankings
from .reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from .ruleset import DEFAULT_RULESET_DIR, load_ruleset
from .run import ScanRun, create_scan_run
from .scoring import build_score_artifact
from .verification import VerificationResult, write_verification_results
from .verify_judge import verify_findings_dispatch

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

    improve = subparsers.add_parser(
        "improve",
        help="run the bounded self-improvement loop against a benchmark manifest and update the loop-owned ruleset ledger",
    )
    improve.add_argument("manifest", type=Path)
    improve.add_argument("--max-rounds", type=int, default=5)
    improve.add_argument("--recall-floor", type=float, default=RECALL_FLOOR)
    improve.add_argument("--fp-ceiling", type=float, default=FALSE_POSITIVE_CEILING)
    improve.add_argument(
        "--ledger", type=Path, default=None, help="ruleset ledger path (default: <target>/.openultrasast/calibration/rule_policy.json)"
    )
    improve.add_argument("--journal", type=Path, default=None, help="improvement journal path (default: alongside the ledger)")
    improve.add_argument(
        "--ruleset-dir", type=Path, default=DEFAULT_RULESET_DIR, help="ruleset directory to improve (default: the bundled ruleset)"
    )
    improve.add_argument("--dry-run", action="store_true", help="run rounds against a throwaway ledger; never touch the target's ledger")

    subparsers.add_parser("mcp", help="run the narrow MCP server over stdio for OpenCode integration")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.config, args.mode, args.fail_on)
    if args.command == "index":
        return _index(args.path, args.config, args.chunk_lines)
    if args.command == "benchmark":
        return _benchmark(args.manifest, args.config, args.mode)
    if args.command == "improve":
        return _improve(
            args.manifest,
            max_rounds=args.max_rounds,
            recall_floor=args.recall_floor,
            fp_ceiling=args.fp_ceiling,
            ledger=args.ledger,
            journal=args.journal,
            ruleset_dir=args.ruleset_dir,
            dry_run=args.dry_run,
        )
    if args.command == "mcp":
        from .mcp import serve  # lazy: keeps the import cycle (mcp -> cli) one-directional

        return serve()
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
    # Capability gates for the optional HarnessX agentic plane. When the extra is
    # absent (default/CI), both stay False and the deterministic path runs unchanged.
    hunter_model = config.models.hunter
    verifier_model = config.models.verifier
    harnessx_present = has_harnessx()
    hx_hunter = mode == "standard" and bool(hunter_model) and harnessx_present
    hx_verify = mode == "standard" and bool(verifier_model) and harnessx_present
    run = create_scan_run(path, config)
    runtime = HarnessRuntime(
        scan_id=run.scan_id,
        config=config,
        trace_writer=HarnessTraceWriter(run.root / "trace" / "events.jsonl", redact=config.hardening.redact_secrets),
    )
    write_harness_config(config=config, processors=[], contract_mode="strict", path=run.root / "harness.json")
    runtime.start(mode=mode, target=run.target)
    policy = runtime.run_stage("policy_load", load_policy)
    ledger_path = run.target / CALIBRATION_DIR / "false_positive_learnings.json"
    rule_ledger_path = run.target / CALIBRATION_DIR / "rule_policy.json"
    ruleset = runtime.run_stage("ruleset_load", lambda: load_ruleset(DEFAULT_RULESET_DIR, rule_ledger_path))
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
    prior_learnings = load_false_positive_learnings(ledger_path)
    rankings, calibrations = runtime.run_stage("calibrate", lambda: calibrate_rankings(rankings, prior_learnings))
    applied_calibrations = [calibration for calibration in calibrations if calibration.applied_learning_ids]
    write_rankings(rankings, run.root / "rank" / "ranking.json")
    write_ranking_calibrations(calibrations, run.root / "calibration" / "applied_calibrations.json")
    if mode == "standard":
        if hx_hunter and hunter_model:
            orchestrator = HxScanOrchestrator(
                provider_model=hunter_model,
                provider=config.harnessx.provider,
                max_cost_usd=config.harnessx.max_cost_usd,
                token_threshold=config.harnessx.token_threshold,
            )
            hunter_result = runtime.run_stage(
                "hunter_pool",
                lambda: orchestrator.run_pool(
                    run.target, targets, rankings, scan_id=run.scan_id, ruleset=ruleset, policy=policy, emit=runtime.emit
                ),
            )
        else:
            if bool(hunter_model) and not harnessx_present:
                runtime.state["degradations"].append(
                    {"stage": "hunter_pool", "requested": "harnessx", "reason": "harnessx_extra_unavailable", "fallback": "run_hunter_pool"}
                )
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
    # Bounded-CI budget: cap the reported finding count (0 = unlimited). Findings are
    # severity/priority-sorted, so truncation keeps the most severe and is disclosed.
    max_findings = config.hardening.max_findings
    if max_findings and len(findings) > max_findings:
        runtime.state["degradations"].append(
            {"stage": "budget", "reason": "max_findings_exceeded", "requested": max_findings, "actual": len(findings)}
        )
        findings = findings[:max_findings]
    findings_path = run.root / "findings.json"
    verification_path = run.root / "verification.json"
    markdown_path = run.root / "report.md"
    sarif_path = run.root / "report.sarif"
    manifest_path = run.root / "manifest.json"
    trajectories_path = run.root / "traces" / "hunter_trajectories.jsonl"
    write_findings(findings, findings_path)
    if trajectories:
        write_hunter_trajectories(trajectories, trajectories_path)
    if mode == "standard" and bool(verifier_model) and not harnessx_present:
        runtime.state["degradations"].append(
            {"stage": "verify", "requested": "harnessx", "reason": "harnessx_extra_unavailable", "fallback": "structural_verifier"}
        )
    verifications = runtime.run_stage(
        "verify",
        lambda: verify_findings_dispatch(
            findings,
            verifier_model=verifier_model,
            verifier_provider=config.harnessx.provider,
            use_harnessx=hx_verify,
        ),
    )
    write_verification_results(verifications, verification_path)
    runtime.run_stage(
        "record_calibration",
        lambda: _persist_calibration_feedback(run, ledger_path, prior_learnings, findings, verifications),
    )
    # Fusion: two-panel adjudication for triggered findings (standard mode). Runs
    # deterministically by default; routes panels through the configured provider when
    # a panel model is set and the extra is present, else falls back + records a degradation.
    fusion_decisions: list[FusionDecision] = []
    fusion_path = run.root / "fusion.json"
    if mode == "standard" and config.fusion.enabled:
        hx_fusion = bool(config.fusion.panel_model) and harnessx_present
        if bool(config.fusion.panel_model) and not harnessx_present:
            runtime.state["degradations"].append(
                {"stage": "fusion", "requested": "harnessx", "reason": "harnessx_extra_unavailable", "fallback": "deterministic_panels"}
            )
        fusion_decisions = runtime.run_stage(
            "fusion",
            lambda: fuse_findings_dispatch(
                findings,
                verifications,
                panel_model=config.fusion.panel_model,
                decider_model=config.fusion.decider_model,
                provider=config.harnessx.provider,
                use_harnessx=hx_fusion,
                high_assurance=config.fusion.high_assurance,
            ),
        )
        if fusion_decisions:
            fusion_path.write_text(json.dumps([decision.to_dict() for decision in fusion_decisions], indent=2, sort_keys=True) + "\n")
    cwe_by_rule = {rule.rule_id: rule.cwe for rule in ruleset}
    rule_cwe_by_id = {finding.finding_id: cwe_by_rule.get(finding.finding_id.split(":", 1)[0], "") for finding in findings}
    # A confirmed false positive (prior-scan learning) lowers a finding's effective
    # reachability multiplier in the score instead of deleting the rule.
    reachability_override = fp_reachability_overrides(findings, prior_learnings)
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
            reachability_override=reachability_override,
        ),
    )
    score_path = run.root / "score.json"
    score_path.write_text(json.dumps(score_artifact.to_dict(), indent=2, sort_keys=True) + "\n")
    runtime.run_stage(
        "report", lambda: write_markdown_report(findings, markdown_path, verifications, redact=config.hardening.redact_secrets)
    )
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
                fusion=fusion_path if fusion_decisions else None,
            ),
            path=manifest_path,
            score=score_artifact.to_dict(),
            degradations=runtime.state["degradations"] or None,
            fusion=[_fusion_summary(decision) for decision in fusion_decisions] or None,
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


def _fusion_summary(decision: FusionDecision) -> dict[str, object]:
    return {
        "finding_id": decision.finding_id,
        "disposition": str(decision.disposition),
        "decision_source": decision.decision_source,
        "triggers": decision.triggers,
    }


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


def _improve(
    manifest_path: Path,
    *,
    max_rounds: int,
    recall_floor: float,
    fp_ceiling: float,
    ledger: Path | None,
    journal: Path | None,
    ruleset_dir: Path,
    dry_run: bool,
) -> int:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise SystemExit(f"benchmark manifest is not a file: {manifest_path}")
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    policy = load_policy()

    # The loop writes its accepted ledger where `scan`/`benchmark` read it, so a
    # subsequent scan of this target automatically picks up the improved ruleset.
    default_ledger = target / CALIBRATION_DIR / "rule_policy.json"
    with tempfile.TemporaryDirectory(prefix="ousast-improve-") as scratch:
        if dry_run:
            ledger_path = Path(scratch) / "rule_policy.json"
            journal_path = Path(scratch) / "improve_journal.json"
        else:
            ledger_path = ledger or default_ledger
            journal_path = journal or ledger_path.with_name("improve_journal.json")

        outcomes = run_improvement(
            target,
            manifest,
            ledger_path=ledger_path,
            journal_path=journal_path,
            ruleset_dir=ruleset_dir,
            policy=policy,
            max_rounds=max_rounds,
            recall_floor=recall_floor,
            fp_ceiling=fp_ceiling,
        )
        _print_improve_outcomes(outcomes, manifest_path, target, ledger_path, dry_run=dry_run)
    return 0


def _print_improve_outcomes(outcomes: list[RoundOutcome], manifest_path: Path, target: Path, ledger_path: Path, *, dry_run: bool) -> None:
    print(f"manifest={manifest_path}")
    print(f"target={target}")
    accepted = [o for o in outcomes if o.accepted]
    for outcome in outcomes:
        edits = ", ".join(f"{e.rule_id}:{e.from_status}->{e.to_status}" for e in outcome.edits) or "-"
        print(
            f"round {outcome.round}: {outcome.reason} | "
            f"recall {outcome.recall_before:.2%}->{outcome.recall_after:.2%} "
            f"fp {outcome.fp_before:.2%}->{outcome.fp_after:.2%} "
            f"score {outcome.score_before}->{outcome.score_after} | edits: {edits}"
        )
    print(f"rounds={len(outcomes)} accepted={len(accepted)}")
    if dry_run:
        print("dry_run=true (no ledger written)")
    elif accepted:
        print(f"ledger={ledger_path}")
    else:
        print("ledger=unchanged (no round accepted)")


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
