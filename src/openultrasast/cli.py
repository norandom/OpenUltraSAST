from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter

from . import tool_hunter
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
from .complexity import map as complexity_map
from .complexity.ledger import persist_verdicts
from .config import load_config, load_dotenv
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
from .pair_gate import print_pair_metrics
from .pairs import (
    DEFAULT_CATALOG,
    SLICE_NAMES,
    evaluate_catalog,
    load_pair_catalog,
    make_hunter_scan,
    result_payload,
    select_profile,
    select_slice,
    select_split,
)
from .policy import assert_rules_resolve, load_policy
from .preprocess import preprocess_repository, write_preprocess_artifact
from .provenance import fingerprint
from .provider.openrouter import OpenRouterEmbeddingClient, OpenRouterError
from .rank import rank_targets, write_rankings
from .regress import TRIGGERABLE, CandidateVerdict, run_regression, write_verdicts
from .reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from .ruleset import DEFAULT_RULESET_DIR, load_ruleset
from .run import ScanRun, create_scan_run
from .sandbox import resolve_sandbox_probe, resolve_sandbox_runner
from .scoring import build_score_artifact
from .semantic import (
    MechanismStore,
    OverlayRecord,
    adjudicate,
    append_mechanism,
    filter_promoted_hotspots,
    finding_from_coverage,
    load_facts,
    order_promotions,
    write_overlay,
)
from .semantic.facts import FactLoadError, SemanticFacts
from .stages import Stage, plan_for_mode, record_completed, record_skip, skip_as_degradation, stages_payload
from .verification import VerificationResult, verify_findings, write_verification_results
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
    load_dotenv()
    parser = argparse.ArgumentParser(prog="ousast")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("quick", "standard", "deep"), default="quick")
    scan.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    scan.add_argument("--fail-on", choices=("never", "findings", "verified", "worth-fixing"), default="never")

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
    improve.add_argument(
        "--pair-catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help="pair catalog whose holdout split gates every round per provenance profile",
    )
    improve.add_argument(
        "--no-pair-gate", action="store_true", help="skip the per-profile holdout clause (faster; not for accepted ledgers)"
    )
    improve.add_argument(
        "--profile-tolerance", type=float, default=0.0, help="allowed per-profile drop in pair_correct/Youden before rejecting"
    )
    improve.add_argument("--min-holdout-pairs", type=int, default=5, help="profiles with fewer holdout pairs are reported, not gated")

    pairs = subparsers.add_parser(
        "pairs",
        help="scan isolated vuln-vs-fixed pairs (TP on vuln, silent on fix) and emit improve-loop signals",
    )
    pairs.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    pairs.add_argument("--slice", choices=SLICE_NAMES, default="all")
    pairs.add_argument(
        "--profile", choices=("all", "human", "agent", "mixed", "synthetic"), default="all", help="filter pairs by provenance profile"
    )
    pairs.add_argument("--split", choices=("all", "train", "holdout"), default="all", help="filter pairs by declared split")
    pairs.add_argument("--hunter", action="store_true", help="also score the LLM tool hunter on overlay slices (needs a hunter model)")
    pairs.add_argument("--hunter-model", default=None, help="model id for --hunter (default: [models].hunter from openultrasast.toml)")
    pairs.add_argument("--json", action="store_true", help="print the pair scoreboard as JSON")

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
            pair_catalog=None if args.no_pair_gate else args.pair_catalog,
            profile_tolerance=args.profile_tolerance,
            min_holdout_pairs=args.min_holdout_pairs,
        )
    if args.command == "pairs":
        return _pairs(
            args.catalog,
            args.slice,
            json_out=args.json,
            profile=args.profile,
            split=args.split,
            hunter=args.hunter,
            hunter_model=args.hunter_model,
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
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"scan path is not a directory: {path}")

    plan = plan_for_mode(mode)
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
    provenance = runtime.run_stage("provenance", lambda: fingerprint(run.target))
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
    plan = record_completed(plan, Stage.STATIC)
    complexity_payload: dict[str, object] | None = None
    complexity_map_path = run.root / "complexity_map.json"
    overlay_path = run.root / "overlay.json"
    built_map = None
    overlay_records: list[OverlayRecord] = []
    wrote_overlay = False
    if Stage.MAP in plan.requested:
        built_map = runtime.run_stage(
            "map",
            lambda: complexity_map.build_complexity_map(
                targets,
                findings,
                complexity_map_path,
                repo_files=[target.path for target in targets],
                ledger_path=run.target / CALIBRATION_DIR / "complexity_ledger.json",
            ),
        )
        facts_or_error: SemanticFacts | FactLoadError
        try:
            facts_or_error = load_facts()
        except FactLoadError as exc:
            facts_or_error = exc
            runtime.state["degradations"].append({"stage": "overlay", "reason": "facts_unavailable", "detail": str(exc)})
        overlay_records = list(
            runtime.run_stage(
                "overlay",
                lambda: adjudicate(root=run.target, targets=targets, findings=findings, facts=facts_or_error),
            )
        )
        write_overlay(overlay_records, overlay_path)
        wrote_overlay = True
        coverage_findings = [finding_from_coverage(record) for record in overlay_records if record.disposition == "coverage"]
        if coverage_findings:
            seen = {finding.finding_id for finding in findings}
            extra = [item for item in coverage_findings if item.finding_id not in seen]
            if extra:
                findings = findings + extra
                write_findings(findings, findings_path)
        plan = record_completed(plan, Stage.MAP)
        if not hunter_model:
            runtime.state["degradations"].append(skip_as_degradation(Stage.MAP, "hunter_model_unavailable"))
        else:
            built_map, findings, verifications = _attach_tool_hunter(
                root=run.target,
                built_map=built_map,
                findings=findings,
                verifications=verifications,
                hunter_model=hunter_model,
                max_hotspots=config.complexity.max_hunter_hotspots,
                max_findings=max_findings,
                findings_path=findings_path,
                verification_path=verification_path,
                complexity_map_path=complexity_map_path,
                runtime=runtime,
            )
        complexity_payload = {
            "hotspot_count": len(built_map.hotspots),
            "heuristic_only": built_map.heuristic_only,
        }
    verdicts_path = run.root / "verdicts.json"
    wrote_verdicts = False
    verdict_records: tuple[CandidateVerdict, ...] = ()
    if Stage.REGRESS in plan.requested:
        probe = resolve_sandbox_probe()
        if not probe.available():
            plan = record_skip(plan, Stage.REGRESS, "sandbox_unavailable")
            runtime.state["degradations"].append(skip_as_degradation(Stage.REGRESS, "sandbox_unavailable"))
        else:
            sandbox = resolve_sandbox_runner()
            hotspots = built_map.hotspots if built_map is not None else ()
            hotspots = filter_promoted_hotspots(hotspots, overlay_records, findings)
            store = MechanismStore(run.target / CALIBRATION_DIR / "mechanisms.jsonl")
            embed_client = None
            embed_model = config.embeddings.model
            if embed_model:
                try:
                    embed_client = OpenRouterEmbeddingClient.from_env()
                except OpenRouterError:
                    embed_client = None
            hotspots, budget_degradation = order_promotions(
                hotspots,
                overlay_records,
                findings,
                store=store,
                client=embed_client,
                model=embed_model,
            )
            if budget_degradation:
                runtime.state["degradations"].append({"stage": "prove_budget", "reason": budget_degradation})
            promoted = [
                finding
                for finding in findings
                if finding.finding_id in {record.proposal_id for record in overlay_records if record.disposition == "promote"}
            ]
            cwe_by_rule_id = {rule.rule_id: rule.cwe for rule in ruleset}
            rule_cwe_by_finding = {finding.finding_id: cwe_by_rule_id.get(finding.finding_id.split(":", 1)[0], "") for finding in promoted}
            languages_by_path = {target.path: target.language for target in targets}
            records = runtime.run_stage(
                "regress",
                lambda: run_regression(
                    hotspots,
                    promoted,
                    max_candidates=config.regress.max_candidates,
                    policy=policy,
                    rule_cwe=rule_cwe_by_finding,
                    languages_by_path=languages_by_path,
                    repo_root=run.target,
                    sandbox=sandbox,
                    sandbox_limits=config.sandbox,
                    images=dict(config.regress.images),
                ),
            )
            write_verdicts(records, verdicts_path)
            persist_verdicts(run.target / CALIBRATION_DIR / "complexity_ledger.json", records)
            _append_proven_mechanisms(store, records, overlay_records, findings, run.target)
            verdict_records = records
            wrote_verdicts = True
            plan = record_completed(plan, Stage.REGRESS)
    worth_fixing_payload = _worth_fixing_payload(verdict_records) if wrote_verdicts else None
    runtime.run_stage(
        "report",
        lambda: write_markdown_report(
            findings,
            markdown_path,
            verifications,
            redact=config.hardening.redact_secrets,
            complexity_map=built_map,
            verdicts=verdict_records if wrote_verdicts else None,
            overlay=overlay_records if wrote_overlay else None,
        ),
    )
    runtime.run_stage(
        "sarif",
        lambda: write_sarif_report(
            findings,
            verifications,
            sarif_path,
            overlay=overlay_records if wrote_overlay else None,
        ),
    )
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
                complexity_map=complexity_map_path if complexity_payload is not None else None,
                overlay=overlay_path if wrote_overlay else None,
                verdicts=verdicts_path if wrote_verdicts else None,
            ),
            path=manifest_path,
            score=score_artifact.to_dict(),
            degradations=runtime.state["degradations"] or None,
            fusion=[_fusion_summary(decision) for decision in fusion_decisions] or None,
            stages=stages_payload(plan),
            complexity=complexity_payload,
            worth_fixing=worth_fixing_payload,
            provenance=provenance.to_dict(),
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
        exit_code=scan_exit_code(findings, verifications, fail_on, worth_fixing_verdicts=verdict_records),
    )


def _append_proven_mechanisms(
    store: MechanismStore,
    verdicts: tuple[CandidateVerdict, ...],
    overlay_records: list[OverlayRecord],
    findings: list[StaticFinding],
    target: Path,
) -> None:
    overlay_by_id = {record.proposal_id: record for record in overlay_records}
    finding_by_id = {finding.finding_id: finding for finding in findings}
    for verdict in verdicts:
        if verdict.verdict != TRIGGERABLE:
            continue
        for finding_id in verdict.inventory_finding_ids:
            record = overlay_by_id.get(finding_id)
            if record is None or record.disposition != "promote":
                continue
            finding = finding_by_id.get(finding_id)
            append_mechanism(
                store,
                summary=record.reason,
                cwe=record.cwe,
                language=record.language or verdict.language,
                tags=finding.tags if finding is not None else (),
                what_made_it_exploitable=record.reason,
                source_finding_id=finding_id,
                source_repo=str(target),
            )


def _attach_tool_hunter(
    *,
    root: Path,
    built_map: complexity_map.ComplexityMap,
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    hunter_model: str,
    max_hotspots: int,
    max_findings: int,
    findings_path: Path,
    verification_path: Path,
    complexity_map_path: Path,
    runtime: HarnessRuntime,
) -> tuple[complexity_map.ComplexityMap, list[StaticFinding], list[VerificationResult]]:
    client = tool_hunter.resolve_hunter_client()
    if client is None:
        return built_map, findings, verifications
    hunter_hotspots = list(built_map.hotspots[: max(max_hotspots, 0)])
    hunter_findings = runtime.run_stage(
        "tool_hunter",
        lambda: tool_hunter.run_tool_hunter(
            root,
            hunter_hotspots,
            client=client,
            model=hunter_model,
            max_steps=tool_hunter.DEFAULT_MAX_STEPS,
        ),
    )
    seen = {finding.finding_id for finding in findings}
    extra = [finding for finding in hunter_findings if finding.finding_id not in seen]
    if extra:
        findings = findings + extra
        if max_findings and len(findings) > max_findings:
            if not any(entry.get("reason") == "max_findings_exceeded" for entry in runtime.state["degradations"]):
                runtime.state["degradations"].append(
                    {"stage": "budget", "reason": "max_findings_exceeded", "requested": max_findings, "actual": len(findings)}
                )
            findings = findings[:max_findings]
            kept = {finding.finding_id for finding in findings}
            extra = [finding for finding in extra if finding.finding_id in kept]
        if extra:
            verifications = verifications + verify_findings(extra)
            write_verification_results(verifications, verification_path)
    write_findings(findings, findings_path)
    built_map = replace(built_map, heuristic_only=False)
    complexity_map.write_complexity_map(built_map, complexity_map_path)
    return built_map, findings, verifications


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


def _worth_fixing_payload(verdicts: tuple[CandidateVerdict, ...]) -> dict[str, object]:
    worth = [record for record in verdicts if record.worth_fixing]
    return {
        "count": len(worth),
        "verdicts": [
            {
                "path": record.path,
                "function_name": record.function_name,
                "verdict": record.verdict,
                "reason": record.reason,
                "worth_fixing": True,
            }
            for record in worth
        ],
    }


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
    pair_catalog: Path | None = None,
    profile_tolerance: float = 0.0,
    min_holdout_pairs: int = 5,
) -> int:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise SystemExit(f"benchmark manifest is not a file: {manifest_path}")
    pair_cases: tuple[object, ...] = ()
    if pair_catalog is not None:
        if not pair_catalog.is_file():
            raise SystemExit(f"pair catalog is not a file: {pair_catalog} (pass --no-pair-gate to skip the per-profile holdout clause)")
        pair_cases = select_split(load_pair_catalog(pair_catalog), "holdout")
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
            pair_cases=pair_cases,
            profile_tolerance=profile_tolerance,
            min_holdout_pairs=min_holdout_pairs,
        )
        _print_improve_outcomes(outcomes, manifest_path, target, ledger_path, dry_run=dry_run)
    return 0


def _pairs(
    catalog: Path,
    slice_name: str,
    *,
    json_out: bool,
    profile: str = "all",
    split: str = "all",
    hunter: bool = False,
    hunter_model: str | None = None,
) -> int:
    if not catalog.exists() or not catalog.is_file():
        raise SystemExit(f"pair catalog is not a file: {catalog}")
    cases = select_split(select_profile(select_slice(load_pair_catalog(catalog), slice_name), profile), split)
    scan = None
    if hunter:
        config_path = Path("openultrasast.toml")
        config = load_config(config_path if config_path.exists() else None)
        model = hunter_model or config.models.hunter or ""
        client = tool_hunter.resolve_hunter_client()
        if model and client is not None:
            scan = make_hunter_scan(client, model)
    result = evaluate_catalog(cases, hunter=scan)
    if json_out:
        print(json.dumps(result_payload(result), indent=2, sort_keys=True))
        return 0
    print_pair_metrics("pair eval", result)
    print(f"signals={len(result.signals)}")
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
        if outcome.profile_regressions or outcome.profiles_under_minimum:
            print(f"  profiles: regressed={outcome.profile_regressions or '-'} under_minimum={outcome.profiles_under_minimum or '-'}")
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
