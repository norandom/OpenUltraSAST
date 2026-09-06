from __future__ import annotations

import argparse
import json
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Any

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
from .complexity.map import Hotspot
from .config import ObligationsConfig, load_config, load_dotenv
from .findings import StaticFinding, quick_scan_findings, write_findings
from .fusion import FusionDecision, fuse_findings_dispatch
from .gate import FALSE_POSITIVE_CEILING, RECALL_FLOOR
from .harness import HarnessRuntime, HarnessTraceWriter, write_harness_config
from .harness_ext import has_harnessx
from .hunter import run_hunter_pool, write_hunter_trajectories
from .hunter_harness import HxScanOrchestrator
from .improve import RoundOutcome, run_improvement
from .index import build_code_chunks
from .learning.families import FamilyTaxonomy
from .mapping import analyze_entry_points, attach_reachability_hints, ingest_sarif, write_entry_points, write_static_hints
from .pair_gate import print_pair_metrics
from .pairs import (
    DEFAULT_CATALOG,
    SLICE_NAMES,
    PairCase,
    evaluate_catalog,
    load_pair_catalog,
    make_hunter_scan,
    result_payload,
    select_profile,
    select_slice,
    select_split,
    select_vendored,
)
from .policy import assert_rules_resolve, load_policy
from .preprocess import FileTarget, preprocess_repository, write_preprocess_artifact
from .provenance import fingerprint
from .provider.openrouter import OpenRouterEmbeddingClient, OpenRouterError
from .rank import rank_obligations, rank_targets, write_rankings
from .regress import TRIGGERABLE, CandidateVerdict, run_regression, write_verdicts
from .regress.candidate import hotspot_from_finding
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


if TYPE_CHECKING:
    from .learning.proposer import Proposer


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
    improve.add_argument(
        "--mechanism-candidates",
        type=Path,
        default=None,
        help=(
            "exporter candidates the mechanisms lever may admit (default: <target>/.openultrasast/calibration/"
            "mechanism-candidates.jsonl, then ./.openultrasast/calibration/mechanism-candidates.jsonl)"
        ),
    )
    improve.add_argument(
        "--mechanism-store",
        type=Path,
        default=None,
        help="scan-time mechanisms.jsonl the lever writes (default: <target>/.openultrasast/calibration/mechanisms.jsonl)",
    )
    improve.add_argument("--no-mechanisms", action="store_true", help="disable the mechanisms lever for this run")

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
    pairs.add_argument("--pointers", action="store_true", help="allow network for non-vendored pointer pairs this run (nightly; CI never)")
    pairs.add_argument(
        "--loo", action="store_true", help="leave-one-out: score each pair against a store seeded from the other trusted pairs"
    )
    pairs.add_argument("--loo-out", type=Path, default=None, help="where to write loo.json (default: reports/loo.json)")
    pairs.add_argument("--json", action="store_true", help="print the pair scoreboard as JSON")
    pairs.add_argument("--k-runs", type=int, default=1, help="runs per pair on the hunter path; the family scorer needs at least three")

    subparsers.add_parser("mcp", help="run the narrow MCP server over stdio for OpenCode integration")
    mechanisms = subparsers.add_parser("mechanisms", help="maintainer: mechanism memory seeded from trusted pairs")
    mechanisms_sub = mechanisms.add_subparsers(dest="mechanisms_command", required=True)
    export = mechanisms_sub.add_parser("export", help="derive mechanism records from seeded/reviewed pairs (offline)")
    export.add_argument("--slice", choices=SLICE_NAMES, default="all")
    export.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    export.add_argument(
        "--store",
        type=Path,
        default=Path(CALIBRATION_DIR) / "mechanism-candidates.jsonl",
        help="append-only candidates file the improve lever admits from (the scan reads mechanisms.jsonl next to it; never written here)",
    )
    export.add_argument("--json", action="store_true")

    learning = subparsers.add_parser("learning", help="maintainer: the classified detector set and its rounds")
    learning_sub = learning.add_subparsers(dest="learning_command", required=True)
    for name, help_text in (
        ("classify", "classify every labeled pair and report the classifier against itself"),
        ("score", "score a catalog by family, with the denominator every number was computed over"),
        ("baseline", "round zero: clone one detector into every family and measure each against itself"),
        ("round", "one evolve round: propose one change for one family and let the evidence decide"),
        ("publish", "regenerate every published number from the artifacts that produced it"),
    ):
        command = learning_sub.add_parser(name, help=help_text)
        command.add_argument("--out", type=Path, default=Path(".openultrasast/learning"), help="where artifacts are read and written")
        if name != "publish":
            command.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
            command.add_argument("--slice", choices=SLICE_NAMES, default="all")
            command.add_argument("--json", action="store_true")
        if name in {"baseline", "round", "score"}:
            command.add_argument("--k-runs", type=int, default=None, help="runs per pair; never fewer than three")
            command.add_argument("--model", default=None, help="detector model; artifacts are keyed by it")
            command.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
        if name == "round":
            command.add_argument("--family", required=True)
            command.add_argument("--cost-cap-usd", type=float, default=None)
            command.add_argument(
                "--proposals",
                type=Path,
                default=None,
                help="a JSON list of proposals to try in order; without it the round asks the meta-agent",
            )
        if name == "publish":
            command.add_argument("--measurements", type=Path, default=Path("benchmarks/measurements"))
            command.add_argument("--roadmap", type=Path, default=Path(".kiro/steering/roadmap.md"))

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
            mechanism_candidates=args.mechanism_candidates,
            mechanism_store=args.mechanism_store,
            mechanisms_enabled=not args.no_mechanisms,
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
            pointers=args.pointers,
            loo=args.loo,
            loo_out=args.loo_out,
            k_runs=args.k_runs,
        )
    if args.command == "mechanisms":
        return _mechanisms_export(args.catalog, args.slice, args.store, json_out=args.json)
    if args.command == "learning":
        return _learning(args)
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
    variants_payload: dict[str, object] | None = None
    variant_findings: list[StaticFinding] = []
    mechanisms_cited: dict[str, dict[str, object]] = {}
    obligations_payload: dict[str, object] | None = None
    learning_payload: dict[str, object] | None = None
    learning_cited: dict[str, dict[str, object]] = {}
    obligations_cited: dict[str, dict[str, object]] = {}
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
        if config.variants.enabled:
            variant_findings, overlay_records, variants_payload, mechanisms_cited = _search_variants(
                root=run.target,
                targets=targets,
                overlay_records=overlay_records,
                facts=facts_or_error,
                max_mechanisms=config.variants.max_mechanisms,
                runtime=runtime,
            )
            if variant_findings:
                findings = findings + variant_findings
                write_findings(findings, findings_path)
            write_overlay(overlay_records, overlay_path)
        if config.obligations.enabled:
            obligation_findings, obligations_payload, obligations_cited = _check_obligations(
                root=run.target,
                targets=targets,
                entries=entry_points,
                facts=facts_or_error,
                settings=config.obligations,
                runtime=runtime,
                hunter_model=hunter_model,
            )
            if obligation_findings:
                findings = rank_obligations(findings + obligation_findings)
                write_findings(findings, findings_path)
        if config.learning.enabled:
            family_findings, learning_payload, learning_cited = _run_family_detectors(
                root=run.target,
                hotspots=built_map.hotspots if built_map is not None else (),
                cases=None,
                settings=config.learning,
                config=config,
                runtime=runtime,
            )
            if family_findings:
                findings = findings + family_findings
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
            # Variant findings are candidates after the promotions (Req 3.4): same safety check, same cap, lowest rank.
            variant_ids = {finding.finding_id for finding in variant_findings}
            promoted = promoted + [finding for finding in findings if finding.finding_id in variant_ids]
            hotspots = hotspots + tuple(_hotspot_from_variant(finding) for finding in findings if finding.finding_id in variant_ids)
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
            # Req 6.4: proof rungs live on verdicts, not on StaticFinding, so obligations re-rank once the sandbox has spoken.
            proven_ids = {fid for record in records if record.verdict == TRIGGERABLE for fid in record.inventory_finding_ids}
            if proven_ids and any(finding.finding_id.startswith("obligation:") for finding in findings):
                findings = rank_obligations(findings, proven_ids=proven_ids)
                write_findings(findings, findings_path)
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
            mechanisms=mechanisms_cited or None,
            obligations=obligations_cited or None,
            obligations_summary=obligations_payload or None,
            learning=learning_cited or None,
        ),
    )
    runtime.run_stage(
        "sarif",
        lambda: write_sarif_report(
            findings,
            verifications,
            sarif_path,
            overlay=overlay_records if wrote_overlay else None,
            mechanisms=mechanisms_cited or None,
            obligations=obligations_cited or None,
            learning=learning_cited or None,
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
            variants=variants_payload,
            obligations=obligations_payload,
            learning=learning_payload,
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
    mechanism_candidates: Path | None = None,
    mechanism_store: Path | None = None,
    mechanisms_enabled: bool = True,
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
    # corpus-seeded-mechanisms Req 5: the lever runs when a candidates file exists (exporter output) and the pair gate is on.
    # Candidates: an explicit path, else the target's calibration dir, else the working directory's (where `mechanisms export`
    # writes by default). The store always lives where a scan of this target reads it unless overridden.
    calibration = target / CALIBRATION_DIR
    candidates_path: Path | None = mechanism_candidates
    if candidates_path is None:
        for candidate in (calibration / "mechanism-candidates.jsonl", Path(CALIBRATION_DIR) / "mechanism-candidates.jsonl"):
            if candidate.is_file():
                candidates_path = candidate
                break
    if not mechanisms_enabled or not pair_cases or candidates_path is None or not candidates_path.is_file():
        candidates_path = None
    store_path = mechanism_store if mechanism_store is not None else calibration / "mechanisms.jsonl"
    policy = load_policy()

    # The loop writes its accepted ledger where `scan`/`benchmark` read it, so a
    # subsequent scan of this target automatically picks up the improved ruleset.
    default_ledger = target / CALIBRATION_DIR / "rule_policy.json"
    with tempfile.TemporaryDirectory(prefix="ousast-improve-") as scratch:
        if dry_run:
            ledger_path = Path(scratch) / "rule_policy.json"
            journal_path = Path(scratch) / "improve_journal.json"
            if candidates_path is not None:  # a dry run must not mutate the scan-time store either
                scratch_store = Path(scratch) / "mechanisms.jsonl"
                if store_path.is_file():
                    scratch_store.write_bytes(store_path.read_bytes())
                store_path = scratch_store
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
            mechanism_candidates=candidates_path,
            mechanism_store=store_path if candidates_path is not None else None,
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
    pointers: bool = False,
    loo: bool = False,
    loo_out: Path | None = None,
    k_runs: int | None = None,
) -> int:
    if not catalog.exists() or not catalog.is_file():
        raise SystemExit(f"pair catalog is not a file: {catalog}")
    cases = select_split(select_profile(select_slice(load_pair_catalog(catalog), slice_name), profile), split)
    if loo:
        return _pairs_loo(cases, loo_out or Path("reports") / "loo.json", json_out=json_out)
    scan = None
    if hunter:
        config_path = Path("openultrasast.toml")
        config = load_config(config_path if config_path.exists() else None)
        model = hunter_model or config.models.hunter or ""
        client = tool_hunter.resolve_hunter_client()
        if model and client is not None:
            from .learning.families import load_families

            scan = make_hunter_scan(client, model, taxonomy=load_families())
    result = evaluate_catalog(cases, hunter=scan, pointers=True if pointers else None, k_runs=k_runs)
    if json_out:
        print(json.dumps(result_payload(result), indent=2, sort_keys=True))
        return 0
    print_pair_metrics("pair eval", result)
    print(f"signals={len(result.signals)}")
    return 0


def _search_variants(
    *,
    root: Path,
    targets: list[FileTarget],
    overlay_records: list[OverlayRecord],
    facts: SemanticFacts | FactLoadError,
    max_mechanisms: int,
    runtime: HarnessRuntime,
) -> tuple[list[StaticFinding], list[OverlayRecord], dict[str, object], dict[str, dict[str, object]]]:
    """Third MAP proposer (corpus-seeded-mechanisms Req 3): shapes from the mechanism store, merged with overlay flows.

    Also returns the mechanisms the findings cite (summary, guard, pairs, cwe) for the reports (Req 6.1).
    """
    from .semantic.mechanisms import corpus_mechanisms
    from .semantic.variant_search import hits_to_findings, search_tree

    store = MechanismStore(root / CALIBRATION_DIR / "mechanisms.jsonl")
    empty: dict[str, object] = {"mechanisms_searched": 0, "files_searched": 0, "findings": 0, "merged_into_overlay": 0}
    if isinstance(facts, FactLoadError):
        return [], overlay_records, empty, {}
    result = runtime.run_stage("variants", lambda: search_tree(root, targets, store, facts, max_mechanisms=max_mechanisms))
    for degradation in result.degradations:
        runtime.state["degradations"].append(degradation)
    records_by_id = {record.id: record for record in corpus_mechanisms(store.load())}
    summaries = {record.id: (record.summary, record.pairs, record.cwe) for record in records_by_id.values()}
    findings, records = hits_to_findings(result.hits, overlay_records, summaries)
    merged = sum(1 for before, after in zip(overlay_records, records, strict=True) if before.mechanism_id is None and after.mechanism_id)
    payload: dict[str, object] = {
        "mechanisms_searched": result.mechanisms_searched,
        "files_searched": result.files_searched,
        "findings": len(findings),
        "merged_into_overlay": merged,
    }
    cited_ids = {tag.split(":", 1)[1] for finding in findings for tag in finding.tags if tag.startswith("mechanism:")} | {
        str(record.mechanism_id) for record in records if record.mechanism_id
    }
    cited: dict[str, dict[str, object]] = {
        mechanism_id: {"summary": record.summary, "guard": record.guard, "pairs": list(record.pairs), "cwe": record.cwe}
        for mechanism_id, record in records_by_id.items()
        if mechanism_id in cited_ids
    }
    return findings, records, payload, cited


def _check_obligations(
    *,
    root: Path,
    targets: list[FileTarget],
    entries: Sequence[object],
    facts: SemanticFacts | FactLoadError,
    settings: ObligationsConfig,
    runtime: HarnessRuntime,
    hunter_model: str | None = None,
) -> tuple[list[StaticFinding], dict[str, object], dict[str, dict[str, object]]]:
    """Fourth MAP proposer (authorization-obligations Req 3-6): obligations without a dominating discharger, at suspicion.

    Function-local until path records exist; the declared policy is read from the target; obligation findings never
    enter the sandbox candidate set.
    """
    from .semantic.ir import parse_file
    from .semantic.obligations import load_obligation_facts, obligation_mechanisms
    from .semantic.obligations.check import check_obligations, findings_to_static
    from .semantic.obligations.dominance import OrderDominance
    from .semantic.obligations.policy import PolicyError, load_declared_policy

    payload: dict[str, object] = {"sibling_sets": 0, "under_populated": 0, "operations": 0, "findings_by_label": {}, "policy_version": None}
    if isinstance(facts, FactLoadError):
        runtime.state["degradations"].append({"stage": "obligations", "reason": "facts_unavailable"})
        return [], payload, {}
    irs: dict[str, tuple[Any, str]] = {}
    texts: dict[str, str] = {}
    for target in targets:
        try:
            text = (root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        texts[target.path] = text
        irs[target.path] = (parse_file(target.path, text, target.language), text)
    policy = None
    policy_path = root / settings.policy_path
    try:
        policy = load_declared_policy(policy_path)
    except PolicyError as exc:
        runtime.state["degradations"].append({"stage": "obligations", "reason": "policy_invalid", "detail": str(exc)[:200]})
    store = MechanismStore(root / CALIBRATION_DIR / "mechanisms.jsonl")
    result = runtime.run_stage(
        "obligations",
        lambda: check_obligations(
            irs=irs,
            entries=entries,
            facts=load_obligation_facts(),
            flow_facts=facts,
            policy=policy,
            paths=(),
            dominance=OrderDominance(texts=texts),
            store_shapes=obligation_mechanisms(store.load()),
            min_siblings=settings.min_siblings,
        ),
    )
    from .semantic.obligations.intent import adjudicate_intent

    result = adjudicate_intent(result, client=tool_hunter.resolve_hunter_client(), model=hunter_model or "", texts=texts)
    for degradation in result.degradations:
        runtime.state["degradations"].append(degradation)
    by_label: dict[str, int] = {}
    for finding in result.findings:
        by_label[finding.label] = by_label.get(finding.label, 0) + 1
    payload = {
        "sibling_sets": len(result.sibling_sets),
        "under_populated": len(result.under_populated),
        "operations": result.operations,
        "findings_by_label": by_label,
        "policy_version": result.policy_version,
        "degradations": [dict(item) for item in result.degradations],
        "sets": [{"module": group.key[0], "resource": group.key[1], "handlers": len(group.handlers)} for group in result.sibling_sets],
    }
    statics = findings_to_static(result)
    cited: dict[str, dict[str, object]] = {}
    for finding, static in zip(result.findings, statics, strict=True):
        cited[static.finding_id] = {
            "obligation": finding.operation.kind,
            "resource": finding.operation.resource,
            "missing": finding.missing,
            "provenance": finding.provenance,
            "label": finding.label,
            "evidence": list(finding.evidence),
            "known_fix": finding.known_fix,
            "intent": finding.intent,
            "intent_rationale": finding.intent_rationale,
        }
    return statics, payload, cited


def _run_family_detectors(
    *,
    root: Path,
    hotspots: Sequence[object],
    cases: object,
    settings: object,
    config: object,
    runtime: HarnessRuntime,
) -> tuple[list[StaticFinding], dict[str, object], dict[str, dict[str, object]]]:
    """Fifth MAP proposer (learning-harness Req 6.3, 7.1): one detector per admitted family, plus the generalist.

    Every claim passes through its family's verifier and carries what produced it. Nothing rises above
    suspicion here: the verifier writes a tag, and the evidence ladder is another boundary's to move.
    """
    del cases
    from .learning.classify import classify_region
    from .learning.detectors import DetectorConfigError, Region, load_family_configs, run_region_detectors
    from .learning.endpoint import resolve_chat_endpoint, resolve_models
    from .learning.families import FamiliesError, load_families
    from .learning.verifiers import apply_verification, verifier_for

    empty: dict[str, dict[str, object]] = {}
    configs_dir = root / str(getattr(settings, "configs_dir", ".openultrasast/learning/configs"))
    try:
        taxonomy = load_families(Path(p) if (p := getattr(settings, "families_path", None)) else None)
        configs = load_family_configs(configs_dir, taxonomy)
    except (FamiliesError, DetectorConfigError) as exc:
        runtime.state["degradations"].append({"stage": "learning", "reason": "learning_configs_unavailable", "detail": str(exc)[:200]})
        return [], {}, empty
    if not configs:
        runtime.state["degradations"].append(
            {"stage": "learning", "reason": "learning_configs_unavailable", "detail": f"no family configurations under {configs_dir}"}
        )
        return [], {}, empty
    resolved = resolve_chat_endpoint(config)  # type: ignore[arg-type]
    if resolved is None:
        runtime.state["degradations"].append({"stage": "learning", "reason": "learning_endpoint_unavailable"})
        return [], {}, empty
    client, endpoint = resolved
    model = resolve_models(config)[0]  # type: ignore[arg-type]
    findings: list[StaticFinding] = []
    per_family: dict[str, int] = {}
    per_tier: dict[str, int] = {}
    abstained = 0
    seen: set[str] = set()
    for hotspot in hotspots:
        path = str(getattr(hotspot, "path", ""))
        function = getattr(hotspot, "function_name", None)
        key = f"{path}::{function}"
        if not path or key in seen:
            continue
        seen.add(key)
        answer = classify_region(root, path, function=function, taxonomy=taxonomy, client=None)
        per_tier[answer.tier] = per_tier.get(answer.tier, 0) + 1
        abstained += 0 if answer.families else 1
        region = Region(path=path, function=str(function) if function else None, families=answer.families)

        def _run(region: Region = region) -> list[StaticFinding]:
            return run_region_detectors(root, region, configs, client=client, model=model)

        produced = runtime.run_stage("learning", _run)
        for finding in produced:
            family_id = next((tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("family:")), "unknown")
            verification = verifier_for(taxonomy.by_id(family_id)).verify(finding, root=root, language="python")
            findings.append(apply_verification(finding, verification))
            per_family[family_id] = per_family.get(family_id, 0) + 1
    payload: dict[str, object] = {
        "taxonomy_version": taxonomy.version,
        "families": per_family,
        # What the classifier did on *this* scan. Scoring it needs labels a maintainer stands behind, which a scan
        # of someone else's repository does not have, so the block reports the routing rather than an accuracy.
        "classifier": {
            "regions": len(seen),
            "per_tier": dict(sorted(per_tier.items())),
            "abstained": abstained,
            # Req 2.6/3.7: say out loud that no family declares a parent at this taxonomy version, so the
            # partial credit for a parent-child relation never applied to any number here.
            "hierarchical_credit": taxonomy.hierarchical,
        },
        "round": None,
        "endpoint": endpoint.provider,
        "regions": len(seen),
    }
    cited: dict[str, dict[str, object]] = {
        finding.finding_id: {
            "family": next((tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("family:")), ""),
            "detector": next((tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("detector:")), ""),
            "verifier": next((tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("verifier:")), ""),
        }
        for finding in findings
    }
    return findings, payload, cited


def _learning(args: argparse.Namespace) -> int:
    """The maintainer's entry points into the classified detector set. Everything degrades with a reason."""
    from .learning.classify import measure_classifier, write_review_queue
    from .learning.families import load_families
    from .learning.publish import publish

    out: Path = args.out
    taxonomy = load_families()
    if args.learning_command == "publish":
        report = publish(learning_dir=out, measurements_dir=args.measurements, roadmap=args.roadmap)
        print(f"learning publish: {len(report.families)} families over {len(report.models)} model(s) -> {args.roadmap}")
        for artifact in report.artifacts:
            print(f"  artifact {artifact}")
        return 0
    cases = select_vendored(select_slice(load_pair_catalog(args.catalog), args.slice))
    if args.learning_command == "classify":
        measured = measure_classifier(cases, taxonomy, client=None)
        out.mkdir(parents=True, exist_ok=True)
        payload = measured.to_dict()
        (out / "classifier.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        written = write_review_queue(out / "review-queue.jsonl", measured.queue)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"learning classify: classified {measured.classified}, unknown {measured.unknown}, queued {written}")
        return 0
    return _learning_run(args, cases, taxonomy)


def _learning_run(args: argparse.Namespace, cases: Sequence[PairCase], taxonomy: FamilyTaxonomy) -> int:
    """score, baseline and round: the three that need a detector, and degrade with a reason without one."""
    from .learning.detectors import load_family_configs, write_default_configs
    from .learning.endpoint import resolve_chat_endpoint, resolve_models
    from .learning.journal import Archive, LearningJournal
    from .learning.rounds import MIN_K_RUNS, load_noise_floors, run_baseline, run_learning_round
    from .learning.scoring import aggregate
    from .tool_hunter import _SYSTEM_PROMPT

    out: Path = args.out
    config = load_config(args.config if args.config.exists() else None)
    k_runs = args.k_runs or max(config.learning.k_runs, MIN_K_RUNS)
    model = args.model or resolve_models(config)[0]
    configs_dir = out / "configs"
    if not configs_dir.exists():
        write_default_configs(configs_dir, taxonomy, prompt=_SYSTEM_PROMPT, version="0")  # type: ignore[arg-type]
    resolved = resolve_chat_endpoint(config)
    if resolved is None:
        print("learning: learning_endpoint_unavailable; scoring what can be scored without a detector")
    client = resolved[0] if resolved else None
    configs = load_family_configs(configs_dir, taxonomy)  # type: ignore[arg-type]

    def factory(family_config: object) -> Callable[[Path], list[StaticFinding]]:
        from .learning.detectors import Region, run_family_detector

        def scan(root: Path) -> list[StaticFinding]:
            if client is None:
                return []
            region = Region(path=_first_source(root), function=None)
            return run_family_detector(root, region, family_config, client=client, model=model)  # type: ignore[arg-type]

        return scan

    if args.learning_command == "score":
        from .learning.rounds import score_case

        scores = [
            score_case(case, factory(configs[_label(case, taxonomy)]), taxonomy=taxonomy, runs=k_runs, family=_label(case, taxonomy))
            for case in cases
            if _label(case, taxonomy) in configs
        ]
        families = {name: block.to_dict() for name, block in aggregate(scores, taxonomy=taxonomy).items()}
        if args.json:
            print(json.dumps({"families": families}, indent=2, sort_keys=True))
        else:
            for name, block in sorted(families.items()):
                print(f"learning score {name}: scorable={block['scorable']} recall={block['recall']:.3f} youden={block['youden']:.3f}")
        return 0
    if args.learning_command == "baseline":
        report = run_baseline(
            cases,
            taxonomy=taxonomy,
            configs_dir=configs_dir,
            scan_factory=factory,
            model=model,
            out_dir=out,
            k_runs=k_runs,
        )
        print(f"learning baseline {model}: {len(report.floors)} families, k={report.k_runs} -> {out / 'baseline'}")
        return 0
    journal = LearningJournal(out / "journal.jsonl")
    record = run_learning_round(
        cases,
        family=args.family,
        taxonomy=taxonomy,
        configs_dir=configs_dir,
        proposer=_proposer(args, configs_dir, model),
        scan_factory=factory,
        model=model,
        journal=journal,
        archive=Archive(out / "archive.jsonl"),
        floors=load_noise_floors(out, model),
        out_dir=out,
        cost_cap_usd=args.cost_cap_usd or config.learning.round_cost_cap_usd,
        minibatch=config.learning.minibatch,
        k_runs=k_runs,
        # Every other family the corpus actually carries, so a change that reaches beyond its own directory is
        # measured rather than assumed impossible (Req 9.5).
        sweep_families=tuple(sorted({_label(case, taxonomy) for case in cases} & set(configs) - {args.family})),
    )
    print(f"learning round {record.round} {record.family}: {record.outcome} ({record.reason})")
    return 0


def _label(case: PairCase, taxonomy: object) -> str:
    """The family that routes this pair: the maintainer's label when there is one, else the classifier's answer.

    Reading only the declared label would send every unlabeled row to the generalist, whose findings earn no credit
    against any real family, so a scoreboard built that way reports structural zeros (Req 2.1, 8.2)."""
    from .learning.rounds import _family_of

    return _family_of(case, taxonomy)  # type: ignore[arg-type]


def _proposer(args: argparse.Namespace, configs_dir: Path, model: str) -> Proposer:
    """`--proposals FILE` runs a recorded sequence offline; without it the round asks the meta-agent."""
    from .learning.proposer import HarnessXProposer, Proposal, ScriptedProposer

    path = getattr(args, "proposals", None)
    if path is None:
        return HarnessXProposer(configs_dir=configs_dir, model=model)
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScriptedProposer(
        [
            Proposal(
                hypothesis=str(row["hypothesis"]),
                lever=row["lever"],
                change=dict(row["change"]),
                predicted_affected=tuple(row.get("predicted_affected", ())),
                predicted_at_risk=tuple(row.get("predicted_at_risk", ())),
            )
            for row in rows
        ]
    )


def _first_source(root: Path) -> str:
    from .preprocess import preprocess_repository

    _, targets = preprocess_repository(root)
    return targets[0].path if targets else "."


def _hotspot_from_variant(finding: StaticFinding) -> Hotspot:
    return hotspot_from_finding(finding, rationale="variant of a known mechanism (suspicion; sandbox may raise)")


def _pairs_loo(cases: Sequence[PairCase], out: Path, *, json_out: bool) -> int:
    """Req 4: the corpus's own detection rate; written as an artifact, never a gate."""
    from .semantic.loo import evaluate_loo

    result = evaluate_loo(select_vendored(cases))
    payload = result.to_dict()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if json_out:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    for slice_name, metrics in result.per_slice.items():
        print(
            f"loo {slice_name}: pairs={metrics['pairs']} detected={metrics['detected']} silent={metrics['silent']} "
            f"youden={metrics['youden']:+.3f} teaching={metrics['teaching']}"
        )
    print(f"artifact={out}")
    return 0


def _mechanisms_export(catalog: Path, slice_name: str, store_path: Path, *, json_out: bool) -> int:
    from .semantic.mechanisms import MechanismStore
    from .semantic.seed import export_mechanisms

    if not catalog.is_file():
        raise SystemExit(f"pair catalog is not a file: {catalog}")
    cases = select_vendored(select_slice(load_pair_catalog(catalog), slice_name))
    report = export_mechanisms(cases, MechanismStore(store_path))
    payload = {"slice": slice_name, "store": str(store_path), "pairs": len(cases), **report.to_dict()}
    if json_out:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"mechanisms export slice={slice_name} pairs={len(cases)} seeded={report.seeded} records={report.records} -> {store_path}")
    for pair, reason in report.skipped:
        print(f"  skip {pair}: {reason}")
    return 0


def _print_improve_outcomes(outcomes: list[RoundOutcome], manifest_path: Path, target: Path, ledger_path: Path, *, dry_run: bool) -> None:
    print(f"manifest={manifest_path}")
    print(f"target={target}")
    accepted = [o for o in outcomes if o.accepted]
    for outcome in outcomes:
        edits = (
            ", ".join(
                [f"{e.rule_id}:{e.from_status}->{e.to_status}" for e in outcome.edits]
                + [f"{m.action} {m.mechanism_id}" for m in outcome.mechanism_edits]
            )
            or "-"
        )
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
        print("dry_run=true (no ledger or mechanism store written)")
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
