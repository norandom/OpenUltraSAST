"""Deterministic self-improvement loop (tasks 7.4, 7.5, 7.6).

One round: benchmark with the current ledger -> per-rule signals -> propose bounded
edits (auto-shadow precision-draggers) -> validate -> replay smoke -> re-benchmark ->
hard acceptance gate (recall >= floor AND FP < ceiling AND project score not regressed
AND no matched-finding regression) -> accept (persist the ledger) or revert byte-for-byte.

The edit *proposer* here is the benchmark's per-rule signal; the LLM ``MetaAgent.evolve``
proposer plugs into this same validated/gated machinery when the HarnessX extra is present.
The project score is the optimization reward; the recall/FP gate is a separate hard
feasibility constraint that is never folded into the reward.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..benchmark import BenchmarkManifest, BenchmarkResult, BenchmarkRun, evaluate_benchmark
from ..findings import StaticFinding, quick_scan_findings
from ..mapping import analyze_entry_points, attach_reachability_hints
from ..policy import CwePolicy, load_policy
from ..preprocess import preprocess_repository
from ..rank import rank_targets
from ..ruleset import DEFAULT_RULESET_DIR, PatternRule, load_ruleset, read_rule_ledger, write_rule_ledger
from ..scoring import build_score_artifact
from .journal import append_round, load_journal, next_round_index, reverted_edit_keys
from .validator import EvolveValidator, RuleStatusEdit, StrictValidationError, edits_to_ledger


@dataclass(frozen=True)
class RoundOutcome:
    round: int
    accepted: bool
    reason: str
    edits: list[RuleStatusEdit] = field(default_factory=list)
    recall_before: float = 0.0
    recall_after: float = 0.0
    fp_before: float = 0.0
    fp_after: float = 0.0
    score_before: int = 0
    score_after: int = 0
    matched_before: int = 0
    matched_after: int = 0
    profile_regressions: list[str] = field(default_factory=list)
    profiles_under_minimum: list[str] = field(default_factory=list)
    per_profile_before: dict[str, dict[str, float]] = field(default_factory=dict)
    per_profile_after: dict[str, dict[str, float]] = field(default_factory=dict)
    # learning-harness Req 5.2: the candidates this round declined to learn from, by pair name.
    degradations: list[dict[str, object]] = field(default_factory=list)


MAX_PROFILES = 4


def evaluate_profiles(
    pair_cases: Sequence[object],
    rules: tuple[PatternRule, ...],
) -> dict[str, dict[str, float]]:
    """Pair-corpus metrics per provenance profile under ``rules`` (holdout split, no inventory sidecar).

    Only ``seeded`` and ``reviewed`` pairs gate (Req 9.3); ``advisory`` and ``title`` pairs are scored by ``pairs``, never here.

    Deliberately split-blind: this *measures* a ruleset, it never learns from a pair, so every pair is scored and the
    teacher rule has nothing to say here. What the rule governs is the store these rules were built from
    (`semantic.seed`, `semantic.loo`), and a filter here would only shrink the evidence (learning-harness Req 5.1).
    """
    from ..pairs import GATING_TIERS, PairCase, evaluate_catalog, select_tier, select_vendored

    # Gates score vendored pairs only (Req 10.4); pointer pairs are for `pairs --pointers`, never for the improve gate.
    cases = list(select_tier(select_vendored([case for case in pair_cases if isinstance(case, PairCase)]), GATING_TIERS))
    if not cases:
        return {}
    result = evaluate_catalog(cases, ruleset=rules, inventory_sidecar=False)
    return {
        profile: {
            "pairs": float(metrics.pairs),
            "pair_correct": float(metrics.pair_correct),
            "pair_pass_rate": metrics.pair_pass_rate,
            "youden": metrics.youden,
        }
        for profile, metrics in result.per_profile.items()
    }


def profile_regressions(
    before: dict[str, dict[str, float]],
    after: dict[str, dict[str, float]],
    *,
    tolerance: float = 0.0,
    min_pairs: int = 5,
) -> tuple[list[str], list[str]]:
    """(regressed profiles, profiles under the minimum).

    A profile regresses when its pair pass rate or Youden drops by more than ``tolerance``
    (both are rates in [-1, 1], so one tolerance applies to both).
    """
    regressed: list[str] = []
    small: list[str] = []
    for profile in sorted(set(before) | set(after)):
        old = before.get(profile, {"pairs": 0.0, "pair_correct": 0.0, "pair_pass_rate": 0.0, "youden": 0.0})
        new = after.get(profile, old)
        if old["pairs"] < min_pairs:
            small.append(profile)
            continue
        old_rate = old.get("pair_pass_rate", old["pair_correct"] / old["pairs"] if old["pairs"] else 0.0)
        new_rate = new.get("pair_pass_rate", new["pair_correct"] / new["pairs"] if new["pairs"] else 0.0)
        if new_rate < old_rate - tolerance or new["youden"] < old["youden"] - tolerance:
            regressed.append(profile)
    return regressed, small


def build_rule_signals(result: BenchmarkResult) -> list[dict[str, object]]:
    """Convert a benchmark result into per-rule loop signals (recall: miss; precision: fp)."""
    signals: list[dict[str, object]] = []
    for miss in result.misses:
        signals.append({"rule_id": miss.rule_id or "", "signal": "miss", "cwe": miss.cwe, "path": miss.path})
    for fp in result.false_positives:
        signals.append({"rule_id": fp.rule_id, "signal": "fp", "path": fp.path, "line": fp.line})
    return sorted(signals, key=lambda item: (str(item.get("signal")), str(item.get("rule_id")), str(item.get("path"))))


def propose_status_edits(
    per_rule: Mapping[str, dict[str, int]],
    ruleset_by_id: Mapping[str, PatternRule],
    current_ledger: Mapping[str, dict[str, object]],
    blocked_keys: set[str],
) -> list[RuleStatusEdit]:
    """Auto-shadow precision-draggers: enabled rules with false positives -> shadow (never delete)."""
    edits: list[RuleStatusEdit] = []
    for rule_id, counts in sorted(per_rule.items()):
        if counts.get("false_positives", 0) <= 0:
            continue
        rule = ruleset_by_id.get(rule_id)
        if rule is None:
            continue
        current_status = str(current_ledger.get(rule_id, {}).get("status", rule.status))
        if current_status != "enabled":
            continue  # already staged or disabled
        edit = RuleStatusEdit(rule_id=rule_id, from_status="enabled", to_status="shadow", rationale="")
        if edit.key() in blocked_keys:
            continue  # novelty gate: previously reverted without a new rationale
        edits.append(edit)
    return edits


def run_round(
    target: Path,
    manifest: BenchmarkManifest,
    *,
    ledger_path: Path,
    journal_path: Path,
    ruleset_dir: Path = DEFAULT_RULESET_DIR,
    policy: dict[str, CwePolicy] | None = None,
    recall_floor: float = 0.9,
    fp_ceiling: float = 0.1,
    pair_cases: Sequence[object] | None = None,
    profile_tolerance: float = 0.0,
    min_holdout_pairs: int = 5,
) -> RoundOutcome:
    policy = policy if policy is not None else load_policy()
    rounds = load_journal(journal_path)
    round_index = next_round_index(rounds)
    blocked = reverted_edit_keys(rounds)
    current_ledger = read_rule_ledger(ledger_path)

    before_findings, before_rules = _scan(target, ruleset_dir, current_ledger, policy)
    before = _evaluate(target, manifest, before_findings, before_rules, policy)
    (ledger_path.parent / "rule_signals.json").parent.mkdir(parents=True, exist_ok=True)
    _write_signals(ledger_path.parent / "rule_signals.json", build_rule_signals(before.result))

    ruleset_by_id = {rule.rule_id: rule for rule in before_rules}
    edits = propose_status_edits(before.result.metrics.per_rule, ruleset_by_id, current_ledger, blocked)
    refusals: list[dict[str, object]] = []
    if not edits:
        return _outcome(round_index, accepted=False, reason="no_proposals", edits=[], before=before, after=before, degradations=refusals)

    validator = EvolveValidator()
    try:
        for edit in edits:
            validator.validate(edit, ruleset_by_id, policy)
    except StrictValidationError as exc:
        _record(journal_path, round_index, edits, "rejected", before, before, str(exc))
        return _outcome(
            round_index, accepted=False, reason=f"validation_failed: {exc}", edits=edits, before=before, after=before, degradations=refusals
        )

    candidate = edits_to_ledger(edits, current_ledger)
    try:
        _load_with(ruleset_dir, candidate)  # replay smoke gate: candidate ruleset must boot
    except Exception as exc:  # noqa: BLE001 — any boot failure rejects the round
        _record(journal_path, round_index, edits, "rejected", before, before, f"replay_failed: {exc}")
        return _outcome(
            round_index, accepted=False, reason="replay_failed", edits=edits, before=before, after=before, degradations=refusals
        )

    after_findings, after_rules = _scan(target, ruleset_dir, candidate, policy)
    after = _evaluate(target, manifest, after_findings, after_rules, policy)

    accepted = (
        after.recall >= recall_floor and after.fp_rate < fp_ceiling and after.score >= before.score and after.matched >= before.matched
    )
    profiles_before: dict[str, dict[str, float]] = {}
    profiles_after: dict[str, dict[str, float]] = {}
    regressed: list[str] = []
    small: list[str] = []
    if accepted and pair_cases:
        # pair-corpus-honesty Req 7.2: a change may not help one provenance profile by hurting another.
        profiles_before = evaluate_profiles(pair_cases, before_rules)
        profiles_after = evaluate_profiles(pair_cases, after_rules)
        if len(profiles_before) > MAX_PROFILES:
            raise ValueError(f"at most {MAX_PROFILES} provenance profiles are supported; got {sorted(profiles_before)}")
        regressed, small = profile_regressions(profiles_before, profiles_after, tolerance=profile_tolerance, min_pairs=min_holdout_pairs)
        if regressed:
            accepted = False
    if accepted:
        if edits:
            write_rule_ledger(ledger_path, candidate)
        reason = "accepted"
    elif regressed:
        reason = f"profile_regression:{regressed[0]}"  # every regressed profile is listed in profile_regressions
    else:
        reason = "reverted"  # ledger_path untouched -> byte-for-byte revert
    _record(
        journal_path,
        round_index,
        edits,
        "accepted" if accepted else "reverted",
        before,
        after,
        reason,
        regressed,
        small,
    )
    outcome = _outcome(round_index, accepted=accepted, reason=reason, edits=edits, before=before, after=after, degradations=refusals)
    return RoundOutcome(
        **{
            **outcome.__dict__,
            "profile_regressions": regressed,
            "profiles_under_minimum": small,
            "per_profile_before": profiles_before,
            "per_profile_after": profiles_after,
        }
    )


def run_improvement(
    target: Path,
    manifest: BenchmarkManifest,
    *,
    ledger_path: Path,
    journal_path: Path,
    ruleset_dir: Path = DEFAULT_RULESET_DIR,
    policy: dict[str, CwePolicy] | None = None,
    max_rounds: int = 5,
    recall_floor: float = 0.9,
    fp_ceiling: float = 0.1,
    pair_cases: Sequence[object] | None = None,
    profile_tolerance: float = 0.0,
    min_holdout_pairs: int = 5,
) -> list[RoundOutcome]:
    """Run improvement rounds until convergence (no new proposals) or ``max_rounds``."""
    outcomes: list[RoundOutcome] = []
    for _ in range(max_rounds):
        outcome = run_round(
            target,
            manifest,
            ledger_path=ledger_path,
            journal_path=journal_path,
            ruleset_dir=ruleset_dir,
            policy=policy,
            recall_floor=recall_floor,
            fp_ceiling=fp_ceiling,
            pair_cases=pair_cases,
            profile_tolerance=profile_tolerance,
            min_holdout_pairs=min_holdout_pairs,
        )
        outcomes.append(outcome)
        if outcome.reason == "no_proposals":
            break
    return outcomes


@dataclass(frozen=True)
class _Eval:
    result: BenchmarkResult
    recall: float
    fp_rate: float
    score: int
    matched: int


def _scan(
    target: Path, ruleset_dir: Path, ledger: Mapping[str, dict[str, object]], policy: dict[str, CwePolicy]
) -> tuple[list[StaticFinding], tuple[PatternRule, ...]]:
    rules = _load_with(ruleset_dir, ledger)
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    rankings = rank_targets(targets)
    findings = quick_scan_findings(target, targets, rankings, rules, policy)
    reported = [finding for finding in findings if finding.status != "shadow"]
    return reported, rules


def _evaluate(
    target: Path, manifest: BenchmarkManifest, findings: list[StaticFinding], rules: tuple[PatternRule, ...], policy: dict[str, CwePolicy]
) -> _Eval:
    run = BenchmarkRun(benchmark_run_id="improve", root=target, manifest=manifest)
    result = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
    metrics = result.metrics
    cwe_by_rule = {rule.rule_id: rule.cwe for rule in rules}
    rule_cwe_by_id = {f.finding_id: cwe_by_rule.get(f.finding_id.split(":", 1)[0], "") for f in findings}
    score = build_score_artifact(findings, rule_cwe_by_id, policy).project_score
    recall = metrics.recall if metrics.recall is not None else 1.0
    fp_rate = metrics.false_positive_findings_total / metrics.actual_findings_total if metrics.actual_findings_total else 0.0
    return _Eval(result=result, recall=recall, fp_rate=fp_rate, score=score, matched=metrics.matched_findings_total)


def _load_with(ruleset_dir: Path, ledger: Mapping[str, dict[str, object]]) -> tuple[PatternRule, ...]:
    import json

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(json.dumps(ledger))
        temp_path = Path(handle.name)
    try:
        return load_ruleset(ruleset_dir, temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def _write_signals(path: Path, signals: list[dict[str, object]]) -> None:
    import json

    path.write_text(json.dumps(signals, indent=2, sort_keys=True) + "\n")


def _outcome(
    round_index: int,
    *,
    accepted: bool,
    reason: str,
    edits: list[RuleStatusEdit],
    before: _Eval,
    after: _Eval,
    degradations: list[dict[str, object]] | None = None,
) -> RoundOutcome:
    return RoundOutcome(
        round=round_index,
        accepted=accepted,
        reason=reason,
        edits=edits,
        degradations=list(degradations or []),
        recall_before=before.recall,
        recall_after=after.recall,
        fp_before=before.fp_rate,
        fp_after=after.fp_rate,
        score_before=before.score,
        score_after=after.score,
        matched_before=before.matched,
        matched_after=after.matched,
    )


def _record(
    journal_path: Path,
    round_index: int,
    edits: list[RuleStatusEdit],
    outcome: str,
    before: _Eval,
    after: _Eval,
    reason: str = "",
    profile_regressions: list[str] | None = None,
    profiles_under_minimum: list[str] | None = None,
) -> None:
    append_round(
        journal_path,
        {
            "round": round_index,
            "outcome": outcome,
            "reason": reason or outcome,
            "profile_regressions": list(profile_regressions or []),
            "profiles_under_minimum": list(profiles_under_minimum or []),
            "edits": [
                {"key": e.key(), "lever": e.lever, "rule_id": e.rule_id, "from": e.from_status, "to": e.to_status, "rationale": e.rationale}
                for e in edits
            ],
            "recall_before": round(before.recall, 4),
            "recall_after": round(after.recall, 4),
            "fp_before": round(before.fp_rate, 4),
            "fp_after": round(after.fp_rate, 4),
            "score_before": before.score,
            "score_after": after.score,
        },
    )
