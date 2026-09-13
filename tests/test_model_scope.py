"""Exact ranker execution scope, uncertainty and cross-language transfer (task 3.2)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository


def region(path, language="python", families=("injection",), rank=0.5):
    return ScanRegion(path, "run", language, families, rank, "entry_point")


class Backend:
    def __init__(self, evidence=None, missing=(), fail=False):
        self.evidence = evidence or {}
        self.missing = missing
        self.fail = fail
        self.executed = []

    def build(self, root, **kwargs):
        # Prove these tests provide real readable source to the driver boundary.
        assert any(p.read_bytes() for p in root.rglob("*") if p.is_file())
        if self.fail:
            return None
        return SimpleNamespace(cpg_path=Path("test.cpg"), run_batch=self.batch, cleanup=lambda: None)

    def batch(self, kind, requests):
        if any(p.get("evidenceOnly") == "true" for p in requests.values()):
            return {rid: self.evidence.get(p["file"], []) for rid, p in requests.items()}
        self.executed.extend((rid, kind, p["file"]) for rid, p in requests.items())
        return {rid: [] for rid, p in requests.items() if kind not in self.missing}


def source(tmp_path, *paths):
    for path in paths:
        (tmp_path / path).write_text("readable source\n")
    return tmp_path


def vector(open_sink=True):
    rows = [{"kind": "summary", "familyInRepo": True, "sourceLocal": True}]
    if open_sink:
        rows += [{"kind": "sink", "sink": "operation(value)", "sinkLine": 1, "sinkMethod": "run", "sinkArity": 1}]
    return rows


def test_final_order_is_the_scope_and_execution_order(tmp_path):
    root = source(tmp_path, "high.py", "low.py")
    backend = Backend({"high.py": vector(False), "low.py": vector()})
    result = scan_repository(
        root,
        [region("high.py", rank=1.0), region("low.py")],
        backend=backend,
        ranking_mode="evidence",
        unit="head-unit",
        population_complete=True,
        budget=ScanBudget(max_regions=1),
    )
    assert [q.identity.path for q in result.scope.selected] == ["low.py"]
    assert [q.identity.path for q in result.scope.deferred] == ["high.py"]
    assert backend.executed == [(result.scope.selected[0].identity.question_id, "taint", "low.py")]
    assert result.scope.ranking_mode == "evidence"
    assert result.scope.population_complete
    assert result.question_outcomes[0].status == "completed"


def test_unknown_evidence_and_family_completion_remain_separate(tmp_path):
    root = source(tmp_path, "api.py")
    result = scan_repository(
        root,
        [region("api.py", families=("injection", "access_control", "config_secrets", "unmodeled"))],
        backend=Backend(missing=("dominance", "config")),
        ranking_mode="evidence",
    )
    selected = {q.identity.family: q for q in result.scope.selected}
    assert selected["injection"].tier is None
    assert selected["access_control"].tier is None
    assert selected["config_secrets"].tier is None
    coverage = {c.family: c for c in result.family_coverage}
    assert coverage["injection"].completed == 1
    assert coverage["access_control"].completed == coverage["config_secrets"].completed == 0
    assert coverage["unmodeled"].unsupported == 1
    assert any(q.reason == "unsupported_family" for q in result.scope.deferred)
    assert any("evidence" in boundary for boundary in result.scope.unresolved_boundaries)


@pytest.mark.parametrize("mode", ["static", "evidence"])
def test_php_javascript_equivalent_vectors_produce_same_decisions(tmp_path, mode):
    results = []
    for language, suffix in [("php", "php"), ("javascript", "js")]:
        root = tmp_path / language
        root.mkdir()
        source(root, f"a.{suffix}", f"b.{suffix}")
        backend = Backend({f"a.{suffix}": vector(False), f"b.{suffix}": vector()})
        result = scan_repository(
            root,
            [region(f"a.{suffix}", language), region(f"b.{suffix}", language)],
            backend=backend,
            ranking_mode=mode,
            budget=ScanBudget(max_regions=1),
        )
        results.append(result)
    assert [(q.identity.function, q.tier, q.score) for q in results[0].scope.selected] == [
        (q.identity.function, q.tier, q.score) for q in results[1].scope.selected
    ]
    assert [(q.reason, q.identity.path.split(".")[0]) for q in results[0].scope.deferred] == [
        (q.reason, q.identity.path.split(".")[0]) for q in results[1].scope.deferred
    ]


def test_failed_build_retains_exact_unanswered_population(tmp_path):
    result = scan_repository(source(tmp_path, "a.py"), [region("a.py")], backend=Backend(fail=True), ranking_mode="evidence")
    assert result.scope.selected == ()
    assert result.scope.deferred[0].reason == "cpg_build_failed"
    assert result.family_coverage[0].completed == 0
    assert not result.scope.population_complete


def test_explicit_static_mode_overrides_legacy_evidence_toggle(tmp_path):
    root = source(tmp_path, "a.py", "b.py")
    result = scan_repository(
        root,
        [region("a.py", rank=1.0), region("b.py")],
        backend=Backend(),
        ranking_mode="static",
        budget=ScanBudget(max_regions=1, order_by_evidence=True),
    )
    assert result.scope.selected[0].identity.path == "a.py"
    assert result.scope.ranking_mode == "static"


def test_scope_payload_is_json_serializable(tmp_path):
    result = scan_repository(source(tmp_path, "a.py"), [region("a.py")], backend=Backend(), ranking_mode="evidence")
    from openultrasast.cli import _model_payload

    payload = _model_payload(result)
    assert json.loads(json.dumps(payload))["scope"]["selected"][0]["identity"]["path"] == "a.py"
    assert payload["family_coverage"][0]["completed"] == 1


def test_partial_evidence_batch_is_unknown_not_tier_zero(tmp_path):
    backend = Backend({"a.py": vector(False)})
    result = scan_repository(source(tmp_path, "a.py", "b.py"), [region("a.py"), region("b.py")], backend=backend, ranking_mode="evidence")
    assert [(q.identity.path, q.reason) for q in result.scope.deferred] == [("a.py", "tier_zero")]
    assert result.scope.selected[0].identity.path == "b.py"
    assert result.scope.selected[0].tier is None
    assert any(d.get("kind") == "evidence" and d.get("requests") == 1 for d in result.degradations)
    assert result.family_coverage[0].completed == 1
    assert result.family_coverage[0].deferred == 1


def test_later_timeout_retains_raw_answer_without_claiming_arbitration(tmp_path):
    import time

    from openultrasast.model.contracts import ExecutionBudget

    class Slow(Backend):
        def batch(self, kind, requests):
            rows = super().batch(kind, requests)
            if kind == "taint" and not any(p.get("evidenceOnly") for p in requests.values()):
                time.sleep(0.3)
                return {rid: [{"kind": "retained", "value": 42}] for rid in requests}
            return rows

    result = scan_repository(
        source(tmp_path, "a.py"),
        [region("a.py", families=("injection", "access_control"))],
        backend=Slow(),
        ranking_mode="static",
        execution_budget=ExecutionBudget(time.monotonic() + 0.2, 0.2),
    )
    outcomes = {q.identity.family: q for q in result.question_outcomes}
    assert outcomes["injection"].status == "not_arbitrated"
    assert json.loads(outcomes["injection"].raw_rows_json) == [{"kind": "retained", "value": 42}]
    assert outcomes["access_control"].status == "unanswered"
    assert all(c.completed == 0 for c in result.family_coverage)


def test_missing_graph_files_disable_safe_pruning_and_completion(tmp_path):
    class Partial(Backend):
        def build(self, root, **kwargs):
            cpg = super().build(root, **kwargs)
            cpg.unparsed = ("missing.py",)
            return cpg

    result = scan_repository(source(tmp_path, "a.py"), [region("a.py")], backend=Partial({"a.py": vector(False)}), ranking_mode="evidence")
    assert len(result.scope.selected) == 1
    assert result.scope.deferred == ()
    assert result.question_outcomes[0].status == "unresolved"
    assert result.family_coverage[0].completed == 0


def test_cli_sample_uses_deferred_order_not_scanned_count(tmp_path):
    from openultrasast.cli import _model_payload

    backend = Backend({"high.py": vector(False), "low.py": vector()})
    result = scan_repository(
        source(tmp_path, "high.py", "low.py"),
        [region("high.py", rank=1), region("low.py")],
        backend=backend,
        ranking_mode="evidence",
        budget=ScanBudget(max_regions=1),
    )
    assert _model_payload(result)["unjudged_sample"] == ["high.py"]


def test_invalid_mode_and_duplicate_identity_fail_before_build(tmp_path):
    backend = Backend()
    root = source(tmp_path, "a.py")
    with pytest.raises(ValueError, match="ranking_mode"):
        scan_repository(root, [region("a.py")], backend=backend, ranking_mode="invented")
    with pytest.raises(ValueError, match="duplicate question"):
        scan_repository(root, [region("a.py"), region("a.py")], backend=backend)
    assert backend.executed == []


def test_empty_evidence_graph_census_cannot_prune_every_check(tmp_path):
    class Empty(Backend):
        def batch(self, kind, requests):
            result = super().batch(kind, requests)
            result["__census__"] = [{"methods": "0", "files": "0"}]
            return result

    result = scan_repository(source(tmp_path, "a.py"), [region("a.py")], backend=Empty({"a.py": vector(False)}), ranking_mode="evidence")
    assert len(result.scope.selected) == 1
    assert result.family_coverage[0].completed == 0
    assert "cpg_empty" in result.scope.unresolved_boundaries


def test_overlapping_frontend_paths_keep_ids_distinct_and_evidence_unknown(tmp_path):
    result = scan_repository(
        source(tmp_path, "a.txt"),
        [region("a.txt", "php"), region("a.txt", "javascript")],
        backend=Backend({"a.txt": vector()}),
        ranking_mode="evidence",
    )
    assert len({q.identity.question_id for q in result.scope.selected}) == 2
    assert all(q.tier is None for q in result.scope.selected)
    assert len(result.family_coverage) == 2


def test_outcome_and_coverage_contracts_reject_forged_completion():
    from openultrasast.model.contracts import FamilyCoverage, QuestionIdentity, QuestionOutcome

    identity = QuestionIdentity("unit", "php", "api.php", "run", "injection")
    for raw in ("{}", "not json"):
        with pytest.raises(ValueError, match="JSON row list"):
            QuestionOutcome(identity, "completed", "answered", raw)
    with pytest.raises(ValueError, match="requires raw rows"):
        QuestionOutcome(identity, "completed", "answered")
    with pytest.raises(ValueError, match="cannot carry"):
        QuestionOutcome(identity, "unanswered", "failed", "[]")
    with pytest.raises(ValueError, match="nonnegative"):
        FamilyCoverage("unit", "php", "injection", -1, 0, -1, 0, 0)
    with pytest.raises(ValueError, match="inconsistent"):
        FamilyCoverage("unit", "php", "injection", 1, 1, 1, 0, 0)
    outcome = QuestionOutcome(identity, "completed", "answered", "[]")
    assert QuestionOutcome.from_payload(outcome.to_payload()) == outcome


def test_unbatched_failure_is_not_a_completed_empty_answer(tmp_path):
    class Single(Backend):
        def build(self, root, **kwargs):
            return SimpleNamespace(cpg_path=Path("cpg"), run=lambda *a: None, cleanup=lambda: None)

    result = scan_repository(source(tmp_path, "a.py"), [region("a.py")], backend=Single(), ranking_mode="static")
    assert result.question_outcomes[0].status == "unanswered"
    assert result.regions_scanned == 0
    assert result.family_coverage[0].completed == 0
