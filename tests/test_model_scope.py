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
        names = [str(p) for p in root.rglob("*") if p.is_file()]

        def batch(kind, requests):
            return {"__census__": [{"methods": len(names), "files": len(names), "file_names": names}], **self.batch(kind, requests)}

        return SimpleNamespace(cpg_path=Path("test.cpg"), run_batch=batch, cleanup=lambda: None)

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

    result = scan_repository(
        source(tmp_path, "a.py", "missing.py"),
        [region("a.py"), region("missing.py")],
        backend=Partial({"a.py": vector(False), "missing.py": vector(False)}),
        ranking_mode="evidence",
    )
    # Pruning stays off: the unparsed file may hold the very sink a vector did not see.
    assert len(result.scope.selected) == 2
    assert result.scope.deferred == ()
    # Completion is owned by the file: the unparsed one is unresolved, the one the graph read is answered.
    status = {o.identity.path: o.status for o in result.question_outcomes}
    assert status == {"a.py": "completed", "missing.py": "unresolved"}, status


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


def test_failed_build_does_not_reload_facts_after_deadline(tmp_path, monkeypatch):
    import time

    import openultrasast.model.scan as driver
    from openultrasast.model.contracts import ExecutionBudget

    root = source(tmp_path, "api.py")

    def forbidden_facts(*args, **kwargs):
        raise AssertionError("failed build must not perform fresh semantic work")

    monkeypatch.setattr(driver, "_spec_for", forbidden_facts)
    regions = [ScanRegion("api.py", f"handler{i}", "python", ("injection", "access_control"), 1.0, "entry_point") for i in range(200)]
    started = time.monotonic()
    result = scan_repository(root, regions, backend=Backend(fail=True), execution_budget=ExecutionBudget(started + 0.01, 0.5))
    assert time.monotonic() - started < 0.5
    assert len(result.scope.deferred) == 400 and not result.scope.selected
    assert all(q.reason == "cpg_build_failed" for q in result.scope.deferred)
    assert not result.question_outcomes and "cpg_build_failed" in result.scope.unresolved_boundaries


def test_expired_planning_keeps_census_without_more_fact_reads(tmp_path, monkeypatch):
    import time

    import openultrasast.model.scan as driver
    from openultrasast.model.contracts import ExecutionBudget

    root = source(tmp_path, "api.py")
    original = driver._spec_for
    deadline = time.monotonic() + 0.05

    def checked_facts(*args, **kwargs):
        assert time.monotonic() < deadline, "fact load started after the deadline"
        time.sleep(0.015)
        return original(*args, **kwargs)

    monkeypatch.setattr(driver, "_spec_for", checked_facts)
    regions = [ScanRegion("api.py", f"handler{i}", "python", ("injection",), 1.0, "entry_point") for i in range(200)]
    result = scan_repository(root, regions, backend=Backend(), execution_budget=ExecutionBudget(deadline, 0.5))
    assert time.monotonic() < deadline + 0.5
    assert len(result.scope.selected) + len(result.scope.deferred) == 200
    assert "deadline_exhausted" in result.scope.unresolved_boundaries


def test_a_portion_sizer_learns_measured_costs_per_family() -> None:
    """Portions are sized in predicted seconds from what each family's answers reported costing."""
    from openultrasast.model import scan

    weights = {"i1": 10, "i2": 10, "o1": 10, **{f"x{i}": 10 for i in range(8)}}
    families = {"i1": "injection", "i2": "injection", "o1": "output_encoding", **{f"x{i}": "output_encoding" for i in range(8)}}
    sizer = scan._PortionSizer(weights, families)
    # A whole portion: answers explain 2 s, the other 23 s is the fixed start -- not the 70 s prior.
    sizer.observe({"i1": {}, "i2": {}}, 25.0, answered={"i1", "i2"}, timing={"i1": 1.0, "i2": 1.0})
    assert sizer.fixed == 23.0
    assert abs(sizer.rate("injection") - 0.1) < 1e-9
    # A family never seen is costed at the dearest rate known, never below the prior.
    assert sizer.rate("output_encoding") >= scan.PORTION_PRIOR_SECONDS_PER_VISIT
    sizer.observe({"o1": {}}, 43.0, answered={"o1"}, timing={"o1": 20.0})
    assert abs(sizer.rate("output_encoding") - 2.0) < 1e-9
    assert abs(sizer.rate("injection") - 0.1) < 1e-9, "one family's cost leaked into another's"
    # A portion is cut where the predicted seconds run out: 97 s of allowance holds four 20 s requests.
    pending: list[dict[str, dict[str, object]]] = []
    fitted = sizer.fit({f"x{i}": {} for i in range(8)}, pending=pending)
    assert len(fitted) == 4 and len(pending[0]) == 4, (fitted, pending)


def test_a_fast_portion_grows_the_next_one_after_a_collapse() -> None:
    """The trace that motivated this: after two kills the budget fell to 3 visits and never came back.

    Portions of 3 visits finished in 27 s. Under an assumed 70 s start that was 'no information', so the
    budget could only shrink. Measured, 27 s is almost all start, the work is cheap, and the next portion
    must carry far more.
    """
    from openultrasast.model import scan

    weights = {f"r{i}": 3 for i in range(200)}
    families = dict.fromkeys(weights, "injection")
    sizer = scan._PortionSizer(weights, families)
    sizer.observe({"r0": {}}, 27.0, answered={"r0"}, timing={"r0": 0.6})
    pending = [{f"r{i}": {} for i in range(2, 200)}]
    fitted = sizer.fit({"r1": {}}, pending=pending)
    assert len(fitted) >= 100, len(fitted)


def test_a_killed_culprit_makes_its_family_dearer_and_nothing_else() -> None:
    """The request running at the kill ran at least as long as nothing else explains."""
    from openultrasast.model import scan

    weights = {"a": 5, "b": 5, "c": 5}
    families = {"a": "injection", "b": "output_encoding", "c": "output_encoding"}
    sizer = scan._PortionSizer(weights, families)
    sizer.fixed = 25.0
    sizer.observe({"a": {}, "b": {}, "c": {}}, 300.0, answered={"a"}, timing={"a": 5.0}, culprit="b")
    # b ran at least 300 - 25 - 5 = 270 s over 5 visits.
    assert sizer.rate("output_encoding") >= 54.0
    assert abs(sizer.rate("injection") - 1.0) < 1e-9
    assert sizer.fixed == 25.0, "a killed portion must not be read as a fixed-start sample"


def test_only_a_request_entry_treats_its_parameters_as_attacker_input() -> None:
    """The mapper's `function` kind is its catch-all; its parameters carry whatever the caller had."""
    from openultrasast.model import scan

    route = ScanRegion("api.php", "handle", "php", ("injection",), 1.0, "entry_point", entry_kind="route")
    helper = ScanRegion("mail.php", "sendCancelAdminEmail", "php", ("injection",), 0.3, "entry_point", entry_kind="function")
    params = scan._grouped([("0", route, scan._spec_for("injection", "php")), ("1", helper, scan._spec_for("injection", "php"))])["taint"]
    assert params["0"]["parameterSources"] == "true"
    assert params["1"]["parameterSources"] == "false"
    # Still followed into its callees: only its own parameters stop being sources.
    assert params["1"]["callDepth"] == params["0"]["callDepth"] != "0"


class _CensusGapBackend(Backend):
    """A graph whose census reads only some of its files, or reports no file names at all."""

    def __init__(self, observed, **kwargs):
        super().__init__(**kwargs)
        self.observed = observed

    def build(self, root, **kwargs):
        graph = super().build(root, **kwargs)
        inner = graph.run_batch

        def batch(kind, requests):
            answer = dict(inner(kind, requests))
            row = {"methods": "3", "files": "2"}
            if self.observed is not None:
                row["file_names"] = list(self.observed)
            answer["__census__"] = [row]
            return answer

        graph.run_batch = batch
        return graph


def test_a_named_missing_file_demotes_only_the_questions_about_it(tmp_path):
    """The first evaluation on untouched code completed no question on eight of eleven projects: a missing
    `.eslintrc.js` or `api.wsgi` made every question of its language unresolved. A missing file makes the
    graph incomplete about THAT file; an answer about another file is still an answer."""
    root = source(tmp_path, "app.py", "broken.py")
    evidence = {"app.py": vector(), "broken.py": vector()}
    regions = [region("app.py", "python"), region("broken.py", "python")]
    result = scan_repository(root, regions, backend=_CensusGapBackend(["app.py"], evidence=evidence), population_complete=True)
    status = {o.identity.path: (o.status, o.reason) for o in result.question_outcomes}
    assert status["broken.py"] == ("unresolved", "graph_incomplete"), status
    assert status["app.py"][0] == "completed", status
    assert "partition_file_census_incomplete" in result.scope.unresolved_boundaries


def test_a_census_gap_that_names_no_file_still_reaches_its_partition(tmp_path):
    root = source(tmp_path, "app.py", "other.py")
    evidence = {"app.py": vector(), "other.py": vector()}
    regions = [region("app.py", "python"), region("other.py", "python")]
    result = scan_repository(root, regions, backend=_CensusGapBackend(None, evidence=evidence), population_complete=True)
    assert all(o.status == "unresolved" for o in result.question_outcomes), [(o.status, o.reason) for o in result.question_outcomes]


def test_a_language_no_frontend_reads_demotes_only_its_own_questions(tmp_path):
    """wger's Python questions all went unresolved because the repository also holds files of a language no
    frontend reads. That gap is about THAT language; it is reported, and it names the language."""
    root = source(tmp_path, "app.py")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "main.go").write_text("package main\n")
    result = scan_repository(root, [region("app.py")], backend=Backend({"app.py": vector()}), population_complete=True)
    gap = [d for d in result.degradations if d.get("reason") == "frontend_unsupported"]
    assert gap and gap[0].get("census_language") == "go", result.degradations
    assert "frontend_unsupported" in result.scope.unresolved_boundaries
    assert result.question_outcomes[0].status == "completed", result.question_outcomes


def test_unvalidated_typescript_demotes_only_typescript_questions(tmp_path):
    """YesWiki is PHP with a few `.ts` files; the TypeScript limit made every one of its PHP questions unresolved."""
    root = source(tmp_path, "app.py", "widget.ts")
    result = scan_repository(
        root,
        [region("app.py"), region("widget.ts", "typescript")],
        backend=Backend({"app.py": vector(), "widget.ts": vector()}),
        population_complete=True,
    )
    gap = [d for d in result.degradations if d.get("reason") == "typescript_property_support_unvalidated"]
    assert gap and gap[0].get("census_language") == "typescript", result.degradations
    status = {o.identity.path: o.status for o in result.question_outcomes}
    assert status == {"app.py": "completed", "widget.ts": "unresolved"}, status
