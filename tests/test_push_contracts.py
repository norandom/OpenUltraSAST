"""Approved task 1.4 contracts: persist identities without inventing completed analysis."""

import ast
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from openultrasast.config import PushConfig, config_payload, load_config
from openultrasast.contracts import Contract
from openultrasast.cpg.artifact import GraphArtifact, GraphCensus, GraphIdentity, GraphLease
from openultrasast.model.contracts import (
    ChangeContext,
    ChangedSpan,
    DeferredQuestion,
    QuestionIdentity,
    RankedQuestion,
    ScopeDecision,
)
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison, PushResult, PushUpdate


def question(language: str = "javascript", path: str = "src/api.js") -> QuestionIdentity:
    return QuestionIdentity("api", language, path, "handler", "injection")


def scope() -> ScopeDecision:
    return ScopeDecision("core-v1", "evidence", True, (RankedQuestion(question(), 2.5, ("source→operation",)),), (), ())


def comparison() -> PushComparison:
    return PushComparison("a" * 64, "b" * 64, "supplied_remote_tip", ("refs/heads/main",))


def test_config_round_trip_and_ordinary_scan_compatibility(tmp_path: Path) -> None:
    baseline = load_config()
    path = tmp_path / "settings.toml"
    path.write_text(
        '[push]\ncomparison_base = "refs/heads/main"\ndeadline_seconds = 11.5\n'
        'cancellation_allowance_seconds = 1\ncache_max_bytes = 4096\nmode = "blocking"\n'
        'incomplete_coverage_policy = "block"\n'
    )
    configured = load_config(path)
    assert configured.push == PushConfig("refs/heads/main", 11.5, 1, 4096, "blocking", "block")
    assert PushConfig.from_payload(json.loads(json.dumps(config_payload(configured)["push"]))) == configured.push
    before, after = config_payload(baseline), config_payload(configured)
    before.pop("push")
    after.pop("push")
    assert before == after
    assert baseline.push == PushConfig()
    assert baseline.push.deadline_seconds == 30
    assert baseline.push.cancellation_allowance_seconds == 2
    assert baseline.push.cache_max_bytes == 2 * 1024**3
    assert baseline.push.mode == "advisory"
    assert baseline.push.incomplete_coverage_policy == "allow"


@pytest.mark.parametrize(
    "setting",
    [
        'push = "bad"',
        "push = []",
        "[push]\ndeadline_seconds = true",
        '[push]\ndeadline_seconds = "30"',
        "[push]\ndeadline_seconds = nan",
        "[push]\ndeadline_seconds = inf",
        "[push]\ndeadline_seconds = 0",
        "[push]\ncancellation_allowance_seconds = -1",
        "[push]\ncache_max_bytes = 0",
        "[push]\ncache_max_bytes = 1.5",
        "[push]\ncache_max_bytes = true",
        '[push]\nmode = "nag"',
        '[push]\nincomplete_coverage_policy = "ignore"',
        '[push]\ncomparison_base = ""',
        "[push]\ncomparison_base = 1",
        "[push]\ndeadline_second = 60",
    ],
)
def test_push_configuration_rejects_unsafe_coercion(tmp_path: Path, setting: str) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(setting)
    with pytest.raises(ValueError):
        load_config(path)


def test_contract_round_trips_preserve_partition_ref_and_comparison_identity() -> None:
    update = PushUpdate("refs/heads/topic", "a" * 64, "refs/heads/main", "b" * 64)
    context = ChangeContext(
        "b" * 64,
        "a" * 64,
        ("src/api.js",),
        ("src/guard.js",),
        (ChangedSpan("src/guard.js", 3, 8, "base"),),
        (),
        ("package.json",),
        (),
        ("dynamic dispatch",),
    )
    for value in (update, comparison(), context, scope()):
        assert type(value).from_payload(json.loads(json.dumps(value.to_payload()))) == value
    assert question() != question("php", "src/api.js")
    assert question().question_id != question("php", "src/api.js").question_id
    other_base = replace(comparison(), base_oid="c" * 64)
    assert other_base != comparison()
    with pytest.raises(FrozenInstanceError):
        update.local_oid = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "finding,coverage,disposition",
    [
        ("none", "incomplete", "allow"),
        ("none", "unavailable", "block"),
        ("actionable", "incomplete", "allow"),
        ("actionable", "complete_within_scope", "block"),
    ],
)
def test_result_statuses_are_independent(finding: str, coverage: str, disposition: str) -> None:
    payload = {
        "analyses": [ComparisonAnalysis(comparison(), (scope(),), (question(),), coverage).to_payload()],
        "finding_status": finding,
        "coverage_status": coverage,
        "push_disposition": disposition,
        "actionable_defect_ids": ["defect-1"] if finding == "actionable" else [],
    }
    result = PushResult.from_payload(payload)
    assert PushResult.from_payload(json.loads(json.dumps(result.to_payload()))) == result
    assert result.finding_status == finding
    assert result.coverage_status == coverage
    assert result.push_disposition == disposition


def test_incomplete_scope_cannot_be_serialized_as_complete_negative() -> None:
    result = ComparisonAnalysis(comparison(), (scope(),), (question(),), "complete_within_scope")
    assert ComparisonAnalysis.from_payload(result.to_payload()) == result
    deferred = DeferredQuestion(question("php", "index.php"), "deadline", ("unanswered",))
    for changed in (
        replace(scope(), deferred=(deferred,)),
        replace(scope(), unresolved_boundaries=("vendor call",)),
        replace(scope(), population_complete=False),
    ):
        with pytest.raises(ValueError):
            replace(result, scopes=(changed,))
    with pytest.raises(ValueError):
        replace(result, completed_questions=())
    with pytest.raises(ValueError):
        replace(result, scopes=())
    with pytest.raises(ValueError):
        replace(result, comparison=replace(comparison(), base_oid=None, base_reason="missing"))
    with pytest.raises(ValueError):
        replace(scope(), deferred=(DeferredQuestion(question(), "deadline", ()),))


@pytest.mark.parametrize(
    "value",
    [
        {"local_ref": "x", "local_oid": "a", "remote_ref": "y", "remote_oid": "b", "extra": 1},
        {"local_ref": "x", "local_oid": 1, "remote_ref": "y", "remote_oid": "b"},
        {"local_ref": "x", "local_oid": "a", "remote_ref": "y"},
    ],
)
def test_malformed_identity_payloads_fail(value: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PushUpdate.from_payload(value)


def test_graph_provenance_round_trip_and_live_lease_separation() -> None:
    identity = GraphIdentity(
        "source-digest",
        "declarations",
        "exclusions",
        "api",
        "javascript",
        "4.0.625",
        "jssrc2cpg",
        "4.0.625",
        ("dataflowOss-v1",),
        (("option", "value"),),
    )
    artifact = GraphArtifact(identity, "graph-sha256", 128, GraphCensus(1, 2, 3), "complete", ())
    assert GraphArtifact.from_payload(json.loads(json.dumps(artifact.to_payload()))) == artifact
    assert replace(identity, exclusions_digest="changed") != identity
    assert not issubclass(GraphLease, Contract)  # a manifest cannot restore a live resource
    with pytest.raises(ValueError):
        replace(artifact, source_bytes=0)
    with pytest.raises(ValueError):
        replace(artifact, diagnostics=("file unreadable",))
    with pytest.raises(ValueError):
        replace(artifact, census=GraphCensus(0, 0, 0))
    with pytest.raises(ValueError):
        replace(identity, overlay_options=(("x", "1"), ("x", "2")))


def test_strict_runtime_construction_not_only_decoding() -> None:
    with pytest.raises(ValueError):
        RankedQuestion(question(), float("nan"), ())
    with pytest.raises(ValueError):
        ChangedSpan("x", True, 3, "head")
    with pytest.raises(ValueError):
        ChangedSpan("x", 4, 3, "head")
    with pytest.raises(ValueError):
        PushConfig(deadline_seconds=True)
    with pytest.raises(ValueError):
        PushConfig.from_payload({"mode": "blocking", "incomplete_coverage_policy": []})


def test_generic_contracts_and_engine_do_not_depend_on_push() -> None:
    root = Path("src/openultrasast")
    paths = [root / "contracts.py", *(root / "model").glob("*.py"), *(root / "cpg").glob("*.py")]
    for path in paths:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert "push" not in (node.module or "").split("."), path
            elif isinstance(node, ast.Import):
                assert all("push" not in alias.name.split(".") for alias in node.names), path


def test_shared_head_does_not_merge_different_base_completion() -> None:
    completed = ComparisonAnalysis(comparison(), (scope(),), (question(),), "complete_within_scope")
    pending = ComparisonAnalysis(replace(comparison(), base_oid="c" * 64), (scope(),), (), "incomplete")
    result = PushResult((completed, pending), "none", "incomplete", "allow", ())
    restored = PushResult.from_payload(json.loads(json.dumps(result.to_payload())))
    assert restored == result
    assert restored.analyses[1].completed_questions == ()
    with pytest.raises(ValueError):
        replace(result, coverage_status="complete_within_scope")
    with pytest.raises(ValueError):
        replace(pending, coverage_status="complete_within_scope")


def test_deletion_only_result_is_explicitly_not_applicable() -> None:
    result = PushResult((), "none", "not_applicable", "allow", ())
    assert PushResult.from_payload(result.to_payload()) == result
    with pytest.raises(ValueError):
        replace(result, coverage_status="complete_within_scope")


@pytest.mark.parametrize(
    "field,value",
    [
        ("finding_status", "clean"),
        ("coverage_status", "secure"),
        ("push_disposition", "warn"),
        ("finding_status", True),
        ("coverage_status", None),
    ],
)
def test_result_rejects_unknown_status_vocabulary(field: str, value: object) -> None:
    payload = PushResult((), "none", "not_applicable", "allow", ()).to_payload()
    payload[field] = value
    with pytest.raises(ValueError):
        PushResult.from_payload(payload)


def test_graph_partial_provenance_stays_partial_and_options_are_preserved() -> None:
    identity = GraphIdentity(
        "sources",
        "decls",
        "excludes",
        "core",
        "c",
        "4.0.625",
        "c2cpg",
        "4.0.625",
        ("dataflowOss-v1",),
        (("depth", "2"),),
        (("include", "src"),),
    )
    artifact = GraphArtifact(identity, "digest", 0, GraphCensus(0, 0, 0), "partial", ("source unreadable",))
    restored = GraphArtifact.from_payload(json.loads(json.dumps(artifact.to_payload())))
    assert restored == artifact
    assert restored.identity.frontend_options == (("include", "src"),)
    with pytest.raises(ValueError):
        replace(restored, completeness="complete")


def test_execution_budget_requires_finite_clock_and_distinct_positive_allowance() -> None:
    from openultrasast.model.contracts import ExecutionBudget

    budget = ExecutionBudget(123.0, 2.0)
    assert budget.deadline_monotonic == 123
    assert budget.cancellation_allowance_seconds == 2
    for deadline, allowance in ((float("inf"), 2), (1, float("nan")), (True, 2), (1, 0), (-1, 2)):
        with pytest.raises(ValueError):
            ExecutionBudget(deadline, allowance)


def test_empty_population_needs_an_explicit_census_assertion() -> None:
    empty = ScopeDecision("core-v1", "evidence", True, (), (), ())
    analyzed = ComparisonAnalysis(comparison(), (empty,), (), "complete_within_scope")
    assert analyzed.completed_questions == ()
    with pytest.raises(ValueError):
        replace(analyzed, scopes=(replace(empty, population_complete=False),))


def test_direct_mutable_collection_is_not_an_immutable_contract() -> None:
    with pytest.raises(ValueError):
        PushComparison("head", "base", "supplied", ["refs/heads/main"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        PushResult.from_payload({"finding_status": "none"})
