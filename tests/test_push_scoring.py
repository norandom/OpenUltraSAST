"""An absent answer must never improve a security score."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from openultrasast.push_scoring import freeze_profile, score


def inputs():
    cases = [
        dict(id=label, label=label, capability="javascript/express/injection", role="development", base="b", tip="h", prerequisites=[])
        for label in ("vulnerable", "fixed", "benign", "regression", "unreviewed")
    ]
    manifest = json.dumps(dict(schema_version=1, cases=cases)).encode()
    config = dict(
        version="test-v1",
        core="core-test",
        ranking_mode="static",
        engine="joern-test",
        facts="facts-test",
        queries="queries-test",
        policy="diagnostic-test",
        scope="first-party-test",
        hardware="test",
        budget_seconds=30,
        targets={case["id"]: dict(path="api.js", function="evalBody", lines=[4], family="injection") for case in cases},
    )
    profile = freeze_profile(manifest, config)
    validation = dict(
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        cases=[dict(case, status="ready") for case in cases],
        snapshots=[dict(id="b", status="ready", bytes_read=42), dict(id="h", status="ready", bytes_read=42)],
    )
    return profile, validation


def record(case="vulnerable", **updates):
    value = dict(
        case_id=case,
        ranking_mode="static",
        rank=None,
        selected=["q-handler"],
        deferred=[],
        queries=[
            dict(
                id="q-handler",
                status="answered",
                outcome="positive",
                origin=dict(path="routes.js", function="handler"),
                flow=[dict(path="routes.js", function="handler"), dict(path="api.js", function="evalBody")],
                finding=dict(
                    site="api.js:4", family="injection", rung="model_entailed", witness="source req.body.value -> eval at api.js:4"
                ),
            )
        ],
        alerts=[],
        delta="new",
        coverage="complete",
        cache_state="cold",
        timings=dict(build=1.0, query=2.0, total=3.0),
    )
    value.update(updates)
    return value


def run(records):
    profile, validation = inputs()
    return score(profile, validation, dict(profile_sha256=profile["profile_sha256"], context=profile["config"], records=records))


def test_missing_and_failed_keep_positive_denominator():
    missing = run([])
    failed = run([record(queries=[dict(id="q-handler", status="failed", outcome="unknown")])])
    assert missing["metrics"]["recall"]["denominator"] == failed["metrics"]["recall"]["denominator"] == 1
    assert failed["metrics"]["recall"]["numerator"] == 0
    assert failed["cases"][0]["outcome"] == "unresolved"
    assert len(missing["cases"]) == 5
    assert missing["recorded_cases"] == 0
    assert missing["measurement_status"] == "unmeasured"


def test_witnessed_positive_without_rank_is_counted():
    result = run([record()])
    assert result["metrics"]["recall"]["numerator"] == 1
    assert result["cases"][0]["reached_transitively"] is True
    assert result["cases"][0]["witnesses"][0]["question_id"] == "q-handler"


@pytest.mark.parametrize("mutation", ["empty_witness", "wrong_site", "wrong_family", "unanswered", "unselected"])
def test_positive_requires_answered_exact_target_witness(mutation):
    row = record()
    q = row["queries"][0]
    if mutation == "empty_witness":
        q["finding"]["witness"] = ""
    elif mutation == "wrong_site":
        q["finding"]["site"] = "other-api.js:4"
    elif mutation == "wrong_family":
        q["finding"]["family"] = "path"
    elif mutation == "unanswered":
        q["status"] = "failed"
    else:
        row["selected"] = []
    result = run([row])
    assert result["metrics"]["recall"]["numerator"] == 0
    assert result["cases"][0]["reached_transitively"] is False


def test_fixed_negative_needs_completed_answer_benign_backlog_is_not_alert():
    fixed = record(
        "fixed",
        queries=[
            dict(
                id="q-handler",
                status="answered",
                outcome="negative",
                target=dict(path="api.js", function="evalBody", lines=[4], family="injection"),
                witness="bound parameter discharges target",
            )
        ],
        delta="removed",
    )
    benign = record("benign", delta="unchanged")
    result = run([fixed, benign])
    assert result["metrics"]["fixed_side_silence"]["numerator"] == 1
    assert result["metrics"]["benign_interruption"]["numerator"] == 0
    assert result["cases"][2]["outcome"] == "positive"
    assert result["metrics"]["precision"]["denominator"] == 0
    failed = run([record("fixed", queries=[], coverage="incomplete")])
    assert failed["metrics"]["fixed_side_silence"]["numerator"] == 0


def test_profiles_cannot_be_swapped_or_mutated():
    profile, validation = inputs()
    for mutation in ("hash", "mode", "manifest", "profile"):
        p, v = copy.deepcopy(profile), copy.deepcopy(validation)
        data = dict(profile_sha256=p["profile_sha256"], context=profile["config"], records=[record()])
        if mutation == "hash":
            data["profile_sha256"] = "other"
        elif mutation == "mode":
            data["records"][0]["ranking_mode"] = "evidence"
        elif mutation == "manifest":
            v["manifest_sha256"] = "other"
        else:
            p["config"]["facts"] = "new"
        with pytest.raises(ValueError):
            score(p, v, data)


def test_static_rank_never_claims_transitive_detection(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "benchmarks/ranking/position.py"
    spec = importlib.util.spec_from_file_location("position", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ordered_regions", lambda root: [])
    (tmp_path / "api.js").write_text("eval(req.body.value)")
    result = module.measure(
        "test", tmp_path, [dict(id="missing", file="api.js", function="handler", family="injection", line=4, in_scope=True)]
    )
    assert result["known"][0]["reached_transitively"] is False
    assert result["supported_population"] == 1
    assert result["budget_at_recall"] is None
    assert result["detection_recall"] is None


def test_rank_absence_without_path_is_not_transitivity():
    row = record()
    del row["queries"][0]["flow"]
    result = run([row])
    assert result["metrics"]["recall"]["numerator"] == 1
    assert result["cases"][0]["reached_transitively"] is False


@pytest.mark.parametrize("field", ["engine", "facts", "queries", "scope", "budget_seconds"])
def test_actual_execution_context_must_match(field):
    profile, validation = inputs()
    context = dict(profile["config"], **{field: "different"})
    with pytest.raises(ValueError, match="context mismatch"):
        score(profile, validation, dict(profile_sha256=profile["profile_sha256"], context=context, records=[]))


def test_unreviewed_wrong_target_alerts_remain_precision_denominator():
    row = record(
        alerts=[
            dict(review="unreviewed"),
            dict(review="actionable_true", review_evidence="review1", question_id="q-handler", site="other.js:4"),
        ]
    )
    result = run([row])
    assert result["metrics"]["precision"]["numerator"] == 0
    assert result["metrics"]["precision"]["denominator"] == 2
    assert result["gates_passed"] is False


def test_regression_readable_despite_missing_admission_prerequisite():
    profile, validation = inputs()
    validation["cases"][3]["status"] = "missing_prerequisite"
    validation["cases"][3]["problem"] = "independent holdout missing"
    result = score(
        profile,
        validation,
        dict(profile_sha256=profile["profile_sha256"], context=profile["config"], records=[record("regression", delta="unchanged")]),
    )
    assert result["metrics"]["regression_detection"]["numerator"] == 1
    assert result["metrics"]["recall"]["numerator"] == 0
    assert result["admission"] == "experimental"


def test_missing_source_overrides_an_asserted_positive():
    profile, validation = inputs()
    validation["snapshots"][1]["bytes_read"] = 0
    result = score(profile, validation, dict(profile_sha256=profile["profile_sha256"], context=profile["config"], records=[record()]))
    assert result["metrics"]["recall"]["numerator"] == 0
    assert result["cases"][0]["outcome"] == "unresolved"


def test_unmeasured_benign_is_not_perfect_interruption_rate():
    assert run([])["metrics"]["benign_interruption"]["value"] is None


def test_evidence_launch_failure_retains_unresolved_population(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "benchmarks/ranking/position.py"
    spec = importlib.util.spec_from_file_location("position_failure", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ordered_regions", lambda root: [])

    def fail(*args):
        raise SystemExit("no graph: input unreadable")

    monkeypatch.setattr(module, "evidence_ordered_regions", fail)
    result = module.measure(
        "test",
        tmp_path,
        [dict(id="missing", file="api.js", function="handler", family="injection", line=4, in_scope=True)],
        by_evidence=True,
    )
    assert result["ranking_mode"] == "unavailable"
    assert result["supported_population"] == 1
    assert result["input_status"] == "incomplete"
    assert "no graph" in result["evidence_failure"]


def test_deferred_questions_and_unmeasured_cases_remain_coverage_limits():
    result = run([record(deferred=["q-deferred"])])
    assert result["metrics"]["completion"]["numerator"] == 0
    assert result["metrics"]["query_completion"]["denominator"] == 2
    assert result["metrics"]["query_completion"]["numerator"] == 1
    assert result["metrics"]["query_completion"]["value"] is None


def test_actionable_recall_requires_reviewed_alert_beside_detection():
    result = run([record()])
    assert result["metrics"]["recall"]["numerator"] == 1
    assert result["metrics"]["actionable_recall"]["numerator"] == 0
    result = run([record(alerts=[dict(review="actionable_true", review_evidence="review1", question_id="q-handler", site="api.js:4")])])
    assert result["metrics"]["actionable_recall"]["numerator"] == 1
    assert result["metrics"]["precision"]["numerator"] == 1
