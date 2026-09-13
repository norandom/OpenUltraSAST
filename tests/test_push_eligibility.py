"""Synthetic eligibility contracts, not real capability qualification."""

import copy
import json
from dataclasses import replace

import pytest
from test_push_admission import control
from test_push_scoring import inputs, record

from openultrasast.push.eligibility import create_decision, load_registry
from openultrasast.push_scoring import freeze_profile


def fixture():
    old, validation = inputs()
    current = {key: "synthetic-" + key for key in ("core", "engine", "engine_runtime", "facts", "queries", "policy", "semantics")}
    from openultrasast.cpg.artifact import digest_value

    _, declaration, _ = control()
    declaration = replace(declaration, key=replace(declaration.key, semantics=current["semantics"]), untouched_workload="untouched-control")
    config = {
        **old["config"],
        **current,
        "capability_semantics": {
            digest_value(declaration.key.to_payload()): {
                "key": declaration.key.to_payload(),
                "operation_symbols": list(declaration.operation_symbols),
                "review_id": declaration.evaluation_id,
                "consequence_template": declaration.consequence_template,
                "repair_template": declaration.repair_template,
            }
        },
    }
    cases = [{**row, "role": "independent", "workload": "untouched-control"} for row in old["cases"][:3]]
    raw = json.dumps({"schema_version": 1, "cases": cases}).encode()
    profile = freeze_profile(raw, config)
    validation = {**validation, "manifest_sha256": profile["manifest_sha256"], "cases": [{**c, "status": "ready"} for c in cases]}
    positive = record(
        alerts=[dict(review="actionable_true", review_evidence="synthetic-review", question_id="q-handler", site="api.js:4")],
        cache_state="warm_changed",
    )
    fixed = record(
        "fixed",
        queries=[
            dict(
                id="q-handler",
                status="answered",
                outcome="negative",
                target=config["targets"]["fixed"],
                witness="bound parameter discharges target",
            )
        ],
        delta="removed",
        cache_state="warm_changed",
    )
    benign = record("benign", delta="unchanged", cache_state="warm_changed")
    run = {"profile_sha256": profile["profile_sha256"], "context": config, "records": [positive, fixed, benign]}
    _, declaration, _ = control()
    declaration = replace(declaration, key=replace(declaration.key, semantics=current["semantics"]), untouched_workload="untouched-control")
    runtime = {
        "runtime_verdict": "PASS",
        "provenance": current,
        "workloads": {
            name: dict(
                population=3,
                observed=3,
                missing=0,
                latency_samples=3,
                p95_seconds=3,
                completion=1,
                complete_coverage_cases=3,
                cancellation_overrun_seconds=0,
                timeouts=0,
            )
            for name in ("identical-tip", "function-edit", "dependency-edit", "configuration-edit", "cold", "growth", "multi-ref")
        },
    }
    return profile, validation, run, current, runtime, (declaration,)


def decision(parts):
    profile, validation, run, current, runtime, declarations = parts
    return create_decision(profile, validation, run, current=current, runtime=runtime, declarations=declarations)


def test_matching_reviewed_synthetic_population_can_be_loaded(tmp_path):
    parts = fixture()
    data = decision(parts)
    assert data["verdict"] == "PASS"
    path = tmp_path / "eligibility.json"
    path.write_text(json.dumps(data))
    loaded = load_registry(current=parts[3], path=path)
    assert len(loaded.capabilities) == 1
    assert loaded.capabilities[0].enabled
    assert loaded.capabilities[0].positive_controls == 1
    assert loaded.capabilities[0].reviewed_alerts == 1


@pytest.mark.parametrize("mutation", ["no_alert", "runtime", "stale_runtime", "no_independent", "no_positive", "wrong_semantics"])
def test_missing_joint_evidence_never_enables_advisory(mutation, tmp_path):
    parts = list(copy.deepcopy(fixture()))
    if mutation == "no_alert":
        parts[2]["records"][0]["alerts"] = []
    elif mutation == "runtime":
        parts[4]["workloads"]["function-edit"]["p95_seconds"] = 31
    elif mutation == "stale_runtime":
        parts[4]["provenance"]["policy"] = "other"
    elif mutation == "no_independent":
        parts[5] = (replace(parts[5][0], untouched_workload="wrong-repository"),)
    elif mutation == "no_positive":
        parts[2]["records"] = parts[2]["records"][1:]
    else:
        parts[5] = (replace(parts[5][0], key=replace(parts[5][0].key, semantics="wrong")),)
    data = decision(parts)
    assert data["verdict"] == "NO-GO"
    path = tmp_path / "eligibility.json"
    path.write_text(json.dumps(data))
    assert not load_registry(current=parts[3], path=path).capabilities


def test_stale_or_tampered_registry_is_rejected(tmp_path):
    parts = fixture()
    data = decision(parts)
    path = tmp_path / "eligibility.json"
    path.write_text(json.dumps(data))
    stale = {**parts[3], "facts": "new-facts"}
    assert not load_registry(current=stale, path=path).capabilities
    data["entries"][0]["declaration"]["repair_template"] = "invented advice"
    path.write_text(json.dumps(data))
    assert not load_registry(current=parts[3], path=path).capabilities


def test_runner_consumes_only_matching_registry(tmp_path, monkeypatch):
    import openultrasast.push.eligibility as registry
    from openultrasast.push.runner import _admit

    parts = fixture()
    data = decision(parts)
    path = tmp_path / "eligibility.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(registry, "_DEFAULT", path)
    candidate, _, _ = control()
    candidate = replace(candidate, capability=parts[5][0].key, delta=replace(candidate.delta, semantics=parts[3]["semantics"]))
    assert len(_admit((candidate,), parts[3]).defects) == 1
    assert not _admit((candidate,), {**parts[3], "facts": "changed"}).defects


def test_changed_semantic_advice_needs_a_new_frozen_review():
    parts = list(fixture())
    parts[5] = (replace(parts[5][0], repair_template="Unreviewed advice at {operation} for {context}"),)
    assert decision(parts)["verdict"] == "NO-GO"


def test_shipped_registry_is_reproducible_no_go():
    from openultrasast.push.eligibility import _DEFAULT

    data = json.loads(_DEFAULT.read_bytes())
    loaded = load_registry(current=data["bindings"])
    assert loaded.status == "NO-GO"
    assert not loaded.capabilities
    assert data["entries"]
    assert all(not row["declaration"]["enabled"] for row in data["entries"])
