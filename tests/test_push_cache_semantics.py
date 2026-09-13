"""Semantic layers invalidate independently and comparisons retain revision ownership."""

import time
from dataclasses import replace

from openultrasast.model.contracts import ExecutionBudget
from openultrasast.push.cache import ArtifactCache, SemanticKeys


def keys():
    return SemanticKeys("facts", "queries", "configuration", "ranking", "admission", "model-disabled", "eligibility", "advisory")


def test_query_and_result_invalidation_layers():
    original = keys()

    def query(k):
        return k.query(graph="graph", kind="taint", request={"file": "a.js", "depth": 3}, context="context")

    def result(k):
        return k.comparison(base="base", head="head", context="context", evidence="evidence")

    for field in ("facts", "queries", "configuration"):
        changed = replace(original, **{field: "changed"})
        assert query(changed) != query(original)
        assert result(changed) != result(original)
    for field in ("ranking", "admission", "model", "eligibility", "mode"):
        changed = replace(original, **{field: "changed"})
        assert query(changed) == query(original)
        assert result(changed) != result(original)
    for field in ("graph", "kind", "request", "context"):
        args = {"graph": "graph", "kind": "taint", "request": {"file": "a.js", "depth": 3}, "context": "context"}
        args[field] = "changed"
        assert original.query(**args) != query(original)
    for field in ("base", "head", "context", "evidence"):
        args = {"base": "base", "head": "head", "context": "context", "evidence": "evidence"}
        args[field] = "changed"
        assert original.comparison(**args) != result(original)


def test_json_evidence_retains_provenance_and_rejects_incomplete(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    budget = ExecutionBudget(time.monotonic() + 5, 0.2)
    key = keys().query(graph="graph", kind="taint", request={}, context="context")
    payload = {"rows": [], "provenance": {"facts": "facts", "query": "queries"}}
    assert not cache.put_json(key, payload, kind="query", budget=budget, complete=False)
    assert cache.get_json(key, kind="query", budget=budget) is None
    assert cache.put_json(key, payload, kind="query", budget=budget, complete=True)
    assert cache.get_json(key, kind="query", budget=budget) == payload
    assert cache.get_json(key, kind="comparison", budget=budget) is None


def test_final_results_bind_scope_and_current_admission_provenance():
    original = keys()

    def result(k, scope="scope"):
        return k.result(comparisons=["base-head"], scope=scope)

    for field in ("facts", "queries", "configuration", "ranking", "admission", "model", "eligibility", "mode"):
        assert result(replace(original, **{field: "changed"})) != result(original)
    assert result(original, "different-scope") != result(original)
    assert original.result(comparisons=["another-base-head"], scope="scope") != result(original)
