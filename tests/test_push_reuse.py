"""Live integration of validated graph and query reuse under one deadline."""

import json
import time

from openultrasast.cpg.backend import CpgResult, JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.push.cache import ArtifactCache, SemanticKeys
from openultrasast.push.reuse import ReusingBackend


def test_backend_reuses_graph_and_answers_then_invalidates_source_and_dependencies(tmp_path, monkeypatch):
    import openultrasast.cpg.backend as module

    monkeypatch.setattr(module, "joern_version", lambda: (4, 0, 625))
    builds = []
    queries = []

    class Engine(JoernBackend):
        def build(self, root, *, language, exclude, execution_budget):
            builds.append(root)
            path = tmp_path / f"graph-{len(builds)}.json"
            paths = [str(p) for p in root.glob("*.js")]
            path.write_text(json.dumps(paths))
            return CpgResult(path, lambda kind, params: self.query(path, kind, params), lambda kind, req: self.query_batch(path, kind, req))

        def query(self, path, kind, params):
            names = json.loads(path.read_text())
            return {"files": len(names), "methods": 2, "calls": 1, "file_names": names, "overlays": "dataflowOss"}

        def query_batch(self, path, kind, requests):
            queries.append((kind, requests))
            return {**{rid: [] for rid in requests}, "__census__": [self.query(path, "census", {})]}

    root = tmp_path / "source"
    root.mkdir()
    (root / "a.js").write_text("function f() {}")
    cache = ArtifactCache(tmp_path / "cache", max_bytes=100000)
    semantics = SemanticKeys("facts", "queries", "config", "ranking", "admission", "disabled", "empty", "advisory")
    deadline = ExecutionBudget(time.monotonic() + 10, 0.2)
    backend = ReusingBackend(Engine(), cache, semantics, declarations="dependencies", exclusions="exclusions")

    def run():
        result = backend.build(root, language="javascript", exclude=(), execution_budget=deadline)
        assert result is not None
        answer = result.run_batch("taint", {"q": {"file": "a.js", "callDepth": 3}})
        if result.cleanup:
            result.cleanup()
        return answer

    expected = run()
    assert run() == expected
    assert len(builds) == 1 and len(queries) == 1
    (root / "a.js").write_text("function g() {}")
    run()
    assert len(builds) == 2 and len(queries) == 2
    backend.declarations = "changed-dependency"
    run()
    assert len(builds) == 3 and len(queries) == 3
    backend.semantics = SemanticKeys("changed-facts", "queries", "config", "ranking", "admission", "disabled", "empty", "advisory")
    run()
    assert len(builds) == 3 and len(queries) == 4


def test_fresh_missing_census_cannot_borrow_a_cached_query_census(tmp_path):
    from openultrasast.cpg.artifact import GraphArtifact, GraphCensus, GraphIdentity

    identity = GraphIdentity(
        "source", "declarations", "exclude", "repository", "javascript", "engine", "frontend", "version", ("dataflowOss",), ()
    )
    artifact = GraphArtifact(identity, "graph-bytes", 10, GraphCensus(1, 1, 1), "complete", (), "/old", ("a.js",))
    cache = ArtifactCache(tmp_path / "cache", max_bytes=100000)
    semantics = SemanticKeys("facts", "queries", "config", "ranking", "admission", "disabled", "empty", "advisory")
    wrapper = ReusingBackend(JoernBackend(), cache, semantics, declarations="d", exclusions="e")
    census = [{"files": 1, "methods": 1, "file_names": ["a.js"]}]
    calls = []

    def batch(kind, requests):
        calls.append(requests)
        result = {rid: [] for rid in requests}
        if len(calls) == 1:
            result["__census__"] = census
        return result

    graph = CpgResult(tmp_path / "graph", lambda *_: None, batch)
    result = wrapper._answers(graph, artifact, ExecutionBudget(time.monotonic() + 5, 0.2))
    assert "q" in result.run_batch("taint", {"q": {"file": "a.js"}})
    answer = result.run_batch("taint", {"q": {"file": "a.js"}, "fresh": {"file": "a.js", "callDepth": 3}})
    assert "q" in answer and "fresh" not in answer
