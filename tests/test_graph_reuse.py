"""Real byte identity and isolated graph lease boundaries, without launching Joern."""

import time
from dataclasses import replace

import pytest

from openultrasast.cpg.backend import CpgResult, JoernBackend
from openultrasast.model.contracts import ExecutionBudget


def prepared(tmp_path, monkeypatch):
    import openultrasast.cpg.backend as module

    monkeypatch.setattr(module, "joern_version", lambda: (4, 0, 625))
    root = tmp_path / "source"
    root.mkdir()
    (root / "a.js").write_text("function f(x) { return x; }")
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"graph original")
    backend = JoernBackend()
    census = {"files": "1", "methods": "1", "calls": "0", "file_names": [str(root / "a.js")], "overlays": "dataflowOss"}
    monkeypatch.setattr(JoernBackend, "query", lambda *args: census)
    identity = backend.graph_identity(root, language="javascript", declarations_digest="declarations", exclusions_digest="exclusions")
    result = CpgResult(graph, lambda *_: census)
    artifact = backend.describe_graph(result, root, identity)
    return backend, root, graph, identity, artifact


def test_identity_reads_content_and_rejects_changed_inputs(tmp_path, monkeypatch):
    backend, root, graph, identity, artifact = prepared(tmp_path, monkeypatch)
    assert artifact.source_bytes == (root / "a.js").stat().st_size > 0
    lease = backend.load_graph(graph, artifact, identity)
    assert lease is not None
    lease.cleanup()
    (root / "a.js").write_text("changed")
    changed = backend.graph_identity(root, language="javascript", declarations_digest="declarations", exclusions_digest="exclusions")
    assert changed != identity
    assert backend.load_graph(graph, artifact, changed) is None
    for field in ("declarations_digest", "exclusions_digest", "engine_version", "frontend_version"):
        assert backend.load_graph(graph, artifact, replace(identity, **{field: "changed"})) is None


def test_lease_isolates_loads_and_cleanup_preserves_original(tmp_path, monkeypatch):
    backend, root, graph, identity, artifact = prepared(tmp_path, monkeypatch)
    leased = backend.load_graph(graph, artifact, identity)
    assert leased is not None and leased.cpg_path != graph
    leased.cpg_path.write_bytes(b"query mutated working copy")
    assert graph.read_bytes() == b"graph original"
    leased.cleanup()
    leased.cleanup()
    assert not leased.cpg_path.exists() and graph.exists()


def test_corruption_partial_census_and_deadline_are_misses(tmp_path, monkeypatch):
    backend, root, graph, identity, artifact = prepared(tmp_path, monkeypatch)
    graph.write_bytes(b"corrupted")
    assert backend.load_graph(graph, artifact, identity) is None
    graph.write_bytes(b"graph original")
    assert backend.load_graph(graph, replace(artifact, completeness="partial", diagnostics=("dropped_file",)), identity) is None
    budget = ExecutionBudget(time.monotonic() - 1, 0.1)
    assert backend.load_graph(graph, artifact, identity, execution_budget=budget) is None
    bad = CpgResult(graph, lambda *_: {"files": "1", "methods": "1", "calls": "0", "file_names": [], "overlays": "dataflowOss"})
    assert backend.describe_graph(bad, root, identity) is None


def test_graph_identity_rejects_unreadable_or_symlink_sources(tmp_path, monkeypatch):
    backend, root, *_ = prepared(tmp_path, monkeypatch)
    (root / "link.js").symlink_to(root / "a.js")
    with pytest.raises((ValueError, OSError)):
        backend.graph_identity(root, language="javascript", declarations_digest="d", exclusions_digest="e")


def test_generic_driver_accepts_backend_validated_lease(tmp_path, monkeypatch):
    from openultrasast.model.scan import _build, _dispose

    backend, root, graph, identity, artifact = prepared(tmp_path, monkeypatch)
    budget = ExecutionBudget(time.monotonic() + 5, 0.2)

    class ReusingBackend:
        def build(self, source, *, language, exclude, execution_budget):
            assert source == root and language == "javascript"
            assert execution_budget is budget
            return backend.load_graph(graph, artifact, identity, execution_budget=execution_budget)

    result = _build(ReusingBackend(), root, "javascript", execution_budget=budget)
    assert result is not None
    assert result.run("census", {})["file_names"] == ["a.js"]
    _dispose(result)
    assert graph.read_bytes() == b"graph original"


def test_installed_frontend_adaptation_changes_graph_identity(tmp_path, monkeypatch):
    import openultrasast.cpg.backend as module

    backend, root, _, identity, _ = prepared(tmp_path, monkeypatch)
    home = tmp_path / "engine"
    home.mkdir()
    launcher = home / "joern"
    launcher.write_text("launcher")
    jar = home / "frontends/jssrc2cpg/lib/io.joern.jssrc2cpg-4.0.625.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"frontend-one")
    monkeypatch.setattr(module.shutil, "which", lambda name: str(launcher) if name == "joern" else None)
    first = backend.graph_identity(root, language="javascript", declarations_digest="d", exclusions_digest="e")
    jar.write_bytes(b"frontend-two")
    second = backend.graph_identity(root, language="javascript", declarations_digest="d", exclusions_digest="e")
    assert first != second
